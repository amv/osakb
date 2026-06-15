'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { run } = require('./executor');
const chacha20 = require('./chacha20');
const mouse = require('./mouse');
const qrcode = require('./qr');

const PORT = Number(process.env.PORT) || 8765;
const HOST = process.env.HOST || '0.0.0.0';

// How the address shown/encoded in the QR is built. The server always *listens*
// on PORT; this only affects what the QR/printed link points at. The secret is
// appended as the #fragment, never taken from here.
//
// The first positional arg selects a mode:
//   node osakb.js detect      -> auto (default): Tailscale MagicDNS name if a
//                                tailnet is up, else the Mac .local mDNS name
//   node osakb.js wifi        -> Mac .local mDNS hostname
//   node osakb.js tailscale   -> Tailscale MagicDNS name (over the tailnet)
//   node osakb.js http://host:port/   -> use this URL verbatim (custom override,
//                                e.g. a domain or port-forward)
// Back-compat: the --url / --base-url flags and the OSAKB_URL env var still set
// a custom override and take precedence over a mode.
function parseInvocation() {
  let url = process.env.OSAKB_URL || null;
  let mode = null; // 'detect' | 'wifi' | 'tailscale' | null (null => 'detect')
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--url' || a === '--base-url') { url = argv[i + 1]; i++; }
    else if (a.startsWith('--url=')) url = a.slice('--url='.length);
    else if (a.startsWith('--base-url=')) url = a.slice('--base-url='.length);
    else if (a.startsWith('-')) continue; // ignore unknown flags
    else if (a === 'wifi' || a === 'tailscale' || a === 'detect') mode = a;
    else if (a.includes('://')) url = a; // bare URL positional => custom override
  }
  return { url: url || null, mode: mode || 'detect' };
}
const { url: OVERRIDE_URL, mode: MODE } = parseInvocation();

const PUBLIC_DIR = path.join(__dirname, 'public');
const SECRET_DIR = path.join(os.homedir(), '.osakb');
const SECRET_FILE = path.join(SECRET_DIR, 'secret');

// Load the osakb secret from ~/.osakb/secret, creating it (with a random
// 32-hex-char value) on first run. Kept in memory for the process lifetime.
// Files are created with owner-only permissions.
function loadOrCreateSecret() {
  try {
    const existing = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    if (existing) return { secret: existing, created: false };
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
  const secret = crypto.randomBytes(16).toString('hex'); // 32 hex chars
  fs.mkdirSync(SECRET_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(SECRET_FILE, secret + '\n', { mode: 0o600 });
  return { secret, created: true };
}

const { secret: SECRET, created: SECRET_CREATED } = loadOrCreateSecret();

// Derive separate subkeys for encryption and authentication (never share a key
// between the cipher and the MAC). Both are 32 bytes.
function sha256(data) { return crypto.createHash('sha256').update(data).digest(); }
const ENC_KEY = sha256('osakb-enc:' + SECRET);
const MAC_KEY = sha256('osakb-mac:' + SECRET);

// ---- challenge-response auth (nonce + monotonic counter + HMAC-SHA256) ----
//
// Flow: client GETs /nonce, then signs every action request with
//   HMAC-SHA256(secret, METHOD\nPATH\nNONCE\nCOUNTER\nBODY)
// sent in the X-Osakb-* headers. The secret never travels on the wire; only the
// MAC does. The counter must strictly increase per nonce (replay protection),
// and nonces are random + in-memory only, so a server restart invalidates all
// old sessions. Nonces expire by TTL and are capped to bound memory.
const NONCE_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_NONCES = 200;
const nonces = new Map(); // nonce -> { lastCounter, created }

function pruneNonces() {
  const now = Date.now();
  for (const [k, v] of nonces) {
    if (now - v.created > NONCE_TTL_MS) nonces.delete(k);
  }
  // Cap: drop oldest (Map preserves insertion order).
  while (nonces.size >= MAX_NONCES) {
    nonces.delete(nonces.keys().next().value);
  }
}

function createNonce() {
  pruneNonces();
  const nonce = crypto.randomBytes(32).toString('hex'); // 256-bit, unique in practice
  nonces.set(nonce, { lastCounter: 0, created: Date.now() });
  return nonce;
}

// Constant-time compare a received hex MAC against the expected MAC bytes.
function macOk(hexMac, expectedBuf) {
  let got;
  try {
    got = Buffer.from(hexMac, 'hex');
  } catch (e) {
    return false;
  }
  return got.length === expectedBuf.length && crypto.timingSafeEqual(got, expectedBuf);
}

// Check a (nonce, counter) pair for validity + replay. Advances lastCounter on
// success. Returns { ok } / { ok:false, error }.
function checkNonceCounter(nonce, counter) {
  const entry = nonces.get(nonce);
  if (!entry) return { ok: false, error: 'unknown or expired nonce' };
  if (Date.now() - entry.created > NONCE_TTL_MS) {
    nonces.delete(nonce);
    return { ok: false, error: 'expired nonce' };
  }
  if (!Number.isInteger(counter) || counter <= entry.lastCounter) {
    return { ok: false, error: 'bad or replayed counter' };
  }
  entry.lastCounter = counter;
  return { ok: true };
}

// Decrypt + authenticate an encrypted envelope { iv, ct, mac } for the given
// method/path. Encrypt-then-MAC: verify the MAC over the ciphertext BEFORE
// decrypting. Returns { ok, plaintext } or { ok:false, status, error }.
function openEnvelope(method, pathname, rawBody) {
  let env;
  try {
    env = JSON.parse(rawBody);
  } catch (e) {
    return { ok: false, status: 400, error: 'invalid JSON envelope' };
  }
  if (!env || typeof env.iv !== 'string' || typeof env.ct !== 'string' || typeof env.mac !== 'string') {
    return { ok: false, status: 400, error: 'missing iv/ct/mac' };
  }

  const macInput = `${method}\n${pathname}\n${env.iv}\n${env.ct}`;
  const expected = crypto.createHmac('sha256', MAC_KEY).update(macInput).digest();
  if (!macOk(env.mac, expected)) return { ok: false, status: 401, error: 'bad mac' };

  let iv, ct;
  try {
    iv = Buffer.from(env.iv, 'base64');
    ct = Buffer.from(env.ct, 'base64');
  } catch (e) {
    return { ok: false, status: 400, error: 'bad base64' };
  }
  if (iv.length !== 12) return { ok: false, status: 400, error: 'bad iv length' };

  const pt = Buffer.from(chacha20.xor(ENC_KEY, iv, 1, ct));
  return { ok: true, plaintext: pt.toString('utf8') };
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error('Request body too large'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.json': 'application/json',
  '.webmanifest': 'application/manifest+json',
};

function serveStatic(req, res, urlPath) {
  // Resolve within PUBLIC_DIR only; guard against path traversal.
  const rel = urlPath === '/' ? '/index.html' : urlPath;
  const filePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJSON(res, 403, { error: 'Forbidden' });
    return;
  }
  fs.readFile(filePath, (err, content) => {
    if (err) {
      sendJSON(res, 404, { error: 'Not found' });
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(content);
  });
}

// Normalize a /key payload into an actions array.
function normalizeActions(body) {
  if (Array.isArray(body)) return body;
  if (body && Array.isArray(body.actions)) return body.actions;
  if (body && typeof body === 'object') return [body];
  return null;
}

function clampInt(x) {
  const n = Math.round(Number(x));
  if (!Number.isFinite(n)) return 0;
  return Math.max(-10000, Math.min(10000, n));
}

// Execute one decrypted op.
//   { t:'k', b:<actions> }            keypress
//   { t:'m', k:'mv', dx, dy }         relative mouse move (drag while a btn is held)
//   { t:'m', k:'cl', btn:'l'|'r' }    mouse click (down+up)
//   { t:'m', k:'dn', btn:'l'|'r' }    mouse button down (hold)
//   { t:'m', k:'up', btn:'l'|'r' }    mouse button up (release)
//   { t:'m', k:'sc', dy }             scroll wheel
async function runOp(op) {
  if (!op || typeof op !== 'object') throw new Error('bad op');
  if (op.t === 'k') {
    const actions = normalizeActions(op.b);
    if (!actions) throw new Error('expected action object or array');
    return run(actions);
  }
  if (op.t === 'm') {
    if (op.k === 'mv') return mouse.send({ k: 'mv', dx: clampInt(op.dx), dy: clampInt(op.dy) });
    if (op.k === 'cl') return mouse.send({ k: 'cl', btn: op.btn === 'r' ? 'r' : 'l' });
    if (op.k === 'dn') return mouse.send({ k: 'dn', btn: op.btn === 'r' ? 'r' : 'l' });
    if (op.k === 'up') return mouse.send({ k: 'up', btn: op.btn === 'r' ? 'r' : 'l' });
    if (op.k === 'sc') return mouse.send({ k: 'sc', dy: clampInt(op.dy) });
    throw new Error('bad mouse op');
  }
  throw new Error('unknown op type');
}

// Execute a batch of ops in order (the client coalesces keystrokes per flush).
async function dispatchOps(res, ops) {
  const list = Array.isArray(ops) ? ops : [ops];
  if (list.length === 0) return sendJSON(res, 400, { error: 'empty batch' });
  try {
    let last;
    for (const op of list) last = await runOp(op);
    const extra = last && last.dryRun ? { dryRun: true, script: last.script } : {};
    return sendJSON(res, 200, { ok: true, n: list.length, ...extra });
  } catch (err) {
    console.error('Dispatch error:', err.message);
    return sendJSON(res, 500, { error: err.message });
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const { pathname } = url;

  // Public endpoints (no auth): the page/assets and nonce issue.
  if (req.method === 'GET' && pathname === '/nonce') {
    return sendJSON(res, 200, { nonce: createNonce(), ttlMs: NONCE_TTL_MS });
  }

  // Single authenticated + encrypted endpoint. The body is an encrypt-then-MAC
  // envelope; the decrypted plaintext carries the auth nonce, counter, and the
  // operation — so nothing about the keystroke is visible on the wire.
  if (req.method === 'POST' && pathname === '/msg') {
    let rawBody;
    try {
      rawBody = await readBody(req);
    } catch (err) {
      return sendJSON(res, 400, { error: err.message });
    }

    const opened = openEnvelope('POST', pathname, rawBody);
    if (!opened.ok) return sendJSON(res, opened.status, { error: opened.error });

    let msg;
    try {
      msg = JSON.parse(opened.plaintext);
    } catch (e) {
      return sendJSON(res, 400, { error: 'bad plaintext' });
    }

    const check = checkNonceCounter(msg.n, msg.c);
    if (!check.ok) return sendJSON(res, 401, { error: check.error });

    return dispatchOps(res, msg.o);
  }

  if (req.method === 'GET') {
    return serveStatic(req, res, pathname);
  }

  sendJSON(res, 405, { error: 'Method not allowed' });
});

// Docker's default bridge networks live in 172.16.0.0/12 (docker0 is usually
// 172.17.0.1, compose networks 172.18+). These are almost never the address the
// phone should reach, so we sort them to the back rather than dropping them.
function isDockerIp(ip) {
  const m = /^172\.(\d+)\./.exec(ip);
  return m && Number(m[1]) >= 16 && Number(m[1]) <= 31;
}

function lanAddresses() {
  const out = new Set();
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) out.add(iface.address);
    }
  }
  // Prioritise real LAN addresses over Docker bridge IPs (kept, just last).
  return [...out].sort((a, b) => isDockerIp(a) - isDockerIp(b));
}

function sh(bin, args) {
  try {
    return execFileSync(bin, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null;
  } catch {
    return null;
  }
}

// The Bonjour/mDNS hostname (e.g. "mac-air.local"). This is the LocalHostName
// (`scutil --get LocalHostName`) — the name mDNS actually answers to. We do NOT
// fall back to os.hostname(): that's the kernel HostName, set dynamically from
// DHCP/reverse-DNS or the ComputerName, so it can be wrong (e.g. "MacbookAir")
// or not even a valid .local label (e.g. "Mac Air"). If scutil has no answer
// (non-macOS, or the early-boot window before LocalHostName is set), return null
// and let the caller fall back to a LAN IP instead.
function localHostname() {
  if (process.platform !== 'darwin') return null;
  const name = sh('scutil', ['--get', 'LocalHostName']);
  return name ? name + '.local' : null;
}

// The Tailscale MagicDNS name (e.g. "mac-air.tailnet-xyz.ts.net"), read straight
// from the Tailscale daemon — the authoritative source for the tailnet name,
// which is decoupled from the OS hostname. Uses Self.DNSName (the FQDN, which
// always resolves via MagicDNS regardless of the device's search domains).
// Returns null if Tailscale isn't installed/running or no tailnet is up.
function tailscaleHostname() {
  const bins = ['tailscale', '/Applications/Tailscale.app/Contents/MacOS/Tailscale'];
  for (const bin of bins) {
    const out = sh(bin, ['status', '--json']);
    if (!out) continue;
    try {
      const status = JSON.parse(out);
      // When Tailscale is switched off the daemon still reports Self.DNSName, so
      // skip it unless the tailnet is actually up.
      if (status.BackendState === 'Stopped') continue;
      const self = status.Self || {};
      if (self.DNSName) return self.DNSName.replace(/\.$/, ''); // strip trailing dot
      if (self.HostName) return self.HostName;
    } catch {}
  }
  return null;
}

// Resolve the address to advertise into { url, kind, ips }, where kind is one of
// 'custom' | 'tailscale' | 'local' | 'ip' | 'none' (used to tailor the startup
// banner and warnings). `ips` is the list of auto-detected LAN IPv4 addresses,
// only set for kind 'ip'. For 'none' there's no address to advertise (url null).
//   tailscale -> MagicDNS name
//   wifi      -> .local mDNS name
//   detect    -> MagicDNS name if a tailnet is up, else the .local name
// All hostname modes fall back to auto-detected LAN IP(s); never to localhost
// (the phone can't reach the Mac at localhost).
function resolveBase() {
  if (OVERRIDE_URL) return { url: OVERRIDE_URL, kind: 'custom' };

  let host = null;
  let kind = null;
  if (MODE === 'tailscale') {
    host = tailscaleHostname();
    if (host) kind = 'tailscale';
  } else if (MODE === 'wifi') {
    host = localHostname();
    if (host) kind = 'local';
  } else { // detect
    host = tailscaleHostname();
    if (host) kind = 'tailscale';
    else { host = localHostname(); if (host) kind = 'local'; }
  }

  if (host) return { url: `http://${host}:${PORT}/`, kind };

  // No hostname: fall back to auto-detected LAN IPv4 address(es).
  const ips = lanAddresses();
  if (ips.length) return { url: `http://${ips[0]}:${PORT}/`, kind: 'ip', ips };
  return { url: null, kind: 'none' };
}

// Append the secret as the URL fragment (replacing any existing one).
function withSecret(base, secret) {
  const hash = base.indexOf('#');
  return (hash >= 0 ? base.slice(0, hash) : base) + '#' + secret;
}

server.listen(PORT, HOST, () => {
  console.log('osakb keyboard server running.');
  if (process.platform !== 'darwin') {
    console.log('NOTE: not running on macOS — keypresses will be logged, not executed (dry-run).');
  }
  console.log(
    SECRET_CREATED
      ? `\nGenerated a new secret at ${SECRET_FILE}`
      : `\nLoaded secret from ${SECRET_FILE}`
  );

  const { url: base, kind, ips } = resolveBase();

  // No address at all: the server is still listening on every interface, but
  // there's nothing to advertise — so no QR. Tell the user how to recover.
  if (kind === 'none') {
    console.log('\n⚠️  Could not detect this machine\'s address.');
    console.log('   The server is listening on all interfaces, but there is no');
    console.log('   address to show. If you just changed networks, press Ctrl-C to');
    console.log('   stop the server and start it again to retry. You can also set');
    console.log(`   the address manually: node osakb.js http://<your-ip>:${PORT}/`);
    return;
  }

  if (kind === 'custom') {
    console.log(`\nUsing custom URL (server still listens on port ${PORT}):`);
  } else if (kind === 'tailscale') {
    console.log('\nOpen on your phone (same Tailscale tailnet):');
  } else if (kind === 'local') {
    console.log('\nOpen on your phone (same Wi-Fi):');
  } else {
    console.log('\nOpen on your phone (same LAN):');
  }
  console.log('  ' + base);

  // A .local address trusts the local network. Warn — an active attacker on a
  // compromised router can rewrite the page itself (see README › Security).
  if (kind === 'local') {
    console.log(
      '\n⚠️  This is a LAN address — only safe on a network whose router you trust.\n' +
      '   On an untrusted network it is suggested to use Tailscale.'
    );
  } else if (kind === 'ip') {
    // Auto-detected raw IP — it might not be the Wi-Fi one. Help the user pick.
    if (ips.length > 1) {
      console.log('\n⚠️  No hostname found — auto-detected several LAN IPs. Any of these');
      console.log('   might be the right one (the QR uses the first):');
      for (const ip of ips) console.log(`     http://${ip}:${PORT}/`);
      console.log('   If the QR doesn\'t work, set the right one manually as the first');
      console.log(`   parameter: node osakb.js http://<ip>:${PORT}/`);
    } else {
      console.log('\n⚠️  No hostname found — this IP was auto-detected. Check that it is');
      console.log('   your Wi-Fi address; if not, set it manually as the first parameter:');
      console.log(`     node osakb.js http://<ip>:${PORT}/`);
    }
    console.log('   A LAN address is only safe on a network whose router you trust.');
  }

  // QR with the secret in the #fragment — never sent to the server, but the
  // page reads it from location.hash, so scanning both opens the app and hands
  // it the secret.
  const authUrl = withSecret(base, SECRET);
  console.log('\nScan to open + authenticate (secret is in the # fragment):');
  qrcode.generate(authUrl, { small: true });
  console.log(authUrl + '\n');
});
