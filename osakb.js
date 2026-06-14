'use strict';

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { run } = require('./executor');
const chacha20 = require('./chacha20');
const mouse = require('./mouse');
const qrcode = require('./vendor/qrcode-terminal/lib/main');

const PORT = Number(process.env.PORT) || 8765;
const HOST = process.env.HOST || '0.0.0.0';

// How the address shown/encoded in the QR is built. The server always *listens*
// on PORT; this only affects what the QR/printed link points at. The secret is
// appended as the #fragment, never taken from here.
//
// The first positional arg selects a mode:
//   node osakb.js wifi        -> Mac .local mDNS hostname (default)
//   node osakb.js tailscale   -> bare machine hostname (resolves via Tailscale
//                                MagicDNS / over the tailnet)
//   node osakb.js http://host:port/   -> use this URL verbatim (custom override,
//                                e.g. a domain or port-forward)
// Back-compat: the --url / --base-url flags and the OSAKB_URL env var still set
// a custom override and take precedence over a mode.
function parseInvocation() {
  let url = process.env.OSAKB_URL || null;
  let mode = null; // 'wifi' | 'tailscale' | null (null => default = wifi)
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--url' || a === '--base-url') { url = argv[i + 1]; i++; }
    else if (a.startsWith('--url=')) url = a.slice('--url='.length);
    else if (a.startsWith('--base-url=')) url = a.slice('--base-url='.length);
    else if (a.startsWith('-')) continue; // ignore unknown flags
    else if (a === 'wifi' || a === 'tailscale') mode = a;
    else if (a.includes('://')) url = a; // bare URL positional => custom override
  }
  return { url: url || null, mode };
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

function lanAddresses() {
  const out = new Set();
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) out.add(iface.address);
    }
  }
  return [...out];
}

// The Bonjour/mDNS hostname (e.g. "Anttis-MacBook-Pro.local"). Unlike the IP,
// this survives the Mac getting a new DHCP lease, so it's the better address to
// pin in a home-screen app.
function localHostname() {
  const host = os.hostname();
  if (!host) return null;
  const short = host.split('.')[0]; // strip any existing domain suffix
  return short + '.local';
}

// The bare machine hostname (e.g. "Anttis-MacBook-Pro"), with any domain suffix
// stripped. On a tailnet with MagicDNS this resolves over Tailscale, so it's the
// address to pin when reaching the Mac through the VPN rather than the LAN.
function machineHostname() {
  const host = os.hostname();
  if (!host) return null;
  return host.split('.')[0];
}

// The base URL to advertise: the custom override if given, else an address built
// from the selected mode — `tailscale` uses the bare machine hostname, `wifi`
// (the default) uses the .local mDNS name. Both fall back to a LAN IP, then
// localhost.
function baseUrl() {
  if (OVERRIDE_URL) return OVERRIDE_URL;
  const host = MODE === 'tailscale'
    ? (machineHostname() || lanAddresses()[0] || 'localhost')
    : (localHostname() || lanAddresses()[0] || 'localhost');
  return `http://${host}:${PORT}/`;
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

  const base = baseUrl();
  if (OVERRIDE_URL) {
    console.log(`\nUsing custom URL (server still listens on port ${PORT}):`);
  } else if (MODE === 'tailscale') {
    console.log('\nOpen on your phone (same Tailscale tailnet):');
  } else {
    console.log('\nOpen on your phone (same Wi-Fi):');
  }
  console.log('  ' + base);

  // QR with the secret in the #fragment — never sent to the server, but the
  // page reads it from location.hash, so scanning both opens the app and hands
  // it the secret.
  const authUrl = withSecret(base, SECRET);
  console.log('\nScan to open + authenticate (secret is in the # fragment):');
  qrcode.generate(authUrl, { small: true });
  console.log(authUrl + '\n');
});
