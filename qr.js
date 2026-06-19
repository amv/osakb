// qr.js — minimal, zero-dependency QR code generator for the terminal.
//
// Deliberately specialized to a single configuration:
//   * Version 5  (37x37 modules)
//   * Error correction level L
//   * 8-bit byte mode only
//
// That covers any payload up to 106 bytes — comfortably more than the
// `http://host:port/#<32-hex-secret>` URLs this tool usually encodes.
// Fixing the version/level/mode lets us drop every capacity table,
// mode-selection heuristic, and the version-information block that a general
// QR library needs. v5-L also uses a single Reed-Solomon block, so there is no
// block interleaving either. The one real algorithm left is Reed-Solomon over
// GF(256).
//
// Drop-in replacement for the `generate(input, opts)` call of the vendored
// npm library that was originally used: qrcode-terminal. If there is a future
// need for QR codes that fit larger urls, replacement should be simple.

'use strict';

// ---------------------------------------------------------------------------
// Configuration constants for Version 5 / level L (from the QR spec tables).
// A single RS block of 108 data + 26 EC codewords (totalling 134).
// ---------------------------------------------------------------------------
const MODULE_COUNT = 37;        // 5 * 4 + 17
const EC_LEVEL_BITS = 1;        // level L is encoded as 1 in the format info
const ALIGN_POS = [6, 30];      // alignment-pattern center coordinates
const TOTAL_DATA_CODEWORDS = 108;
const EC_CODEWORDS = 26;        // 134 total - 108 data
const MAX_BYTES = 106;          // 4 (mode) + 8 (count) + 8*N <= 108*8
const PAD_BYTES = [0xec, 0x11];

// ---------------------------------------------------------------------------
// GF(256) arithmetic, primitive polynomial 0x11d (same field as the QR spec).
// ---------------------------------------------------------------------------
const EXP = new Array(256);
const LOG = new Array(256);
(function buildTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  EXP[255] = EXP[0];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a] + LOG[b]) % 255];
}

// Generator polynomial for `n` EC codewords: product of (x - a^i), i=0..n-1.
// Built lowest-degree-first, then reversed so it is highest-degree-first
// (monic, leading coefficient 1) as rsEncode expects.
function rsGenerator(n) {
  let g = [1];
  for (let i = 0; i < n; i++) {
    const next = new Array(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j++) {
      next[j] ^= gfMul(g[j], EXP[i]); // g[j] * a^i
      next[j + 1] ^= g[j];            // g[j] * x
    }
    g = next;
  }
  return g.reverse();
}

// Reed-Solomon EC codewords: remainder of x^n * data(x) divided by gen(x).
function rsEncode(data, ecLen) {
  const gen = rsGenerator(ecLen);
  const res = data.concat(new Array(ecLen).fill(0));
  for (let i = 0; i < data.length; i++) {
    const coef = res[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        res[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return res.slice(data.length);
}

// ---------------------------------------------------------------------------
// Data encoding: byte mode -> 108 data codewords (with terminator & padding).
// ---------------------------------------------------------------------------
function encodeData(text) {
  const bytes = [];
  for (let i = 0; i < text.length; i++) bytes.push(text.charCodeAt(i) & 0xff);
  if (bytes.length > MAX_BYTES) {
    throw new Error(
      `payload too long for QR v5-L: ${bytes.length} bytes (max ${MAX_BYTES})`
    );
  }

  const bits = [];
  const put = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };

  put(0b0100, 4);          // byte-mode indicator
  put(bytes.length, 8);    // character count (8 bits for byte mode at v1-9)
  for (const b of bytes) put(b, 8);

  const capacityBits = TOTAL_DATA_CODEWORDS * 8;
  // Terminator: up to four 0 bits, only as far as capacity allows.
  for (let i = 0; i < 4 && bits.length < capacityBits; i++) bits.push(0);
  // Pad to a byte boundary.
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    codewords.push(b);
  }
  // Pad with the alternating fill bytes until the block is full.
  for (let p = 0; codewords.length < TOTAL_DATA_CODEWORDS; p++) {
    codewords.push(PAD_BYTES[p % 2]);
  }
  return codewords;
}

// Build the full codeword sequence: data followed by EC. With a single RS block
// there is no interleaving — the two simply concatenate.
function buildCodewords(text) {
  const data = encodeData(text);
  return data.concat(rsEncode(data, EC_CODEWORDS));
}

// ---------------------------------------------------------------------------
// Matrix construction.
// ---------------------------------------------------------------------------
function newMatrix() {
  return Array.from({ length: MODULE_COUNT }, () =>
    new Array(MODULE_COUNT).fill(null)
  );
}

function setupFinder(m, row, col) {
  for (let r = -1; r <= 7; r++) {
    if (row + r <= -1 || MODULE_COUNT <= row + r) continue;
    for (let c = -1; c <= 7; c++) {
      if (col + c <= -1 || MODULE_COUNT <= col + c) continue;
      const isPattern =
        (0 <= r && r <= 6 && (c === 0 || c === 6)) ||
        (0 <= c && c <= 6 && (r === 0 || r === 6)) ||
        (2 <= r && r <= 4 && 2 <= c && c <= 4);
      m[row + r][col + c] = isPattern;
    }
  }
}

function setupAlignment(m) {
  for (let i = 0; i < ALIGN_POS.length; i++) {
    for (let j = 0; j < ALIGN_POS.length; j++) {
      const row = ALIGN_POS[i];
      const col = ALIGN_POS[j];
      if (m[row][col] !== null) continue; // overlaps a finder pattern
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          m[row + r][col + c] =
            Math.abs(r) === 2 || Math.abs(c) === 2 || (r === 0 && c === 0);
        }
      }
    }
  }
}

function setupTiming(m) {
  for (let i = 8; i < MODULE_COUNT - 8; i++) {
    if (m[i][6] === null) m[i][6] = i % 2 === 0;
    if (m[6][i] === null) m[6][i] = i % 2 === 0;
  }
}

// 15-bit BCH-coded format information (EC level + mask).
function bchTypeInfo(data) {
  const G15 =
    (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
  const G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);
  const bitDigit = (v) => {
    let d = 0;
    while (v !== 0) { d++; v >>>= 1; }
    return d;
  };
  let d = data << 10;
  while (bitDigit(d) - bitDigit(G15) >= 0) {
    d ^= G15 << (bitDigit(d) - bitDigit(G15));
  }
  return ((data << 10) | d) ^ G15_MASK;
}

// Reserve and fill the format-information modules. During mask evaluation
// (`test` true) these are left blank (light) so the penalty score reflects
// only the data/function modules — matching how the mask is chosen.
function setupFormat(m, mask, test) {
  const bits = bchTypeInfo((EC_LEVEL_BITS << 3) | mask);
  const N = MODULE_COUNT;
  const bit = (i) => !test && ((bits >> i) & 1) === 1;
  for (let v = 0; v < 15; v++) {
    const on = bit(v);
    if (v < 6) m[v][8] = on;
    else if (v < 8) m[v + 1][8] = on;
    else m[N - 15 + v][8] = on;
  }
  for (let h = 0; h < 15; h++) {
    const on = bit(h);
    if (h < 8) m[8][N - h - 1] = on;
    else if (h < 9) m[8][15 - h - 1 + 1] = on;
    else m[8][15 - h - 1] = on;
  }
  m[N - 8][8] = !test; // always-dark module
}

function maskFn(mask, i, j) {
  switch (mask) {
    case 0: return (i + j) % 2 === 0;
    case 1: return i % 2 === 0;
    case 2: return j % 3 === 0;
    case 3: return (i + j) % 3 === 0;
    case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
    case 5: return ((i * j) % 2) + ((i * j) % 3) === 0;
    case 6: return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0;
    case 7: return (((i * j) % 3) + ((i + j) % 2)) % 2 === 0;
    default: throw new Error('bad mask: ' + mask);
  }
}

function mapData(m, codewords, mask) {
  const N = MODULE_COUNT;
  let inc = -1;
  let row = N - 1;
  let bitIndex = 7;
  let byteIndex = 0;
  for (let col = N - 1; col > 0; col -= 2) {
    if (col === 6) col--; // skip the vertical timing column
    for (;;) {
      for (let c = 0; c < 2; c++) {
        if (m[row][col - c] === null) {
          let dark = false;
          if (byteIndex < codewords.length) {
            dark = ((codewords[byteIndex] >>> bitIndex) & 1) === 1;
          }
          if (maskFn(mask, row, col - c)) dark = !dark;
          m[row][col - c] = dark;
          if (--bitIndex === -1) { byteIndex++; bitIndex = 7; }
        }
      }
      row += inc;
      if (row < 0 || N <= row) { row -= inc; inc = -inc; break; }
    }
  }
}

// Penalty score (lower is better) used to choose the mask, per the QR spec.
function lostPoint(m) {
  const N = MODULE_COUNT;
  const dark = (r, c) => m[r][c] === true;
  let lost = 0;

  // Rule 1: runs of same-colored modules in rows/columns.
  for (let r = 0; r < N; r++) {
    for (let c = 0; c < N; c++) {
      let same = 0;
      const d = dark(r, c);
      for (let dr = -1; dr <= 1; dr++) {
        if (r + dr < 0 || N <= r + dr) continue;
        for (let dc = -1; dc <= 1; dc++) {
          if (c + dc < 0 || N <= c + dc) continue;
          if (dr === 0 && dc === 0) continue;
          if (d === dark(r + dr, c + dc)) same++;
        }
      }
      if (same > 5) lost += 3 + same - 5;
    }
  }

  // Rule 2: 2x2 blocks of one color.
  for (let r = 0; r < N - 1; r++) {
    for (let c = 0; c < N - 1; c++) {
      let count = 0;
      if (dark(r, c)) count++;
      if (dark(r + 1, c)) count++;
      if (dark(r, c + 1)) count++;
      if (dark(r + 1, c + 1)) count++;
      if (count === 0 || count === 4) lost += 3;
    }
  }

  // Rule 3: finder-like 1:1:3:1:1 patterns.
  for (let r = 0; r < N; r++) {
    for (let c = 0; c < N - 6; c++) {
      if (dark(r, c) && !dark(r, c + 1) && dark(r, c + 2) && dark(r, c + 3) &&
          dark(r, c + 4) && !dark(r, c + 5) && dark(r, c + 6)) lost += 40;
    }
  }
  for (let c = 0; c < N; c++) {
    for (let r = 0; r < N - 6; r++) {
      if (dark(r, c) && !dark(r + 1, c) && dark(r + 2, c) && dark(r + 3, c) &&
          dark(r + 4, c) && !dark(r + 5, c) && dark(r + 6, c)) lost += 40;
    }
  }

  // Rule 4: overall dark/light balance.
  let darkCount = 0;
  for (let c = 0; c < N; c++) {
    for (let r = 0; r < N; r++) if (dark(r, c)) darkCount++;
  }
  const ratio = Math.abs((100 * darkCount) / (N * N) - 50) / 5;
  lost += ratio * 10;

  return lost;
}

// Build the finished module matrix for a given mask (0-7). With `test` true the
// format-info modules are blanked, for use only in mask-penalty scoring.
function buildMatrix(text, mask, test) {
  const m = newMatrix();
  setupFinder(m, 0, 0);
  setupFinder(m, MODULE_COUNT - 7, 0);
  setupFinder(m, 0, MODULE_COUNT - 7);
  setupAlignment(m);
  setupTiming(m);
  setupFormat(m, mask, test);
  mapData(m, buildCodewords(text), mask);
  return m;
}

function bestMask(text) {
  let best = 0;
  let min = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const score = lostPoint(buildMatrix(text, mask, true));
    if (score < min) { min = score; best = mask; }
  }
  return best;
}

// Build the final matrix, choosing the lowest-penalty mask.
function build(text) {
  return buildMatrix(text, bestMask(text));
}

// ---------------------------------------------------------------------------
// Terminal rendering (matches qrcode-terminal's `{ small: true }` output).
// ---------------------------------------------------------------------------
function renderSmall(m) {
  const N = m.length;
  const GLYPH = { both: '█', top: '▀', bottom: '▄', none: ' ' };
  // qrcode-terminal's border is `new Array(N+3).join(glyph)` => N+2 glyphs.
  const border = (g) => g.repeat(N + 2);

  const rows = m.slice();
  const oddRow = N % 2 === 1;
  if (oddRow) rows.push(new Array(N).fill(false));

  let out = border(GLYPH.bottom) + '\n';
  for (let row = 0; row < N; row += 2) {
    let line = GLYPH.both;
    for (let col = 0; col < N; col++) {
      const top = rows[row][col] === true;
      const bot = rows[row + 1][col] === true;
      if (!top && !bot) line += GLYPH.both;
      else if (!top && bot) line += GLYPH.top;
      else if (top && !bot) line += GLYPH.bottom;
      else line += GLYPH.none;
    }
    line += GLYPH.both;
    out += line + '\n';
  }
  if (!oddRow) out += border(GLYPH.top);
  return out;
}

function renderLarge(m) {
  const N = m.length;
  const black = '[40m  [0m';
  const white = '[47m  [0m';
  const border = white.repeat(N + 2);
  let out = border + '\n';
  for (const row of m) {
    out += white + row.map((d) => (d ? black : white)).join('') + white + '\n';
  }
  out += border;
  return out;
}

// Drop-in replacement for qrcode-terminal's generate(input, opts, cb).
function generate(input, opts, cb) {
  if (typeof opts === 'function') { cb = opts; opts = {}; }
  opts = opts || {};
  const m = build(String(input));
  const output = opts.small ? renderSmall(m) : renderLarge(m);
  if (cb) cb(output);
  else console.log(output);
  return output;
}

module.exports = {
  generate,
  // Exposed for testing.
  _internal: {
    MODULE_COUNT,
    MAX_BYTES,
    buildCodewords,
    buildMatrix,
    bestMask,
    build,
  },
};
