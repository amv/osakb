/*
 * Pure-JS ChaCha20 stream cipher (RFC 8439).
 *
 * Used to encrypt keystroke payloads. `crypto.subtle` is unavailable on osakb's
 * plain-HTTP LAN pages, so this runs in the browser; the same file is also
 * require()d by the server so both sides use an identical, test-vector-verified
 * implementation (guaranteeing interop).
 *
 * ChaCha20 provides confidentiality only — authentication is layered on top via
 * HMAC-SHA256 (encrypt-then-MAC). Never reuse a (key, nonce) pair: callers use a
 * fresh random 96-bit nonce per message.
 *
 * UMD: sets window.ChaCha20 in the browser, module.exports in Node.
 */
(function (root) {
  'use strict';

  function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

  function quarter(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
  }

  // Produce one 64-byte keystream block into `out`.
  function block(key32, counter, nonce32, out) {
    var s = [
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
      key32[0], key32[1], key32[2], key32[3],
      key32[4], key32[5], key32[6], key32[7],
      counter >>> 0, nonce32[0], nonce32[1], nonce32[2]
    ];
    var x = s.slice(0);
    for (var i = 0; i < 10; i++) {
      quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13);
      quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
      quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12);
      quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) {
      var v = (x[i] + s[i]) >>> 0;
      out[i * 4] = v & 0xff; out[i * 4 + 1] = (v >>> 8) & 0xff;
      out[i * 4 + 2] = (v >>> 16) & 0xff; out[i * 4 + 3] = (v >>> 24) & 0xff;
    }
  }

  function toWords(b) {
    var w = new Uint32Array(b.length >> 2);
    for (var i = 0; i < w.length; i++) {
      w[i] = ((b[i * 4]) | (b[i * 4 + 1] << 8) | (b[i * 4 + 2] << 16) | (b[i * 4 + 3] << 24)) >>> 0;
    }
    return w;
  }

  // XOR `data` with the ChaCha20 keystream. Encryption and decryption are the
  // same operation. key: 32 bytes, nonce: 12 bytes, counter: uint32 start.
  function xor(key, nonce, counter, data) {
    var key32 = toWords(key);
    var nonce32 = toWords(nonce);
    var out = new Uint8Array(data.length);
    var ks = new Uint8Array(64);
    var c = counter >>> 0;
    for (var off = 0; off < data.length; off += 64) {
      block(key32, c, nonce32, ks);
      c = (c + 1) >>> 0;
      var n = Math.min(64, data.length - off);
      for (var i = 0; i < n; i++) out[off + i] = data[off + i] ^ ks[i];
    }
    return out;
  }

  var api = { xor: xor, block: block };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ChaCha20 = api;
})(typeof self !== 'undefined' ? self : this);
