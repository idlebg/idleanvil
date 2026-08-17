/* ============================================================================
   crypto.js — self-contained hashing + secp256k1 for the workbench.
   NO private key handling. Verification, point math and tweaking only.
   Exposes: window.BC (Bitcoin Crypto)
   ========================================================================== */
(function (global) {
  'use strict';

  /* ---------------------------------------------------------------- SHA-256 */

  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  function sha256(data) {
    data = u8(data);
    const len = data.length;
    const padded = ((len + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(padded);
    m.set(data);
    m[len] = 0x80;
    const dv = new DataView(m.buffer);
    const bits = len * 8;
    dv.setUint32(padded - 8, Math.floor(bits / 4294967296), false);
    dv.setUint32(padded - 4, bits >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a,
        h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let i = 0; i < padded; i += 64) {
      for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
      for (let j = 16; j < 64; j++) {
        const a = w[j - 15], b = w[j - 2];
        const s0 = rotr(a, 7) ^ rotr(a, 18) ^ (a >>> 3);
        const s1 = rotr(b, 17) ^ rotr(b, 19) ^ (b >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let j = 0; j < 64; j++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K256[j] + w[j]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => odv.setUint32(i * 4, v, false));
    return out;
  }

  /* ------------------------------------------------------------- RIPEMD-160 */

  const RL_IDX = [
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const RR_IDX = [
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const RL_SH = [
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const RR_SH = [
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const RL_K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const RR_K = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  function rmdF(j, x, y, z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  function ripemd160(data) {
    data = u8(data);
    const len = data.length;
    const padded = (((len + 9) + 63) >> 6) << 6;
    const m = new Uint8Array(padded);
    m.set(data);
    m[len] = 0x80;
    const dv = new DataView(m.buffer);
    const bits = len * 8;
    dv.setUint32(padded - 8, bits >>> 0, true);
    dv.setUint32(padded - 4, Math.floor(bits / 4294967296), true);

    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const x = new Uint32Array(16);

    for (let i = 0; i < padded; i += 64) {
      for (let j = 0; j < 16; j++) x[j] = dv.getUint32(i + j * 4, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        const rnd = (j / 16) | 0;
        let t = (al + rmdF(j, bl, cl, dl) + x[RL_IDX[j]] + RL_K[rnd]) >>> 0;
        t = (rotl(t, RL_SH[j]) + el) >>> 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
        t = (ar + rmdF(79 - j, br, cr, dr) + x[RR_IDX[j]] + RR_K[rnd]) >>> 0;
        t = (rotl(t, RR_SH[j]) + er) >>> 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
      }
      const t2 = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl + cr) >>> 0;
      h0 = t2;
    }
    const out = new Uint8Array(20);
    const odv = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((v, i) => odv.setUint32(i * 4, v, true));
    return out;
  }

  /* ------------------------------------------------------------------ SHA-1 */
  /* only needed so OP_SHA1 can be demonstrated in the hash lab */
  function sha1(data) {
    data = u8(data);
    const len = data.length;
    const padded = (((len + 9) + 63) >> 6) << 6;
    const m = new Uint8Array(padded);
    m.set(data); m[len] = 0x80;
    const dv = new DataView(m.buffer);
    const bits = len * 8;
    dv.setUint32(padded - 8, Math.floor(bits / 4294967296), false);
    dv.setUint32(padded - 4, bits >>> 0, false);
    let h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;
    const w = new Uint32Array(80);
    for (let i = 0; i < padded; i += 64) {
      for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
      for (let j = 16; j < 80; j++) w[j] = rotl(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let j = 0; j < 80; j++) {
        let f, k;
        if (j < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (j < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        const t = (rotl(a, 5) + f + e + k + w[j]) >>> 0;
        e = d; d = c; c = rotl(b, 30); b = a; a = t;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }
    const out = new Uint8Array(20), odv = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((v, i) => odv.setUint32(i * 4, v, false));
    return out;
  }

  /* ------------------------------------------------------------- composites */

  function u8(x) {
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return new Uint8Array(x);
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (typeof x === 'string') return new TextEncoder().encode(x);
    throw new Error('expected bytes');
  }
  function cat() {
    const parts = [].slice.call(arguments).map(u8);
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const hash256 = (b) => sha256(sha256(b));
  const hash160 = (b) => ripemd160(sha256(b));

  const _tagCache = Object.create(null);
  function taggedHash(tag, data) {
    let pre = _tagCache[tag];
    if (!pre) {
      const th = sha256(new TextEncoder().encode(tag));
      pre = _tagCache[tag] = cat(th, th);
    }
    return sha256(cat(pre, u8(data)));
  }

  /* -------------------------------------------------------------- secp256k1 */

  const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
  const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
  const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
  const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
  const G  = { x: Gx, y: Gy };

  const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };

  function invMod(a, m = P) {
    a = mod(a, m);
    if (a === 0n) throw new Error('inverse of zero');
    let [old_r, r] = [a, m], [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s, m);
  }

  function powMod(b, e, m = P) {
    let r = 1n; b = mod(b, m);
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }

  /* affine point ops; null === point at infinity */
  function ptAdd(a, b) {
    if (!a) return b;
    if (!b) return a;
    if (a.x === b.x) {
      if (mod(a.y + b.y) === 0n) return null;
      return ptDouble(a);
    }
    const l = mod((b.y - a.y) * invMod(b.x - a.x));
    const x = mod(l * l - a.x - b.x);
    return { x, y: mod(l * (a.x - x) - a.y) };
  }
  function ptDouble(a) {
    if (!a || a.y === 0n) return null;
    const l = mod(3n * a.x * a.x * invMod(2n * a.y));
    const x = mod(l * l - 2n * a.x);
    return { x, y: mod(l * (a.x - x) - a.y) };
  }
  function ptMul(k, pt = G) {
    k = mod(k, N);
    if (k === 0n) return null;
    let acc = null, add = pt;
    while (k > 0n) {
      if (k & 1n) acc = ptAdd(acc, add);
      add = ptDouble(add);
      k >>= 1n;
    }
    return acc;
  }
  function onCurve(pt) {
    if (!pt) return false;
    return mod(pt.y * pt.y - pt.x * pt.x * pt.x - 7n) === 0n;
  }

  /** BIP340 lift_x: point with even Y for a 32-byte x-only key */
  function liftX(xBytes) {
    const x = bytesToBig(xBytes);
    if (x >= P) return null;
    const ySq = mod(x * x * x + 7n);
    const y = powMod(ySq, (P + 1n) / 4n);
    if (mod(y * y) !== ySq) return null;
    return { x, y: (y & 1n) === 0n ? y : P - y };
  }

  function decompressPoint(pub) {
    pub = u8(pub);
    if (pub.length === 33 && (pub[0] === 2 || pub[0] === 3)) {
      const x = bytesToBig(pub.slice(1));
      if (x >= P) return null;
      const ySq = mod(x * x * x + 7n);
      let y = powMod(ySq, (P + 1n) / 4n);
      if (mod(y * y) !== ySq) return null;
      const wantOdd = pub[0] === 3;
      if (((y & 1n) === 1n) !== wantOdd) y = P - y;
      return { x, y };
    }
    if (pub.length === 65 && pub[0] === 4) {
      const pt = { x: bytesToBig(pub.slice(1, 33)), y: bytesToBig(pub.slice(33)) };
      return onCurve(pt) ? pt : null;
    }
    if (pub.length === 32) return liftX(pub);
    return null;
  }

  const serPoint = (pt, compressed = true) => {
    if (!pt) return new Uint8Array(0);
    const xb = bigToBytes(pt.x, 32);
    if (!compressed) return cat(new Uint8Array([4]), xb, bigToBytes(pt.y, 32));
    return cat(new Uint8Array([(pt.y & 1n) === 0n ? 2 : 3]), xb);
  };
  const xOnly = (pt) => bigToBytes(pt.x, 32);

  function bytesToBig(b) {
    b = u8(b);
    let v = 0n;
    for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
    return v;
  }
  function bigToBytes(v, len) {
    const out = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }

  /* ------------------------------------------------------- taproot tweaking */

  /**
   * BIP341 taproot output key: Q = P + int(tagged_hash("TapTweak", P||m))G
   * @param {Uint8Array} internalX 32-byte x-only internal key
   * @param {Uint8Array|null} merkleRoot 32-byte merkle root, or null/empty for key-path-only
   */
  function taprootTweak(internalX, merkleRoot) {
    const Pt = liftX(internalX);
    if (!Pt) throw new Error('internal key is not a valid x-only point');
    const msg = (merkleRoot && merkleRoot.length) ? cat(internalX, merkleRoot) : u8(internalX);
    const t = bytesToBig(taggedHash('TapTweak', msg));
    if (t >= N) throw new Error('tweak out of range');
    const Q = ptAdd(Pt, ptMul(t, G));
    if (!Q) throw new Error('tweak produced point at infinity');
    return { outputKey: xOnly(Q), parity: Number(Q.y & 1n), tweak: bigToBytes(t, 32), point: Q };
  }

  /** BIP341 tapleaf hash: tagged_hash("TapLeaf", leafVersion || compact_size(script) || script) */
  function tapLeafHash(script, leafVersion = 0xc0) {
    return taggedHash('TapLeaf', cat(new Uint8Array([leafVersion & 0xfe]), varIntBytes(script.length), script));
  }
  function tapBranchHash(a, b) {
    const [x, y] = cmpBytes(a, b) <= 0 ? [a, b] : [b, a];
    return taggedHash('TapBranch', cat(x, y));
  }
  function cmpBytes(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) { if (a[i] !== b[i]) return a[i] - b[i]; }
    return a.length - b.length;
  }
  /* local varint (encoding.js has the canonical one; duplicated to keep this file standalone) */
  function varIntBytes(n) {
    if (n < 0xfd) return new Uint8Array([n]);
    if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >> 8) & 0xff]);
    if (n <= 0xffffffff) return new Uint8Array([0xfe, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff]);
    const out = new Uint8Array(9); out[0] = 0xff;
    let v = BigInt(n);
    for (let i = 1; i <= 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }

  /* -------------------------------------------------------- DER (ECDSA sig) */

  function derEncode(r, s) {
    const trim = (v) => {
      let b = bigToBytes(v, 32);
      let i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;
      b = b.slice(i);
      if (b[0] & 0x80) b = cat(new Uint8Array([0]), b);
      return b;
    };
    const rb = trim(r), sb = trim(s);
    const body = cat(new Uint8Array([0x02, rb.length]), rb, new Uint8Array([0x02, sb.length]), sb);
    return cat(new Uint8Array([0x30, body.length]), body);
  }

  /** Lenient DER parse — reports every deviation instead of throwing. */
  function derDecode(bytes) {
    bytes = u8(bytes);
    const issues = [];
    let sighash = null;
    let der = bytes;
    // a trailing sighash byte is common on script signatures
    if (bytes.length > 2 && bytes[0] === 0x30 && bytes[1] + 2 === bytes.length - 1) {
      sighash = bytes[bytes.length - 1];
      der = bytes.slice(0, bytes.length - 1);
    }
    let i = 0;
    if (der[i++] !== 0x30) return { ok: false, error: 'missing SEQUENCE tag (0x30)', issues };
    const seqLen = der[i++];
    if (seqLen !== der.length - 2) issues.push(`sequence length ${seqLen} ≠ remaining ${der.length - 2}`);
    if (der[i++] !== 0x02) return { ok: false, error: 'missing INTEGER tag for r', issues };
    const rLen = der[i++];
    const rb = der.slice(i, i + rLen); i += rLen;
    if (der[i++] !== 0x02) return { ok: false, error: 'missing INTEGER tag for s', issues };
    const sLen = der[i++];
    const sb = der.slice(i, i + sLen); i += sLen;
    if (i !== der.length) issues.push(`${der.length - i} trailing byte(s) after s`);
    if (rb.length > 1 && rb[0] === 0 && !(rb[1] & 0x80)) issues.push('r has a non-minimal leading zero');
    if (sb.length > 1 && sb[0] === 0 && !(sb[1] & 0x80)) issues.push('s has a non-minimal leading zero');
    if (rb[0] & 0x80) issues.push('r is negative (high bit set without padding)');
    if (sb[0] & 0x80) issues.push('s is negative (high bit set without padding)');
    const r = bytesToBig(rb), s = bytesToBig(sb);
    const halfN = N >> 1n;
    return {
      ok: true, r, s, sighash, issues,
      rHex: bigToBytes(r, 32), sHex: bigToBytes(s, 32),
      lowS: s <= halfN,
      sComplement: bigToBytes(mod(N - s, N), 32),
      strictDER: issues.length === 0
    };
  }

  /* ------------------------------------------------------------ verification */

  function verifyECDSA(pubkey, msg32, sig) {
    try {
      const Q = decompressPoint(pubkey);
      if (!Q || !onCurve(Q)) return { ok: false, reason: 'invalid public key' };
      let r, s;
      if (sig && typeof sig === 'object' && 'r' in sig) { r = sig.r; s = sig.s; }
      else {
        const d = derDecode(sig);
        if (!d.ok) return { ok: false, reason: d.error };
        r = d.r; s = d.s;
      }
      if (r <= 0n || r >= N || s <= 0n || s >= N) return { ok: false, reason: 'r or s out of range' };
      const z = bytesToBig(msg32) % N;
      const sInv = invMod(s, N);
      const u1 = mod(z * sInv, N), u2 = mod(r * sInv, N);
      const R = ptAdd(ptMul(u1, G), ptMul(u2, Q));
      if (!R) return { ok: false, reason: 'R is the point at infinity' };
      return { ok: mod(R.x, N) === mod(r, N), reason: '' };
    } catch (e) { return { ok: false, reason: e.message }; }
  }

  function verifySchnorr(xonlyPub, msg32, sig64) {
    try {
      sig64 = u8(sig64);
      if (sig64.length !== 64) return { ok: false, reason: `signature is ${sig64.length} bytes, expected 64` };
      const Pt = liftX(u8(xonlyPub));
      if (!Pt) return { ok: false, reason: 'public key is not on the curve' };
      const r = bytesToBig(sig64.slice(0, 32));
      const s = bytesToBig(sig64.slice(32));
      if (r >= P) return { ok: false, reason: 'r ≥ field size' };
      if (s >= N) return { ok: false, reason: 's ≥ curve order' };
      const e = mod(bytesToBig(taggedHash('BIP0340/challenge',
        cat(sig64.slice(0, 32), bigToBytes(Pt.x, 32), u8(msg32)))), N);
      const R = ptAdd(ptMul(s, G), ptMul(N - e, Pt));
      if (!R) return { ok: false, reason: 'R is the point at infinity' };
      if ((R.y & 1n) !== 0n) return { ok: false, reason: 'R has odd Y' };
      if (R.x !== r) return { ok: false, reason: 'R.x ≠ r' };
      return { ok: true, reason: '' };
    } catch (e) { return { ok: false, reason: e.message }; }
  }

  /** Recover the two candidate R points for a given r value (forensic helper). */
  function rCandidates(rBytes) {
    const x = bytesToBig(rBytes);
    if (x >= P) return null;
    const ySq = mod(x * x * x + 7n);
    const y = powMod(ySq, (P + 1n) / 4n);
    if (mod(y * y) !== ySq) return null;
    const even = (y & 1n) === 0n ? y : P - y;
    return { even: bigToBytes(even, 32), odd: bigToBytes(P - even, 32), x: bigToBytes(x, 32) };
  }

  global.BC = {
    sha256, sha1, ripemd160, hash256, hash160, taggedHash, cat, u8,
    secp: { P, N, G, mod, invMod, powMod, ptAdd, ptDouble, ptMul, onCurve, liftX, decompressPoint, serPoint, xOnly },
    bytesToBig, bigToBytes,
    taprootTweak, tapLeafHash, tapBranchHash,
    derEncode, derDecode, verifyECDSA, verifySchnorr, rCandidates
  };
})(window);
