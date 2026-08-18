/* btc-core.js — bytes, hashes, encodings, secp256k1 point math, serialization primitives.
   No private keys. No signing. Classic script: attaches window.BTC. */
(function (g) {
  const BTC = (g.BTC = g.BTC || {});

  /* ─────────────── bytes / hex ─────────────── */
  const HEXC = '0123456789abcdef';
  const toHex = (b) => { let s = ''; for (let i = 0; i < b.length; i++) s += HEXC[b[i] >> 4] + HEXC[b[i] & 15]; return s; };
  function fromHex(h) {
    h = String(h == null ? '' : h).replace(/[\s:,]/g, '');
    if (h.length % 2) throw new Error('hex must have an even number of characters');
    if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('not hexadecimal');
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
  }
  const isHex = (h) => /^[0-9a-fA-F]*$/.test(String(h || '').replace(/[\s:,]/g, '')) && String(h || '').replace(/[\s:,]/g, '').length % 2 === 0;
  function concat(list) {
    let n = 0; for (const a of list) n += a.length;
    const out = new Uint8Array(n); let o = 0;
    for (const a of list) { out.set(a, o); o += a.length; }
    return out;
  }
  const rev = (b) => { const c = new Uint8Array(b); c.reverse(); return c; };
  const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  const utf8 = (s) => new TextEncoder().encode(s);
  const fromUtf8 = (b) => new TextDecoder().decode(b);
  function ascii(s) { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c > 127) throw new Error('non-ASCII character at ' + i); b[i] = c; } return b; }

  /* ─────────────── base64 ─────────────── */
  const b64enc = (b) => { let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
  function b64dec(s) {
    const bin = atob(String(s || '').replace(/\s/g, ''));
    const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b;
  }

  /* ─────────────── SHA-256 ─────────────── */
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));

  function sha256(msg) {
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const l = msg.length;
    const buf = new Uint8Array((((l + 8) >> 6) + 1) << 6);
    buf.set(msg); buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(buf.length - 8, Math.floor(l / 536870912), false);
    dv.setUint32(buf.length - 4, (l << 3) >>> 0, false);
    const w = new Uint32Array(64);
    for (let i = 0; i < buf.length; i += 64) {
      for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
      for (let j = 16; j < 64; j++) {
        const x = w[j - 15], y = w[j - 2];
        const s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
        const s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], gg = H[6], h = H[7];
      for (let j = 0; j < 64; j++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & gg);
        const t1 = (h + S1 + ch + K256[j] + w[j]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h = gg; gg = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + gg) | 0; H[7] = (H[7] + h) | 0;
    }
    const out = new Uint8Array(32); const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i], false);
    return out;
  }

  /* ─────────────── RIPEMD-160 ─────────────── */
  const ZL = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
  const ZR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
  const SL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
  const SR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
  const HL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const HR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  function rf(j, x, y, z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }
  function ripemd160(msg) {
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const l = msg.length;
    const buf = new Uint8Array((((l + 8) >> 6) + 1) << 6);
    buf.set(msg); buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(buf.length - 8, (l << 3) >>> 0, true);
    dv.setUint32(buf.length - 4, Math.floor(l / 536870912), true);
    const w = new Uint32Array(16);
    for (let i = 0; i < buf.length; i += 64) {
      for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        let t = (rotl((al + rf(j, bl, cl, dl) + w[ZL[j]] + HL[(j / 16) | 0]) | 0, SL[j]) + el) | 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
        t = (rotl((ar + rf(79 - j, br, cr, dr) + w[ZR[j]] + HR[(j / 16) | 0]) | 0, SR[j]) + er) | 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
      }
      const tt = (h1 + cl + dr) | 0;
      h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = tt;
    }
    const out = new Uint8Array(20); const odv = new DataView(out.buffer);
    odv.setUint32(0, h0, true); odv.setUint32(4, h1, true); odv.setUint32(8, h2, true);
    odv.setUint32(12, h3, true); odv.setUint32(16, h4, true);
    return out;
  }

  const hash256 = (b) => sha256(sha256(b));
  const hash160 = (b) => ripemd160(sha256(b));
  const tagCache = {};
  function taggedHash(tag, msg) {
    let t = tagCache[tag];
    if (!t) { const th = sha256(utf8(tag)); t = tagCache[tag] = concat([th, th]); }
    return sha256(concat([t, msg]));
  }

  /* ─────────────── Base58 / Base58Check ─────────────── */
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58enc(bytes) {
    let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits = [0];
    for (let i = zeros; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
      while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
    }
    let s = '1'.repeat(zeros);
    for (let i = digits.length - 1; i >= 0; i--) s += B58[digits[i]];
    return s;
  }
  function b58dec(str) {
    str = String(str || '').trim();
    let zeros = 0; while (zeros < str.length && str[zeros] === '1') zeros++;
    const bytes = [0];
    for (let i = zeros; i < str.length; i++) {
      const v = B58.indexOf(str[i]);
      if (v < 0) throw new Error('invalid base58 character "' + str[i] + '"');
      let carry = v;
      for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>= 8; }
      while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    const out = new Uint8Array(zeros + bytes.length);
    for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
    return out;
  }
  const b58check = (payload) => b58enc(concat([payload, hash256(payload).slice(0, 4)]));
  function b58checkDec(str) {
    const raw = b58dec(str);
    if (raw.length < 5) throw new Error('base58check payload too short');
    const body = raw.slice(0, -4), chk = raw.slice(-4);
    if (!eq(hash256(body).slice(0, 4), chk)) throw new Error('base58check checksum mismatch');
    return body;
  }

  /* ─────────────── Bech32 / Bech32m ─────────────── */
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function polymod(vals) {
    let chk = 1;
    for (const v of vals) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]; }
    return chk;
  }
  function hrpExpand(hrp) {
    const r = [];
    for (let i = 0; i < hrp.length; i++) r.push(hrp.charCodeAt(i) >> 5);
    r.push(0);
    for (let i = 0; i < hrp.length; i++) r.push(hrp.charCodeAt(i) & 31);
    return r;
  }
  const BECH32_CONST = 1, BECH32M_CONST = 0x2bc830a3;
  function bechEncode(hrp, data, spec) {
    const c = spec === 'bech32m' ? BECH32M_CONST : BECH32_CONST;
    const vals = hrpExpand(hrp).concat(data);
    const pm = polymod(vals.concat([0, 0, 0, 0, 0, 0])) ^ c;
    const chk = []; for (let i = 0; i < 6; i++) chk.push((pm >> (5 * (5 - i))) & 31);
    return hrp + '1' + data.concat(chk).map((d) => CHARSET[d]).join('');
  }
  function bechDecode(str) {
    const s = String(str || '').trim();
    if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error('mixed case bech32 string');
    const low = s.toLowerCase();
    const pos = low.lastIndexOf('1');
    if (pos < 1 || pos + 7 > low.length) throw new Error('malformed bech32 string');
    const hrp = low.slice(0, pos);
    const data = [];
    for (let i = pos + 1; i < low.length; i++) {
      const v = CHARSET.indexOf(low[i]);
      if (v < 0) throw new Error('invalid bech32 character "' + low[i] + '"');
      data.push(v);
    }
    const pm = polymod(hrpExpand(hrp).concat(data));
    const spec = pm === BECH32_CONST ? 'bech32' : pm === BECH32M_CONST ? 'bech32m' : null;
    if (!spec) throw new Error('bech32 checksum mismatch');
    return { hrp: hrp, data: data.slice(0, -6), spec: spec };
  }
  function convertBits(data, from, to, pad) {
    let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1;
    for (const v of data) {
      if (v < 0 || v >> from) throw new Error('convertBits: value out of range');
      acc = (acc << from) | v; bits += from;
      while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
    else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('convertBits: invalid padding');
    return out;
  }

  /* ─────────────── secp256k1 point math (no private keys, no signing) ─────────────── */
  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  const mod = (a, m) => { const r = a % m; return r < 0n ? r + m : r; };
  function powMod(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
  const inv = (a, m) => powMod(mod(a, m), m - 2n, m);
  const G = { x: Gx, y: Gy };
  function ptAdd(p1, p2) {
    if (!p1) return p2; if (!p2) return p1;
    if (p1.x === p2.x && mod(p1.y + p2.y, P) === 0n) return null;
    const lam = p1.x === p2.x && p1.y === p2.y
      ? mod(3n * p1.x * p1.x * inv(2n * p1.y, P), P)
      : mod((p2.y - p1.y) * inv(p2.x - p1.x, P), P);
    const x = mod(lam * lam - p1.x - p2.x, P);
    return { x: x, y: mod(lam * (p1.x - x) - p1.y, P) };
  }
  function ptMul(k, p) {
    k = mod(k, N); let r = null, a = p;
    while (k > 0n) { if (k & 1n) r = ptAdd(r, a); a = ptAdd(a, a); k >>= 1n; }
    return r;
  }
  function liftX(xBig) {
    if (xBig <= 0n || xBig >= P) throw new Error('x coordinate out of field range');
    const c = mod(xBig * xBig * xBig + 7n, P);
    const y = powMod(c, (P + 1n) / 4n, P);
    if (mod(y * y, P) !== c) throw new Error('x is not on the secp256k1 curve');
    return { x: xBig, y: (y & 1n) === 0n ? y : P - y };
  }
  const bigToBytes = (v, len) => { let h = v.toString(16); if (h.length > len * 2) throw new Error('integer too large'); return fromHex(h.padStart(len * 2, '0')); };
  const bytesToBig = (b) => (b.length ? BigInt('0x' + toHex(b)) : 0n);
  function pointFromPubkey(bytes) {
    if (bytes.length === 32) return liftX(bytesToBig(bytes));
    if (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) {
      const pt = liftX(bytesToBig(bytes.slice(1)));
      return bytes[0] === 3 ? { x: pt.x, y: P - pt.y } : pt;
    }
    if (bytes.length === 65 && bytes[0] === 4) {
      const pt = { x: bytesToBig(bytes.slice(1, 33)), y: bytesToBig(bytes.slice(33)) };
      if (pt.x <= 0n || pt.x >= P || pt.y <= 0n || pt.y >= P || mod(pt.y * pt.y - pt.x * pt.x * pt.x - 7n, P) !== 0n)
        throw new Error('uncompressed public key is not a point on the secp256k1 curve');
      return pt;
    }
    throw new Error('unrecognised public key encoding (' + bytes.length + ' bytes)');
  }
  const pointToCompressed = (pt) => concat([new Uint8Array([(pt.y & 1n) === 0n ? 2 : 3]), bigToBytes(pt.x, 32)]);
  const pointToUncompressed = (pt) => concat([new Uint8Array([4]), bigToBytes(pt.x, 32), bigToBytes(pt.y, 32)]);
  const xOnly = (pt) => bigToBytes(pt.x, 32);

  /* ─────────────── DER ↔ (r, s) ─────────────── */
  function derFromRS(rHex, sHex, sighashByte) {
    const trim = (h) => { let b = fromHex(h); let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = concat([new Uint8Array([0]), b]); return b; };
    const r = trim(rHex), s = trim(sHex);
    const body = concat([new Uint8Array([0x02, r.length]), r, new Uint8Array([0x02, s.length]), s]);
    const der = concat([new Uint8Array([0x30, body.length]), body]);
    return sighashByte == null ? der : concat([der, new Uint8Array([sighashByte & 0xff])]);
  }
  function derParse(hex) {
    const b = fromHex(hex);
    let i = 0; const out = { valid: true, notes: [] };
    if (b[i++] !== 0x30) throw new Error('DER: expected 0x30 SEQUENCE header');
    const len = b[i++];
    if (len + 2 !== b.length && len + 3 !== b.length) out.notes.push('declared length does not match the byte count');
    out.hasSighashByte = len + 3 === b.length;
    if (b[i++] !== 0x02) throw new Error('DER: expected 0x02 INTEGER before r');
    const rl = b[i++]; const r = b.slice(i, i + rl); i += rl;
    if (b[i++] !== 0x02) throw new Error('DER: expected 0x02 INTEGER before s');
    const sl = b[i++]; const s = b.slice(i, i + sl); i += sl;
    out.sighashByte = out.hasSighashByte ? b[i] : null;
    const rb = bytesToBig(r), sb = bytesToBig(s);
    out.r = rb.toString(16).padStart(64, '0');
    out.s = sb.toString(16).padStart(64, '0');
    out.sLow = (sb > N / 2n ? N - sb : sb).toString(16).padStart(64, '0');
    out.nMinusS = mod(N - sb, N).toString(16).padStart(64, '0');
    out.isLowS = sb <= N / 2n;
    if (r[0] & 0x80) out.notes.push('r has the high bit set without a leading zero pad');
    if (rl > 1 && r[0] === 0 && !(r[1] & 0x80)) out.notes.push('r carries an unnecessary leading zero');
    if (sl > 1 && s[0] === 0 && !(s[1] & 0x80)) out.notes.push('s carries an unnecessary leading zero');
    if (!out.isLowS) out.notes.push('high-S — non-standard under BIP 62 / policy');
    if (rb === 0n || rb >= N) out.notes.push('r is outside 1..n-1');
    if (sb === 0n || sb >= N) out.notes.push('s is outside 1..n-1');
    return out;
  }
  function rCandidates(rHex) {
    const rb = BigInt('0x' + String(rHex || '0').replace(/^0x/, ''));
    const out = { even: null, odd: null, error: null };
    try { const pt = liftX(mod(rb, P)); out.even = toHex(pointToCompressed(pt)); out.odd = toHex(pointToCompressed({ x: pt.x, y: P - pt.y })); }
    catch (e) { out.error = e.message; }
    return out;
  }

  /* ─────────────── writer / reader ─────────────── */
  class Writer {
    constructor() { this.parts = []; this.len = 0; this.marks = []; }
    raw(b) { this.parts.push(b); this.len += b.length; return this; }
    mark(label, fn, meta) {
      const start = this.len; fn(); this.marks.push({ label: label, start: start, end: this.len, meta: meta || null }); return this;
    }
    u8(v) { return this.raw(new Uint8Array([v & 0xff])); }
    u16(v) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, true); return this.raw(b); }
    u32(v) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0, true); return this.raw(b); }
    i32(v) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v | 0, true); return this.raw(b); }
    u64(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v) & 0xffffffffffffffffn, true); return this.raw(b); }
    i64(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); return this.raw(b); }
    varint(v) {
      v = Number(v);
      if (v < 0xfd) return this.u8(v);
      if (v <= 0xffff) return this.u8(0xfd).u16(v);
      if (v <= 0xffffffff) return this.u8(0xfe).u32(v);
      return this.u8(0xff).u64(v);
    }
    varslice(b) { return this.varint(b.length).raw(b); }
    bytes() { return concat(this.parts); }
    hex() { return toHex(this.bytes()); }
  }
  class Reader {
    constructor(b) { this.b = b; this.o = 0; }
    get left() { return this.b.length - this.o; }
    need(n) { if (this.o + n > this.b.length) throw new Error('unexpected end of data at byte ' + this.o); }
    raw(n) { this.need(n); const r = this.b.slice(this.o, this.o + n); this.o += n; return r; }
    u8() { this.need(1); return this.b[this.o++]; }
    u16() { const r = this.raw(2); return new DataView(r.buffer, r.byteOffset, 2).getUint16(0, true); }
    u32() { const r = this.raw(4); return new DataView(r.buffer, r.byteOffset, 4).getUint32(0, true); }
    i32() { const r = this.raw(4); return new DataView(r.buffer, r.byteOffset, 4).getInt32(0, true); }
    u64() { const r = this.raw(8); return new DataView(r.buffer, r.byteOffset, 8).getBigUint64(0, true); }
    varint() {
      const p = this.u8();
      if (p < 0xfd) return p;
      if (p === 0xfd) return this.u16();
      if (p === 0xfe) return this.u32();
      return Number(this.u64());
    }
    varslice() { return this.raw(this.varint()); }
  }

  /* ─────────────── networks ─────────────── */
  const NETWORKS = {
    mainnet: { label: 'Mainnet', hrp: 'bc', p2pkh: 0x00, p2sh: 0x05, wif: 0x80, defaultPort: 8333, magic: 'f9beb4d9' },
    testnet3: { label: 'Testnet3', hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4, wif: 0xef, defaultPort: 18333, magic: '0b110907' },
    testnet4: { label: 'Testnet4', hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4, wif: 0xef, defaultPort: 48333, magic: '1c163f28' },
    signet: { label: 'Signet', hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4, wif: 0xef, defaultPort: 38333, magic: '0a03cf40' },
    regtest: { label: 'Regtest', hrp: 'bcrt', p2pkh: 0x6f, p2sh: 0xc4, wif: 0xef, defaultPort: 18444, magic: 'fabfb5da' }
  };

  Object.assign(BTC, {
    toHex, fromHex, isHex, concat, rev, eq, utf8, fromUtf8, ascii, b64enc, b64dec,
    sha256, ripemd160, hash256, hash160, taggedHash,
    b58enc, b58dec, b58check, b58checkDec,
    bechEncode, bechDecode, convertBits,
    P, N, G, mod, powMod, inv, ptAdd, ptMul, liftX, bigToBytes, bytesToBig,
    pointFromPubkey, pointToCompressed, pointToUncompressed, xOnly,
    derFromRS, derParse, rCandidates,
    Writer, Reader, NETWORKS
  });
})(typeof window !== 'undefined' ? window : globalThis);
