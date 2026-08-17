/* ============================================================================
   encoding.js — hex / varint / base58 / bech32 / bech32m / base64 / byte writer
   Exposes: window.ENC
   ========================================================================== */
(function (global) {
  'use strict';

  const HEXCHARS = '0123456789abcdef';

  function bytesToHex(b) {
    if (!b) return '';
    let s = '';
    for (let i = 0; i < b.length; i++) s += HEXCHARS[b[i] >> 4] + HEXCHARS[b[i] & 15];
    return s;
  }

  function hexToBytes(h) {
    if (h == null) return new Uint8Array(0);
    h = String(h).replace(/^0x/i, '').replace(/[\s:,_-]/g, '');
    if (h.length % 2) throw new Error('hex string has an odd length (' + h.length + ')');
    if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('hex string contains non-hex characters');
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }

  const isHex = (h) => typeof h === 'string' && /^[0-9a-fA-F]*$/.test(h.replace(/\s/g, '')) && h.replace(/\s/g, '').length % 2 === 0;
  const reverse = (b) => new Uint8Array(b).reverse();
  const utf8ToBytes = (s) => new TextEncoder().encode(s);
  const bytesToUtf8 = (b) => new TextDecoder('utf-8', { fatal: false }).decode(b);

  function asciiToBytes(s) {
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c > 0xff) throw new Error(`character "${s[i]}" at position ${i} is not 8-bit ASCII/latin-1`);
      out[i] = c;
    }
    return out;
  }
  function bytesToAscii(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += (b[i] >= 0x20 && b[i] < 0x7f) ? String.fromCharCode(b[i]) : '.';
    return s;
  }

  /* -------------------------------------------------------------- base64 */

  function bytesToBase64(b) {
    let bin = '';
    for (let i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
    return btoa(bin);
  }
  function base64ToBytes(s) {
    const bin = atob(String(s).trim().replace(/\s/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  /* ------------------------------------------------------------- varint */

  function varIntSize(n) {
    if (typeof n === 'bigint') return n < 0xfdn ? 1 : n <= 0xffffn ? 3 : n <= 0xffffffffn ? 5 : 9;
    n = Number(n);
    if (n < 0xfd) return 1;
    if (n <= 0xffff) return 3;
    if (n <= 0xffffffff) return 5;
    return 9;
  }
  function encodeVarInt(n) {
    /* accepts number or BigInt — the 8-byte form must not round-trip through
       Number, which loses precision above 2^53 */
    const v = typeof n === 'bigint' ? n : BigInt(Math.trunc(Number(n)));
    if (v < 0n) throw new Error('varint cannot be negative');
    if (v < 0xfdn) return new Uint8Array([Number(v)]);
    if (v <= 0xffffn) { const x = Number(v); return new Uint8Array([0xfd, x & 0xff, (x >> 8) & 0xff]); }
    if (v <= 0xffffffffn) { const x = Number(v); return new Uint8Array([0xfe, x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >>> 24) & 0xff]); }
    const out = new Uint8Array(9); out[0] = 0xff;
    let b = v;
    for (let i = 1; i <= 8; i++) { out[i] = Number(b & 0xffn); b >>= 8n; }
    return out;
  }

  /* --------------------------------------------------------- byte writer */

  class Writer {
    constructor() { this.chunks = []; this.length = 0; }
    push(b) { if (b && b.length) { this.chunks.push(b); this.length += b.length; } return this; }
    u8(v) { return this.push(new Uint8Array([v & 0xff])); }
    u16(v) { return this.push(new Uint8Array([v & 0xff, (v >> 8) & 0xff])); }
    u32(v) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v >>> 0, true); return this.push(b); }
    i32(v) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v | 0, true); return this.push(b); }
    u64(v) {
      const b = new Uint8Array(8);
      let x = BigInt(v);
      if (x < 0n) x = (1n << 64n) + x;      // allow the SIGHASH_SINGLE -1 sentinel
      for (let i = 0; i < 8; i++) { b[i] = Number(x & 0xffn); x >>= 8n; }
      return this.push(b);
    }
    varint(n) { return this.push(encodeVarInt(n)); }
    varslice(b) { this.varint(b.length); return this.push(b); }
    hex(h) { return this.push(hexToBytes(h)); }
    bytes() {
      const out = new Uint8Array(this.length);
      let o = 0;
      for (const c of this.chunks) { out.set(c, o); o += c.length; }
      return out;
    }
    toHex() { return bytesToHex(this.bytes()); }
  }

  /* --------------------------------------------------------- byte reader */

  class Reader {
    constructor(bytes) { this.b = bytes instanceof Uint8Array ? bytes : hexToBytes(bytes); this.o = 0; }
    get left() { return this.b.length - this.o; }
    get eof() { return this.o >= this.b.length; }
    need(n) { if (this.o + n > this.b.length) throw new Error(`unexpected end of data at byte ${this.o} (needed ${n}, have ${this.left})`); }
    take(n) { this.need(n); const s = this.b.slice(this.o, this.o + n); this.o += n; return s; }
    u8() { this.need(1); return this.b[this.o++]; }
    u16() { const s = this.take(2); return s[0] | (s[1] << 8); }
    u32() { const s = this.take(4); return new DataView(s.buffer, s.byteOffset, 4).getUint32(0, true); }
    i32() { const s = this.take(4); return new DataView(s.buffer, s.byteOffset, 4).getInt32(0, true); }
    u64() {
      const s = this.take(8);
      let v = 0n;
      for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(s[i]);
      return v;
    }
    varint() {
      const f = this.u8();
      if (f < 0xfd) return f;
      if (f === 0xfd) return this.u16();
      if (f === 0xfe) return this.u32();
      return Number(this.u64());
    }
    varslice() { return this.take(this.varint()); }
    peek() { return this.b[this.o]; }
  }

  /* -------------------------------------------------------------- base58 */

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const B58MAP = (() => { const m = {}; for (let i = 0; i < B58.length; i++) m[B58[i]] = i; return m; })();

  function base58Encode(bytes) {
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits = [0];
    for (let i = zeros; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
    }
    let s = '1'.repeat(zeros);
    for (let i = digits.length - 1; i >= 0; i--) s += B58[digits[i]];
    return s;
  }

  function base58Decode(str) {
    str = String(str).trim();
    if (!str.length) return new Uint8Array(0);
    let zeros = 0;
    while (zeros < str.length && str[zeros] === '1') zeros++;
    const bytes = [0];
    for (let i = zeros; i < str.length; i++) {
      const val = B58MAP[str[i]];
      if (val === undefined) throw new Error(`"${str[i]}" is not a base58 character`);
      let carry = val;
      for (let j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    const out = new Uint8Array(zeros + bytes.length);
    for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
    return out;
  }

  function base58checkEncode(payload) {
    const chk = BC.hash256(payload).slice(0, 4);
    return base58Encode(BC.cat(payload, chk));
  }
  function base58checkDecode(str) {
    const raw = base58Decode(str);
    if (raw.length < 5) throw new Error('base58check payload is too short');
    const body = raw.slice(0, -4), chk = raw.slice(-4);
    const exp = BC.hash256(body).slice(0, 4);
    for (let i = 0; i < 4; i++) if (chk[i] !== exp[i]) throw new Error('base58check checksum mismatch');
    return body;
  }

  /* ------------------------------------------------- bech32 / bech32m */

  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  const BECH32_CONST = 1, BECH32M_CONST = 0x2bc830a3;

  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }
  function hrpExpand(hrp) {
    const out = [];
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
    out.push(0);
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }
  function bech32Encode(hrp, data, constant) {
    const values = hrpExpand(hrp).concat(data);
    const mod = polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ constant;
    const chk = [];
    for (let i = 0; i < 6; i++) chk.push((mod >> (5 * (5 - i))) & 31);
    return hrp + '1' + data.concat(chk).map(d => CHARSET[d]).join('');
  }
  function bech32Decode(str) {
    if (/[a-z]/.test(str) && /[A-Z]/.test(str)) throw new Error('mixed upper and lower case');
    const s = str.toLowerCase();
    const pos = s.lastIndexOf('1');
    if (pos < 1 || pos + 7 > s.length) throw new Error('malformed bech32 string (bad separator position)');
    const hrp = s.slice(0, pos);
    const data = [];
    for (const ch of s.slice(pos + 1)) {
      const v = CHARSET.indexOf(ch);
      if (v === -1) throw new Error(`"${ch}" is not a bech32 character`);
      data.push(v);
    }
    const chk = polymod(hrpExpand(hrp).concat(data));
    let spec = null;
    if (chk === BECH32_CONST) spec = 'bech32';
    else if (chk === BECH32M_CONST) spec = 'bech32m';
    else throw new Error('bech32 checksum is invalid');
    return { hrp, data: data.slice(0, -6), spec };
  }
  function convertBits(data, from, to, pad) {
    let acc = 0, bits = 0;
    const out = [];
    const maxv = (1 << to) - 1;
    for (const value of data) {
      if (value < 0 || value >> from !== 0) throw new Error('invalid value for base conversion');
      acc = (acc << from) | value;
      bits += from;
      while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
    else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('invalid padding in base conversion');
    return out;
  }
  function encodeSegwit(hrp, version, program) {
    if (version < 0 || version > 16) throw new Error('witness version must be 0–16');
    if (version === 0 && program.length !== 20 && program.length !== 32)
      throw new Error('v0 witness program must be 20 or 32 bytes');
    if (program.length < 2 || program.length > 40) throw new Error('witness program must be 2–40 bytes');
    const data = [version].concat(convertBits(Array.from(program), 8, 5, true));
    return bech32Encode(hrp, data, version === 0 ? BECH32_CONST : BECH32M_CONST);
  }
  function decodeSegwit(addr) {
    const { hrp, data, spec } = bech32Decode(addr);
    if (!data.length) throw new Error('empty witness program');
    const version = data[0];
    if (version > 16) throw new Error('witness version must be 0–16');
    const program = new Uint8Array(convertBits(data.slice(1), 5, 8, false));
    if (program.length < 2 || program.length > 40) throw new Error('witness program must be 2–40 bytes');
    if (version === 0) {
      if (program.length !== 20 && program.length !== 32) throw new Error('v0 witness program must be 20 or 32 bytes');
      if (spec !== 'bech32') throw new Error('v0 addresses must use bech32, not bech32m');
    } else if (spec !== 'bech32m') {
      throw new Error('v1+ addresses must use bech32m, not bech32');
    }
    return { hrp, version, program, spec };
  }

  /* ------------------------------------------------------------ formatting */

  const SAT = 100000000n;
  function satsToBtc(sats) {
    const neg = BigInt(sats) < 0n;
    const v = neg ? -BigInt(sats) : BigInt(sats);
    const whole = v / SAT, frac = (v % SAT).toString().padStart(8, '0');
    return (neg ? '-' : '') + whole.toString() + '.' + frac;
  }
  function btcToSats(btc) {
    const s = String(btc).trim();
    if (!s) return 0n;
    if (!/^-?\d*\.?\d*$/.test(s)) throw new Error('not a valid BTC amount');
    const neg = s.startsWith('-');
    const [w, f = ''] = s.replace('-', '').split('.');
    /* reject only lossy input: excess decimals are fine when they are all zeros */
    if (f.length > 8 && f.slice(8).replace(/0/g, '') !== '')
      throw new Error('BTC amounts have at most 8 decimal places (1 sat = 0.00000001)');
    const sats = BigInt(w || '0') * SAT + BigInt((f + '00000000').slice(0, 8) || '0');
    return neg ? -sats : sats;
  }
  const groupNum = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');

  global.ENC = {
    bytesToHex, hexToBytes, isHex, reverse,
    utf8ToBytes, bytesToUtf8, asciiToBytes, bytesToAscii,
    bytesToBase64, base64ToBytes,
    varIntSize, encodeVarInt, Writer, Reader,
    base58Encode, base58Decode, base58checkEncode, base58checkDecode,
    bech32Encode, bech32Decode, convertBits, encodeSegwit, decodeSegwit,
    satsToBtc, btcToSats, groupNum
  };
})(window);
