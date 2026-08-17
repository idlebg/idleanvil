/* ============================================================================
   script.js — opcodes, ASM <-> hex, script templates, address <-> scriptPubKey
   Exposes: window.SCRIPT, window.NETWORKS
   ========================================================================== */
(function (global) {
  'use strict';
  const { bytesToHex, hexToBytes, encodeVarInt, Writer, Reader,
          base58checkEncode, base58checkDecode, encodeSegwit, decodeSegwit,
          utf8ToBytes } = ENC;

  /* ------------------------------------------------------------- networks */

  const NETWORKS = {
    mainnet:  { id: 'mainnet',  label: 'Mainnet',   short: 'BTC',  p2pkh: 0x00, p2sh: 0x05, hrp: 'bc',   wif: 0x80, bip32: 'xpub', color: 'amber',  coin: 'BTC'  },
    testnet3: { id: 'testnet3', label: 'Testnet3',  short: 'TEST', p2pkh: 0x6f, p2sh: 0xc4, hrp: 'tb',   wif: 0xef, bip32: 'tpub', color: 'green',  coin: 'tBTC' },
    testnet4: { id: 'testnet4', label: 'Testnet4',  short: 'TST4', p2pkh: 0x6f, p2sh: 0xc4, hrp: 'tb',   wif: 0xef, bip32: 'tpub', color: 'green',  coin: 'tBTC' },
    signet:   { id: 'signet',   label: 'Signet',    short: 'SIG',  p2pkh: 0x6f, p2sh: 0xc4, hrp: 'tb',   wif: 0xef, bip32: 'tpub', color: 'violet', coin: 'sBTC' },
    regtest:  { id: 'regtest',  label: 'Regtest',   short: 'REG',  p2pkh: 0x6f, p2sh: 0xc4, hrp: 'bcrt', wif: 0xef, bip32: 'tpub', color: 'blue',   coin: 'rBTC' }
  };

  /* -------------------------------------------------------------- opcodes */

  const OPS = {
    OP_0: 0x00, OP_FALSE: 0x00,
    OP_PUSHDATA1: 0x4c, OP_PUSHDATA2: 0x4d, OP_PUSHDATA4: 0x4e, OP_1NEGATE: 0x4f,
    OP_RESERVED: 0x50,
    OP_1: 0x51, OP_TRUE: 0x51, OP_2: 0x52, OP_3: 0x53, OP_4: 0x54, OP_5: 0x55, OP_6: 0x56,
    OP_7: 0x57, OP_8: 0x58, OP_9: 0x59, OP_10: 0x5a, OP_11: 0x5b, OP_12: 0x5c, OP_13: 0x5d,
    OP_14: 0x5e, OP_15: 0x5f, OP_16: 0x60,
    OP_NOP: 0x61, OP_VER: 0x62, OP_IF: 0x63, OP_NOTIF: 0x64, OP_VERIF: 0x65, OP_VERNOTIF: 0x66,
    OP_ELSE: 0x67, OP_ENDIF: 0x68, OP_VERIFY: 0x69, OP_RETURN: 0x6a,
    OP_TOALTSTACK: 0x6b, OP_FROMALTSTACK: 0x6c, OP_2DROP: 0x6d, OP_2DUP: 0x6e, OP_3DUP: 0x6f,
    OP_2OVER: 0x70, OP_2ROT: 0x71, OP_2SWAP: 0x72, OP_IFDUP: 0x73, OP_DEPTH: 0x74, OP_DROP: 0x75,
    OP_DUP: 0x76, OP_NIP: 0x77, OP_OVER: 0x78, OP_PICK: 0x79, OP_ROLL: 0x7a, OP_ROT: 0x7b,
    OP_SWAP: 0x7c, OP_TUCK: 0x7d,
    OP_CAT: 0x7e, OP_SUBSTR: 0x7f, OP_LEFT: 0x80, OP_RIGHT: 0x81, OP_SIZE: 0x82,
    OP_INVERT: 0x83, OP_AND: 0x84, OP_OR: 0x85, OP_XOR: 0x86,
    OP_EQUAL: 0x87, OP_EQUALVERIFY: 0x88, OP_RESERVED1: 0x89, OP_RESERVED2: 0x8a,
    OP_1ADD: 0x8b, OP_1SUB: 0x8c, OP_2MUL: 0x8d, OP_2DIV: 0x8e, OP_NEGATE: 0x8f, OP_ABS: 0x90,
    OP_NOT: 0x91, OP_0NOTEQUAL: 0x92, OP_ADD: 0x93, OP_SUB: 0x94, OP_MUL: 0x95, OP_DIV: 0x96,
    OP_MOD: 0x97, OP_LSHIFT: 0x98, OP_RSHIFT: 0x99, OP_BOOLAND: 0x9a, OP_BOOLOR: 0x9b,
    OP_NUMEQUAL: 0x9c, OP_NUMEQUALVERIFY: 0x9d, OP_NUMNOTEQUAL: 0x9e,
    OP_LESSTHAN: 0x9f, OP_GREATERTHAN: 0xa0, OP_LESSTHANOREQUAL: 0xa1, OP_GREATERTHANOREQUAL: 0xa2,
    OP_MIN: 0xa3, OP_MAX: 0xa4, OP_WITHIN: 0xa5,
    OP_RIPEMD160: 0xa6, OP_SHA1: 0xa7, OP_SHA256: 0xa8, OP_HASH160: 0xa9, OP_HASH256: 0xaa,
    OP_CODESEPARATOR: 0xab, OP_CHECKSIG: 0xac, OP_CHECKSIGVERIFY: 0xad,
    OP_CHECKMULTISIG: 0xae, OP_CHECKMULTISIGVERIFY: 0xaf,
    OP_NOP1: 0xb0, OP_CHECKLOCKTIMEVERIFY: 0xb1, OP_CLTV: 0xb1,
    OP_CHECKSEQUENCEVERIFY: 0xb2, OP_CSV: 0xb2,
    OP_NOP4: 0xb3, OP_NOP5: 0xb4, OP_NOP6: 0xb5, OP_NOP7: 0xb6, OP_NOP8: 0xb7, OP_NOP9: 0xb8, OP_NOP10: 0xb9,
    OP_CHECKSIGADD: 0xba,
    OP_INVALIDOPCODE: 0xff
  };

  /* canonical name per byte (aliases resolve to the primary spelling) */
  const OP_NAME = (() => {
    const m = {};
    const primary = ['OP_0','OP_1','OP_PUSHDATA1','OP_PUSHDATA2','OP_PUSHDATA4','OP_1NEGATE',
                     'OP_CHECKLOCKTIMEVERIFY','OP_CHECKSEQUENCEVERIFY'];
    for (const [k, v] of Object.entries(OPS)) {
      if (m[v] === undefined || primary.includes(k)) m[v] = k;
    }
    for (let i = 1; i <= 75; i++) if (m[i] === undefined) m[i] = `PUSH_${i}`;
    return m;
  })();

  const OP_CATEGORIES = {
    push:     ['OP_0','OP_1NEGATE','OP_1','OP_2','OP_3','OP_4','OP_5','OP_6','OP_7','OP_8','OP_9','OP_10','OP_11','OP_12','OP_13','OP_14','OP_15','OP_16','OP_PUSHDATA1','OP_PUSHDATA2','OP_PUSHDATA4'],
    stack:    ['OP_TOALTSTACK','OP_FROMALTSTACK','OP_2DROP','OP_2DUP','OP_3DUP','OP_2OVER','OP_2ROT','OP_2SWAP','OP_IFDUP','OP_DEPTH','OP_DROP','OP_DUP','OP_NIP','OP_OVER','OP_PICK','OP_ROLL','OP_ROT','OP_SWAP','OP_TUCK','OP_SIZE'],
    control:  ['OP_NOP','OP_IF','OP_NOTIF','OP_ELSE','OP_ENDIF','OP_VERIFY','OP_RETURN','OP_EQUAL','OP_EQUALVERIFY'],
    arith:    ['OP_1ADD','OP_1SUB','OP_NEGATE','OP_ABS','OP_NOT','OP_0NOTEQUAL','OP_ADD','OP_SUB','OP_BOOLAND','OP_BOOLOR','OP_NUMEQUAL','OP_NUMEQUALVERIFY','OP_NUMNOTEQUAL','OP_LESSTHAN','OP_GREATERTHAN','OP_LESSTHANOREQUAL','OP_GREATERTHANOREQUAL','OP_MIN','OP_MAX','OP_WITHIN'],
    crypto:   ['OP_RIPEMD160','OP_SHA1','OP_SHA256','OP_HASH160','OP_HASH256','OP_CODESEPARATOR','OP_CHECKSIG','OP_CHECKSIGVERIFY','OP_CHECKMULTISIG','OP_CHECKMULTISIGVERIFY','OP_CHECKSIGADD'],
    locktime: ['OP_CHECKLOCKTIMEVERIFY','OP_CHECKSEQUENCEVERIFY','OP_NOP1','OP_NOP4','OP_NOP5','OP_NOP6','OP_NOP7','OP_NOP8','OP_NOP9','OP_NOP10'],
    disabled: ['OP_CAT','OP_SUBSTR','OP_LEFT','OP_RIGHT','OP_INVERT','OP_AND','OP_OR','OP_XOR','OP_2MUL','OP_2DIV','OP_MUL','OP_DIV','OP_MOD','OP_LSHIFT','OP_RSHIFT'],
    reserved: ['OP_RESERVED','OP_VER','OP_VERIF','OP_VERNOTIF','OP_RESERVED1','OP_RESERVED2','OP_INVALIDOPCODE']
  };
  const OP_CAT_OF = (() => {
    const m = {};
    for (const [cat, list] of Object.entries(OP_CATEGORIES)) for (const n of list) m[n] = cat;
    return m;
  })();

  const OP_DOC = {
    OP_DUP: 'Duplicates the top stack item.',
    OP_HASH160: 'RIPEMD160(SHA256(x)) of the top stack item.',
    OP_HASH256: 'SHA256(SHA256(x)) of the top stack item.',
    OP_EQUALVERIFY: 'OP_EQUAL then OP_VERIFY — fails the script if unequal.',
    OP_CHECKSIG: 'Pops pubkey and signature; pushes true if the signature is valid for this transaction.',
    OP_CHECKSIGVERIFY: 'OP_CHECKSIG then OP_VERIFY — fails the script instead of pushing false.',
    OP_CHECKMULTISIG: 'Pops n pubkeys and m signatures; consumes one extra item (the off-by-one bug).',
    OP_CHECKSIGADD: 'Tapscript only: pops pubkey, num, signature; pushes num+1 on a valid signature.',
    OP_RETURN: 'Marks the output provably unspendable; the standard data-carrier prefix.',
    OP_CHECKLOCKTIMEVERIFY: 'Fails unless nLockTime is at least the top stack value (BIP65).',
    OP_CHECKSEQUENCEVERIFY: 'Fails unless the input nSequence encodes at least the top stack value (BIP112).',
    OP_CODESEPARATOR: 'Resets the start of scriptCode for subsequent signature checks.',
    OP_IF: 'Executes the following branch if the top stack item is true.',
    OP_TOALTSTACK: 'Moves the top item to the alt stack.'
  };

  /* ------------------------------------------------------- push encoding */

  /**
   * Encode a data push.
   * opts: { pushdata: 'auto'|'direct'|'1'|'2'|'4', nonMinimal: bool }
   */
  function pushData(data, opts = {}) {
    const w = new Writer();
    const n = data.length;
    const forced = opts.pushdata && opts.pushdata !== 'auto' ? opts.pushdata : null;

    if (!forced && !opts.nonMinimal) {
      if (n === 0) return new Uint8Array([0x00]);
      if (n === 1 && data[0] >= 1 && data[0] <= 16) return new Uint8Array([0x50 + data[0]]);
      if (n === 1 && data[0] === 0x81) return new Uint8Array([0x4f]);
    }
    const kind = forced || (n < 0x4c ? 'direct' : n <= 0xff ? '1' : n <= 0xffff ? '2' : '4');
    if (kind === 'direct') {
      if (n > 0x4b) throw new Error(`${n} bytes cannot use a direct push (max 75) — choose OP_PUSHDATA1/2/4`);
      w.u8(n);
    } else if (kind === '1') { w.u8(0x4c); w.u8(n); }
    else if (kind === '2') { w.u8(0x4d); w.u16(n); }
    else { w.u8(0x4e); w.u32(n); }
    return w.push(data).bytes();
  }

  /** Minimal-encode a script number (CScriptNum). */
  function scriptNum(n) {
    n = BigInt(n);
    if (n === 0n) return new Uint8Array(0);
    const neg = n < 0n;
    let v = neg ? -n : n;
    const out = [];
    while (v > 0n) { out.push(Number(v & 0xffn)); v >>= 8n; }
    if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0x00);
    else if (neg) out[out.length - 1] |= 0x80;
    return new Uint8Array(out);
  }
  function readScriptNum(b) {
    if (!b.length) return 0n;
    let v = 0n;
    for (let i = 0; i < b.length; i++) v |= BigInt(b[i]) << BigInt(8 * i);
    if (b[b.length - 1] & 0x80) v = -(v & ~(0x80n << BigInt(8 * (b.length - 1))));
    return v;
  }

  /* ------------------------------------------------------- parse / decompile */

  /** Split a script into [{op, name, data, offset, size, minimal}] */
  function parseScript(script) {
    const ops = [];
    let i = 0;
    while (i < script.length) {
      const start = i;
      const op = script[i++];
      let data = null, name = OP_NAME[op] || `OP_UNKNOWN_${op.toString(16)}`;
      let minimal = true;
      try {
        if (op > 0 && op < 0x4c) {
          data = script.slice(i, i + op); i += op;
          if (data.length < op) return finish(ops, script, start, 'truncated push');
        } else if (op === 0x4c) {
          const n = script[i++]; data = script.slice(i, i + n); i += n;
          if (n < 0x4c) minimal = false;
        } else if (op === 0x4d) {
          const n = script[i] | (script[i + 1] << 8); i += 2;
          data = script.slice(i, i + n); i += n;
          if (n <= 0xff) minimal = false;
        } else if (op === 0x4e) {
          const n = new DataView(script.buffer, script.byteOffset + i, 4).getUint32(0, true); i += 4;
          data = script.slice(i, i + n); i += n;
          if (n <= 0xffff) minimal = false;
        }
      } catch (e) {
        return finish(ops, script, start, e.message);
      }
      if (data && data.length === 1 && ((data[0] >= 1 && data[0] <= 16) || data[0] === 0x81) && op < 0x4c) minimal = false;
      ops.push({ op, name, data, offset: start, size: i - start, minimal, isPush: op <= 0x4e });
      if (i > script.length) return finish(ops, script, start, 'push runs past the end of the script');
    }
    return { ops, error: null };
  }
  function finish(ops, script, at, msg) {
    return { ops, error: `${msg} at byte ${at}`, truncatedAt: at };
  }

  /** Script bytes -> ASM text. */
  function toAsm(script, opts = {}) {
    if (!script || !script.length) return '';
    const { ops, error } = parseScript(script);
    const parts = ops.map(o => {
      if (o.data !== null && o.data !== undefined) {
        if (o.data.length === 0) return 'OP_0';
        const hex = bytesToHex(o.data);
        const prefix = (o.op === 0x4c) ? 'OP_PUSHDATA1 ' : (o.op === 0x4d) ? 'OP_PUSHDATA2 ' : (o.op === 0x4e) ? 'OP_PUSHDATA4 ' : '';
        return prefix + (opts.brackets ? `<${hex}>` : hex);
      }
      return o.name;
    });
    if (error) parts.push(`[${error}]`);
    return parts.join(' ');
  }

  /**
   * ASM text -> script bytes.
   * Accepts: OP_NAMES, <hex>, bare hex (pushed as data), 'string', decimal numbers,
   * and 0x-prefixed raw bytes (emitted verbatim, no push opcode).
   */
  function fromAsm(asm, opts = {}) {
    const w = new Writer();
    const tokens = String(asm).trim().split(/\s+/).filter(Boolean);
    let pendingPush = null;
    for (let t of tokens) {
      if (!t) continue;
      const up = t.toUpperCase();

      if (up === 'OP_PUSHDATA1' || up === 'OP_PUSHDATA2' || up === 'OP_PUSHDATA4') {
        pendingPush = up.slice(-1); continue;
      }
      if (OPS[up] !== undefined) { w.u8(OPS[up]); pendingPush = null; continue; }
      if (/^-?\d+$/.test(t) && !/^0\d/.test(t)) {
        const n = BigInt(t);
        if (n >= 1n && n <= 16n && !pendingPush) { w.u8(0x50 + Number(n)); continue; }
        if (n === 0n && !pendingPush) { w.u8(0x00); continue; }
        if (n === -1n && !pendingPush) { w.u8(0x4f); continue; }
        w.push(pushData(scriptNum(n), { pushdata: pendingPush || 'auto' }));
        pendingPush = null; continue;
      }
      if (t.startsWith('<') && t.endsWith('>')) t = t.slice(1, -1);
      if (/^'(.*)'$/.test(t) || /^"(.*)"$/.test(t)) {
        w.push(pushData(utf8ToBytes(t.slice(1, -1)), { pushdata: pendingPush || 'auto' }));
        pendingPush = null; continue;
      }
      if (/^0x[0-9a-fA-F]+$/.test(t)) {         // raw bytes, no push wrapper
        w.push(hexToBytes(t.slice(2))); pendingPush = null; continue;
      }
      if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) {
        w.push(pushData(hexToBytes(t), { pushdata: pendingPush || 'auto', nonMinimal: opts.nonMinimal }));
        pendingPush = null; continue;
      }
      throw new Error(`cannot parse script token "${t}"`);
    }
    return w.bytes();
  }

  /* ------------------------------------------------------- type detection */

  const T = {
    P2PK: 'P2PK', P2PKH: 'P2PKH', P2SH: 'P2SH', P2WPKH: 'P2WPKH', P2WSH: 'P2WSH',
    P2TR: 'P2TR', MULTISIG: 'MULTISIG', OP_RETURN: 'OP_RETURN',
    WITNESS_UNKNOWN: 'WITNESS_UNKNOWN', NONSTANDARD: 'NONSTANDARD', EMPTY: 'EMPTY'
  };

  function classify(script) {
    if (!script || !script.length) return { type: T.EMPTY, standard: false };
    const s = script, n = s.length;

    if (n === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac)
      return { type: T.P2PKH, standard: true, hash: s.slice(3, 23) };
    if (n === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87)
      return { type: T.P2SH, standard: true, hash: s.slice(2, 22) };
    if (n === 22 && s[0] === 0x00 && s[1] === 0x14)
      return { type: T.P2WPKH, standard: true, version: 0, program: s.slice(2) };
    if (n === 34 && s[0] === 0x00 && s[1] === 0x20)
      return { type: T.P2WSH, standard: true, version: 0, program: s.slice(2) };
    if (n === 34 && s[0] === 0x51 && s[1] === 0x20)
      return { type: T.P2TR, standard: true, version: 1, program: s.slice(2) };
    if ((n === 35 && s[0] === 0x21 && s[34] === 0xac) || (n === 67 && s[0] === 0x41 && s[66] === 0xac))
      return { type: T.P2PK, standard: true, pubkey: s.slice(1, n - 1) };
    if (s[0] === 0x6a) {
      const { ops, error } = parseScript(s.slice(1));
      const payloads = ops.filter(o => o.data).map(o => o.data);
      /* Core's default datacarrier policy: whole script ≤ 83 bytes (80 payload
         + OP_RETURN + push opcodes), push-only after the OP_RETURN. */
      const dataLen = payloads.reduce((a, p) => a + p.length, 0);
      return { type: T.OP_RETURN, standard: !error && n <= 83 && ops.every(o => o.isPush), payloads, dataLen, scriptLen: n };
    }
    // bare multisig: OP_m <pk>... OP_n OP_CHECKMULTISIG
    if (s[n - 1] === 0xae && s[0] >= 0x51 && s[0] <= 0x60) {
      const { ops, error } = parseScript(s);
      if (!error && ops.length >= 4) {
        const m = ops[0].op - 0x50;
        const nOp = ops[ops.length - 2];
        if (nOp && nOp.op >= 0x51 && nOp.op <= 0x60) {
          const total = nOp.op - 0x50;
          const keys = ops.slice(1, -2).filter(o => o.data && (o.data.length === 33 || o.data.length === 65)).map(o => o.data);
          if (keys.length === total && total >= m && m >= 1)
            return { type: T.MULTISIG, standard: total <= 3, m, n: total, pubkeys: keys };
        }
      }
    }
    // any other witness program
    if (n >= 4 && n <= 42) {
      const v = s[0];
      if (v === 0x00 || (v >= 0x51 && v <= 0x60)) {
        const ver = v === 0 ? 0 : v - 0x50;
        if (s[1] === n - 2) return { type: T.WITNESS_UNKNOWN, standard: false, version: ver, program: s.slice(2) };
      }
    }
    return { type: T.NONSTANDARD, standard: false };
  }

  /* -------------------------------------------------- script constructors */

  const p2pkh   = (hash160) => new Uint8Array([0x76, 0xa9, 0x14, ...hash160, 0x88, 0xac]);
  const p2sh    = (hash160) => new Uint8Array([0xa9, 0x14, ...hash160, 0x87]);
  const p2wpkh  = (hash160) => new Uint8Array([0x00, 0x14, ...hash160]);
  const p2wsh   = (sha256)  => new Uint8Array([0x00, 0x20, ...sha256]);
  const p2tr    = (xonly)   => new Uint8Array([0x51, 0x20, ...xonly]);
  const p2pk    = (pubkey)  => BC.cat(pushData(pubkey), new Uint8Array([0xac]));
  const witnessProgram = (version, program) =>
    BC.cat(new Uint8Array([version === 0 ? 0 : 0x50 + version]), pushData(program));

  function multisig(m, pubkeys) {
    if (m < 1 || m > 16) throw new Error('m must be 1–16');
    if (pubkeys.length < m || pubkeys.length > 16) throw new Error('n must be between m and 16');
    const w = new Writer();
    w.u8(0x50 + m);
    for (const pk of pubkeys) w.push(pushData(pk));
    w.u8(0x50 + pubkeys.length);
    w.u8(0xae);
    return w.bytes();
  }

  function opReturn(payloads, opts = {}) {
    const w = new Writer();
    if (opts.prefixOpcode !== undefined && opts.prefixOpcode !== null && opts.prefixOpcode !== '')
      w.u8(Number(opts.prefixOpcode));
    else w.u8(0x6a);
    for (const p of payloads) {
      if (!p.length && !opts.keepEmpty) continue;
      w.push(pushData(p, opts));
    }
    return w.bytes();
  }

  /* ------------------------------------------------- addresses <-> scripts */

  function scriptToAddress(script, netId) {
    const net = NETWORKS[netId] || NETWORKS.mainnet;
    const c = classify(script);
    try {
      switch (c.type) {
        case T.P2PKH: return base58checkEncode(BC.cat(new Uint8Array([net.p2pkh]), c.hash));
        case T.P2SH:  return base58checkEncode(BC.cat(new Uint8Array([net.p2sh]), c.hash));
        case T.P2WPKH:
        case T.P2WSH: return encodeSegwit(net.hrp, 0, c.program);
        case T.P2TR:  return encodeSegwit(net.hrp, 1, c.program);
        case T.WITNESS_UNKNOWN: return encodeSegwit(net.hrp, c.version, c.program);
        default: return null;
      }
    } catch (e) { return null; }
  }

  function addressToScript(addr, netId) {
    addr = String(addr).trim();
    if (!addr) throw new Error('address is empty');
    const net = NETWORKS[netId] || NETWORKS.mainnet;

    if (/^(bc|tb|bcrt)1/i.test(addr)) {
      const d = decodeSegwit(addr);
      if (d.hrp !== net.hrp)
        throw new Error(`address is for "${d.hrp}" but the selected network expects "${net.hrp}"`);
      const script = witnessProgram(d.version, d.program);
      return { script, type: classify(script).type, witnessVersion: d.version };
    }
    const payload = base58checkDecode(addr);
    if (payload.length !== 21) throw new Error(`base58 payload is ${payload.length} bytes, expected 21`);
    const ver = payload[0], hash = payload.slice(1);
    if (ver === net.p2pkh) return { script: p2pkh(hash), type: T.P2PKH };
    if (ver === net.p2sh)  return { script: p2sh(hash), type: T.P2SH };
    const known = Object.values(NETWORKS).find(n => n.p2pkh === ver || n.p2sh === ver);
    throw new Error(`version byte 0x${ver.toString(16).padStart(2, '0')} does not belong to ${net.label}` +
      (known ? ` (it looks like ${known.label})` : ''));
  }

  function validateAddress(addr, netId) {
    try { const r = addressToScript(addr, netId); return { ok: true, ...r }; }
    catch (e) { return { ok: false, error: e.message }; }
  }

  /* ------------------------------------------------------------ templates */

  const TEMPLATES = [
    { id: 'p2pk',        label: 'P2PK — pay to public key',            fields: [{ k: 'pubkey', l: 'Public key (33 or 65 bytes hex)', ph: '02...' }] },
    { id: 'p2pkh',       label: 'P2PKH — pay to public key hash',      fields: [{ k: 'pubkey', l: 'Public key hex (or 20-byte hash160)', ph: '02...' }] },
    { id: 'multisig',    label: 'Bare multisig — m-of-n',              fields: [{ k: 'm', l: 'm (required signatures)', ph: '2', num: true }, { k: 'pubkeys', l: 'Public keys, one per line', area: true, ph: '02...\n03...' }] },
    { id: 'p2sh',        label: 'P2SH — wrap a redeem script',         fields: [{ k: 'script', l: 'Redeem script (hex or ASM)', area: true }] },
    { id: 'p2wsh',       label: 'P2WSH — wrap a witness script',       fields: [{ k: 'script', l: 'Witness script (hex or ASM)', area: true }] },
    { id: 'p2wpkh',      label: 'P2WPKH — native segwit v0 key',       fields: [{ k: 'pubkey', l: 'Public key hex (compressed)', ph: '02...' }] },
    { id: 'p2sh-p2wpkh', label: 'P2SH-P2WPKH — nested segwit key',     fields: [{ k: 'pubkey', l: 'Public key hex (compressed)', ph: '02...' }] },
    { id: 'p2sh-p2wsh',  label: 'P2SH-P2WSH — nested witness script',  fields: [{ k: 'script', l: 'Witness script (hex or ASM)', area: true }] },
    { id: 'p2tr-key',    label: 'P2TR — taproot key path',             fields: [{ k: 'internal', l: 'Internal key (32-byte x-only)', ph: '...' }, { k: 'merkle', l: 'Merkle root (optional, 32 bytes)', ph: 'leave empty for key-path only' }] },
    { id: 'p2tr-raw',    label: 'P2TR — raw output key',               fields: [{ k: 'outkey', l: 'Output key (32-byte x-only)', ph: '...' }] },
    { id: 'cltv',        label: 'CLTV — timelock then key',            fields: [{ k: 'locktime', l: 'Locktime (height or unix time)', ph: '800000', num: true }, { k: 'pubkey', l: 'Public key hex', ph: '02...' }] },
    { id: 'csv',         label: 'CSV — relative timelock then key',    fields: [{ k: 'seq', l: 'Sequence value', ph: '144', num: true }, { k: 'pubkey', l: 'Public key hex', ph: '02...' }] },
    { id: 'hashlock',    label: 'Hashlock — HASH160 preimage',         fields: [{ k: 'hash', l: 'HASH160 digest (20 bytes)', ph: '...' }] },
    { id: 'htlc',        label: 'HTLC — hashlock or timeout',          fields: [{ k: 'hash', l: 'HASH160 of the preimage', ph: '...' }, { k: 'recv', l: 'Receiver pubkey', ph: '02...' }, { k: 'locktime', l: 'Refund locktime', ph: '800000', num: true }, { k: 'refund', l: 'Refund pubkey', ph: '03...' }] },
    { id: 'checksig',    label: 'Bare OP_CHECKSIG',                    fields: [{ k: 'pubkey', l: 'Public key hex', ph: '02...' }] },
    { id: 'checksigverify', label: 'Bare OP_CHECKSIGVERIFY',           fields: [{ k: 'pubkey', l: 'Public key hex', ph: '02...' }] },
    { id: 'anyonecanspend', label: 'Anyone-can-spend (OP_TRUE)',       fields: [] },
    { id: 'unspendable', label: 'Provably unspendable (OP_RETURN)',    fields: [] },

    /* --- taproot leaf scripts --- */
    { id: 'tapscript-key',   label: 'Tapscript — single key CHECKSIG',      fields: [{ k: 'pubkey', l: 'x-only public key (32 bytes)', ph: '…' }] },
    { id: 'tapscript-multi', label: 'Tapscript — k-of-n CHECKSIGADD',       fields: [{ k: 'k', l: 'k (required signatures)', ph: '2', num: true }, { k: 'pubkeys', l: 'x-only public keys, one per line', area: true }] },
    { id: 'inscription',     label: 'Tapscript — data envelope (ord style)', fields: [{ k: 'proto', l: 'Protocol tag', ph: 'ord' }, { k: 'mime', l: 'Content type', ph: 'text/plain;charset=utf-8' }, { k: 'body', l: 'Payload (text)', area: true }, { k: 'pubkey', l: 'x-only key that unlocks it', ph: '…' }] },

    /* --- timelocks and vaults --- */
    { id: 'vault-csv',    label: 'Vault — hot key after CSV, cold key now',  fields: [{ k: 'delay', l: 'Relative delay (blocks)', ph: '144', num: true }, { k: 'hot', l: 'Hot (delayed) pubkey', ph: '02…' }, { k: 'cold', l: 'Cold (immediate) pubkey', ph: '03…' }] },
    { id: 'degrading',    label: 'Degrading multisig — 2-of-2, then 1-of-2', fields: [{ k: 'a', l: 'Pubkey A', ph: '02…' }, { k: 'b', l: 'Pubkey B', ph: '03…' }, { k: 'locktime', l: 'CLTV after which A alone suffices', ph: '800000', num: true }] },
    { id: 'cltv-multisig', label: 'Timelocked multisig — CLTV then m-of-n',  fields: [{ k: 'locktime', l: 'Locktime', ph: '800000', num: true }, { k: 'm', l: 'm', ph: '2', num: true }, { k: 'pubkeys', l: 'Public keys, one per line', area: true }] },

    /* --- hashlocks --- */
    { id: 'hashlock256',  label: 'Hashlock — SHA256 preimage',               fields: [{ k: 'hash', l: 'SHA256 digest (32 bytes)', ph: '…' }] },
    { id: 'hashlock-sig', label: 'Hashlock + signature',                     fields: [{ k: 'hash', l: 'HASH160 of the preimage', ph: '…' }, { k: 'pubkey', l: 'Public key', ph: '02…' }] },

    /* --- data-carrying and exotic --- */
    { id: 'data-drop',    label: 'Data + key — <data> OP_DROP <pk> CHECKSIG', fields: [{ k: 'data', l: 'Data to embed (hex or text)', area: true }, { k: 'pubkey', l: 'Public key', ph: '02…' }] },
    { id: 'p2a',          label: 'P2A — pay to anchor (ephemeral anchor)',    fields: [] },
    { id: 'witness-any',  label: 'Arbitrary witness program (v0–v16)',        fields: [{ k: 'version', l: 'Witness version (0–16)', ph: '1', num: true }, { k: 'program', l: 'Program (2–40 bytes hex)', ph: '…' }] },
    { id: 'raw-passthru', label: 'Raw bytes — exactly what you type',         fields: [{ k: 'hex', l: 'Script hex', area: true }] }
  ];

  /** Build a script from a template id + field values. Returns {script, note, sub}. */
  function buildTemplate(id, v) {
    const hexOrAsm = (s) => {
      s = String(s || '').trim();
      if (!s) throw new Error('script is empty');
      if (/^[0-9a-fA-F\s]+$/.test(s) && s.replace(/\s/g, '').length % 2 === 0) return hexToBytes(s);
      return fromAsm(s);
    };
    const key = (s, what = 'public key') => {
      const b = hexToBytes(String(s || '').trim());
      if (b.length !== 33 && b.length !== 65 && b.length !== 32)
        throw new Error(`${what} is ${b.length} bytes; expected 33 (compressed), 65 (uncompressed) or 32 (x-only)`);
      return b;
    };
    switch (id) {
      case 'p2pk': return { script: p2pk(key(v.pubkey)) };
      case 'p2pkh': {
        const b = hexToBytes(String(v.pubkey || '').trim());
        const h = b.length === 20 ? b : BC.hash160(key(v.pubkey));
        return { script: p2pkh(h), note: b.length === 20 ? 'used the value directly as a hash160' : 'hash160 of the public key' };
      }
      case 'multisig': {
        const keys = String(v.pubkeys || '').split(/[\s,]+/).filter(Boolean).map(k => key(k));
        return { script: multisig(Number(v.m || 1), keys) };
      }
      case 'p2sh': {
        const redeem = hexOrAsm(v.script);
        return { script: p2sh(BC.hash160(redeem)), sub: { redeemScript: redeem } };
      }
      case 'p2wsh': {
        const wit = hexOrAsm(v.script);
        return { script: p2wsh(BC.sha256(wit)), sub: { witnessScript: wit } };
      }
      case 'p2wpkh': return { script: p2wpkh(BC.hash160(key(v.pubkey))) };
      case 'p2sh-p2wpkh': {
        const redeem = p2wpkh(BC.hash160(key(v.pubkey)));
        return { script: p2sh(BC.hash160(redeem)), sub: { redeemScript: redeem } };
      }
      case 'p2sh-p2wsh': {
        const wit = hexOrAsm(v.script);
        const redeem = p2wsh(BC.sha256(wit));
        return { script: p2sh(BC.hash160(redeem)), sub: { redeemScript: redeem, witnessScript: wit } };
      }
      case 'p2tr-key': {
        const internal = key(v.internal, 'internal key');
        if (internal.length !== 32) throw new Error('the internal key must be 32 bytes (x-only)');
        const mr = String(v.merkle || '').trim();
        const t = BC.taprootTweak(internal, mr ? hexToBytes(mr) : null);
        return { script: p2tr(t.outputKey), note: `output key ${bytesToHex(t.outputKey)} (parity ${t.parity})`, sub: { taproot: t } };
      }
      case 'p2tr-raw': {
        const k = hexToBytes(String(v.outkey || '').trim());
        if (k.length !== 32) throw new Error('the output key must be 32 bytes (x-only)');
        return { script: p2tr(k) };
      }
      case 'cltv': {
        const w = new Writer();
        w.push(pushData(scriptNum(BigInt(v.locktime || 0))));
        w.u8(0xb1).u8(0x75);                       // CLTV DROP
        w.push(pushData(key(v.pubkey))).u8(0xac);  // <pk> CHECKSIG
        return { script: w.bytes() };
      }
      case 'csv': {
        const w = new Writer();
        w.push(pushData(scriptNum(BigInt(v.seq || 0))));
        w.u8(0xb2).u8(0x75);
        w.push(pushData(key(v.pubkey))).u8(0xac);
        return { script: w.bytes() };
      }
      case 'hashlock': {
        const h = hexToBytes(String(v.hash || '').trim());
        if (h.length !== 20) throw new Error('HASH160 digest must be 20 bytes');
        return { script: BC.cat(new Uint8Array([0xa9]), pushData(h), new Uint8Array([0x87])) };
      }
      case 'htlc': {
        const w = new Writer();
        w.u8(0x63).u8(0xa9);                        // IF HASH160
        w.push(pushData(hexToBytes(v.hash))).u8(0x88); // <h> EQUALVERIFY
        w.push(pushData(key(v.recv)));
        w.u8(0x67);                                 // ELSE
        w.push(pushData(scriptNum(BigInt(v.locktime || 0))));
        w.u8(0xb1).u8(0x75);                        // CLTV DROP
        w.push(pushData(key(v.refund)));
        w.u8(0x68).u8(0xac);                        // ENDIF CHECKSIG
        return { script: w.bytes(), note: 'spend with <sig> <preimage> 1  or  <sig> 0' };
      }
      case 'checksig': return { script: BC.cat(pushData(key(v.pubkey)), new Uint8Array([0xac])) };
      case 'checksigverify': return { script: BC.cat(pushData(key(v.pubkey)), new Uint8Array([0xad])) };
      case 'anyonecanspend': return { script: new Uint8Array([0x51]), note: 'OP_TRUE — spendable by anyone; non-standard' };
      case 'unspendable': return { script: new Uint8Array([0x6a]), note: 'a bare OP_RETURN with no payload' };

      case 'tapscript-key': {
        const k = key(v.pubkey, 'x-only key');
        if (k.length !== 32) throw new Error('tapscript keys must be 32-byte x-only');
        return { script: BC.cat(pushData(k), new Uint8Array([0xac])), note: 'use as a tapleaf, not as a scriptPubKey' };
      }
      case 'tapscript-multi': {
        const keys = String(v.pubkeys || '').split(/[\s,]+/).filter(Boolean).map(x => key(x, 'x-only key'));
        if (!keys.length) throw new Error('at least one key is required');
        if (keys.some(x => x.length !== 32)) throw new Error('tapscript keys must be 32-byte x-only');
        const k = Number(v.k || 1);
        const w = new Writer();
        keys.forEach((pk, i) => {
          w.push(pushData(pk));
          w.u8(i === 0 ? 0xac : 0xba);          // CHECKSIG then CHECKSIGADD
        });
        w.push(pushData(scriptNum(BigInt(k))));
        w.u8(0x9c);                              // OP_NUMEQUAL
        return { script: w.bytes(), note: `${k}-of-${keys.length} tapscript — spend with one signature slot per key, empty for unused` };
      }
      case 'inscription': {
        const w = new Writer();
        w.push(pushData(key(v.pubkey, 'x-only key'))).u8(0xac);   // <pk> CHECKSIG
        w.u8(0x00).u8(0x63);                                      // OP_FALSE OP_IF
        w.push(pushData(utf8ToBytes(v.proto || 'ord')));
        w.push(pushData(new Uint8Array([1])));                    // field 1: content type
        w.push(pushData(utf8ToBytes(v.mime || 'text/plain;charset=utf-8')));
        w.u8(0x00);                                               // OP_0 — body separator
        const body = utf8ToBytes(v.body || '');
        for (let i = 0; i < body.length; i += 520) w.push(pushData(body.slice(i, i + 520)));
        w.u8(0x68);                                               // OP_ENDIF
        return { script: w.bytes(), note: 'an envelope tapleaf — the OP_FALSE OP_IF block never executes, so the data is inert' };
      }
      case 'vault-csv': {
        const w = new Writer();
        w.u8(0x63);                                               // OP_IF  (hot path)
        w.push(pushData(scriptNum(BigInt(v.delay || 0)))).u8(0xb2).u8(0x75);  // <n> CSV DROP
        w.push(pushData(key(v.hot, 'hot key')));
        w.u8(0x67);                                               // OP_ELSE (cold path)
        w.push(pushData(key(v.cold, 'cold key')));
        w.u8(0x68).u8(0xac);                                      // OP_ENDIF OP_CHECKSIG
        return { script: w.bytes(), note: 'spend hot with <sig> 1 after the delay, or cold with <sig> 0 immediately' };
      }
      case 'degrading': {
        const w = new Writer();
        w.u8(0x63);                                               // OP_IF — both keys
        w.u8(0x52);                                               // OP_2
        w.push(pushData(key(v.a, 'key A'))).push(pushData(key(v.b, 'key B')));
        w.u8(0x52).u8(0xae);                                      // OP_2 CHECKMULTISIG
        w.u8(0x67);                                               // OP_ELSE — A alone, later
        w.push(pushData(scriptNum(BigInt(v.locktime || 0)))).u8(0xb1).u8(0x75);
        w.push(pushData(key(v.a, 'key A'))).u8(0xac);
        w.u8(0x68);                                               // OP_ENDIF
        return { script: w.bytes(), note: '2-of-2 immediately, or A alone once the locktime passes' };
      }
      case 'cltv-multisig': {
        const keys = String(v.pubkeys || '').split(/[\s,]+/).filter(Boolean).map(x => key(x));
        const w = new Writer();
        w.push(pushData(scriptNum(BigInt(v.locktime || 0)))).u8(0xb1).u8(0x75);
        w.push(multisig(Number(v.m || 1), keys));
        return { script: w.bytes(), note: 'CLTV gate followed by a bare multisig' };
      }
      case 'hashlock256': {
        const hsh = hexToBytes(String(v.hash || '').trim());
        if (hsh.length !== 32) throw new Error('a SHA256 digest is 32 bytes');
        return { script: BC.cat(new Uint8Array([0xa8]), pushData(hsh), new Uint8Array([0x87])), note: 'OP_SHA256 <h> OP_EQUAL' };
      }
      case 'hashlock-sig': {
        const hsh = hexToBytes(String(v.hash || '').trim());
        if (hsh.length !== 20) throw new Error('a HASH160 digest is 20 bytes');
        const w = new Writer();
        w.u8(0xa9).push(pushData(hsh)).u8(0x88);                  // HASH160 <h> EQUALVERIFY
        w.push(pushData(key(v.pubkey))).u8(0xac);
        return { script: w.bytes(), note: 'spend with <sig> <preimage>' };
      }
      case 'data-drop': {
        const raw = String(v.data || '').trim();
        const bytes = (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) ? hexToBytes(raw) : utf8ToBytes(raw);
        const w = new Writer();
        w.push(pushData(bytes)).u8(0x75);                         // <data> OP_DROP
        w.push(pushData(key(v.pubkey))).u8(0xac);
        return { script: w.bytes(), note: 'carries data in a spendable output rather than an OP_RETURN — non-standard as a bare scriptPubKey, normal inside P2WSH' };
      }
      case 'p2a':
        return { script: hexToBytes('51024e73'), note: 'OP_1 <0x4e73> — the 4-byte pay-to-anchor output used for fee bumping' };
      case 'witness-any': {
        const ver = Number(v.version || 0);
        const prog = hexToBytes(String(v.program || '').trim());
        if (prog.length < 2 || prog.length > 40) throw new Error('a witness program must be 2–40 bytes');
        return {
          script: witnessProgram(ver, prog),
          note: ver > 1 ? `witness version ${ver} is unassigned — anyone-can-spend under current rules` : ''
        };
      }
      case 'raw-passthru':
        return { script: hexToBytes(String(v.hex || '').trim()), note: 'emitted verbatim, with no validation' };

      default: throw new Error(`unknown template "${id}"`);
    }
  }

  /* ---------------------------------------------------------- scriptCode */

  /**
   * The scriptCode that goes into the signature hash for a given input.
   * Returns { scriptCode, kind, note }.
   */
  function deriveScriptCode(inp) {
    const spk = inp.scriptPubKey ? hexToBytes(inp.scriptPubKey) : new Uint8Array(0);
    const redeem = inp.redeemScript ? hexToBytes(inp.redeemScript) : null;
    const witness = inp.witnessScript ? hexToBytes(inp.witnessScript) : null;
    const c = classify(spk);

    if (inp.scriptCodeOverride) return { scriptCode: hexToBytes(inp.scriptCodeOverride), kind: 'override', note: 'manually overridden' };

    switch (c.type) {
      case T.P2PKH:  return { scriptCode: spk, kind: 'legacy', note: 'the scriptPubKey itself' };
      case T.P2PK:   return { scriptCode: spk, kind: 'legacy', note: 'the scriptPubKey itself' };
      case T.MULTISIG: return { scriptCode: spk, kind: 'legacy', note: 'the bare multisig script' };
      case T.P2WPKH: return {
        scriptCode: p2pkh(c.program), kind: 'bip143',
        note: 'BIP143 substitutes the implicit P2PKH form 76a914{20-byte-pubkey-hash}88ac'
      };
      case T.P2WSH: {
        if (!witness) return { scriptCode: null, kind: 'bip143', note: 'a witnessScript is required for P2WSH' };
        return { scriptCode: witness, kind: 'bip143', note: 'the witnessScript' };
      }
      case T.P2SH: {
        if (!redeem) return { scriptCode: null, kind: 'legacy', note: 'a redeemScript is required for P2SH' };
        const rc = classify(redeem);
        if (rc.type === T.P2WPKH) return { scriptCode: p2pkh(rc.program), kind: 'bip143', note: 'nested P2WPKH — implicit P2PKH scriptCode' };
        if (rc.type === T.P2WSH) {
          if (!witness) return { scriptCode: null, kind: 'bip143', note: 'a witnessScript is required for nested P2WSH' };
          return { scriptCode: witness, kind: 'bip143', note: 'nested P2WSH — the witnessScript' };
        }
        return { scriptCode: redeem, kind: 'legacy', note: 'the redeemScript' };
      }
      case T.P2TR: return { scriptCode: null, kind: 'bip341', note: 'Taproot commits to scriptPubKeys directly; there is no scriptCode' };
      default: return { scriptCode: spk.length ? spk : null, kind: 'legacy', note: 'non-standard — using the scriptPubKey as-is' };
    }
  }

  /** Remove OP_CODESEPARATOR from a scriptCode (legacy sighash rule). */
  function stripCodeSeparators(script) {
    const { ops } = parseScript(script);
    const w = new Writer();
    for (const o of ops) {
      if (o.op === 0xab) continue;
      w.push(script.slice(o.offset, o.offset + o.size));
    }
    return w.bytes();
  }

  global.NETWORKS = NETWORKS;
  global.SCRIPT = {
    OPS, OP_NAME, OP_CATEGORIES, OP_CAT_OF, OP_DOC, TYPES: T,
    pushData, scriptNum, readScriptNum, parseScript, toAsm, fromAsm, classify,
    p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, multisig, opReturn, witnessProgram,
    scriptToAddress, addressToScript, validateAddress,
    TEMPLATES, buildTemplate, deriveScriptCode, stripCodeSeparators
  };
})(window);
