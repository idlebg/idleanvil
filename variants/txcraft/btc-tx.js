/* btc-tx.js — opcodes, Script compiler/decompiler, address codecs, Taproot trees,
   transaction serialisation and the three signature-hash algorithms. Requires btc-core.js. */
(function (g) {
  const B = g.BTC;
  const { toHex, fromHex, concat, rev, utf8, sha256, hash160, hash256, taggedHash,
    b58check, b58checkDec, bechEncode, bechDecode, convertBits, Writer, Reader, NETWORKS,
    bigToBytes, bytesToBig, pointFromPubkey, ptAdd, ptMul, xOnly, G, P } = B;

  /* ─────────────── opcodes ─────────────── */
  const OPS = {
    OP_0: 0x00, OP_FALSE: 0x00, OP_PUSHDATA1: 0x4c, OP_PUSHDATA2: 0x4d, OP_PUSHDATA4: 0x4e,
    OP_1NEGATE: 0x4f, OP_RESERVED: 0x50, OP_1: 0x51, OP_TRUE: 0x51, OP_2: 0x52, OP_3: 0x53,
    OP_4: 0x54, OP_5: 0x55, OP_6: 0x56, OP_7: 0x57, OP_8: 0x58, OP_9: 0x59, OP_10: 0x5a,
    OP_11: 0x5b, OP_12: 0x5c, OP_13: 0x5d, OP_14: 0x5e, OP_15: 0x5f, OP_16: 0x60,
    OP_NOP: 0x61, OP_VER: 0x62, OP_IF: 0x63, OP_NOTIF: 0x64, OP_VERIF: 0x65, OP_VERNOTIF: 0x66,
    OP_ELSE: 0x67, OP_ENDIF: 0x68, OP_VERIFY: 0x69, OP_RETURN: 0x6a,
    OP_TOALTSTACK: 0x6b, OP_FROMALTSTACK: 0x6c, OP_2DROP: 0x6d, OP_2DUP: 0x6e, OP_3DUP: 0x6f,
    OP_2OVER: 0x70, OP_2ROT: 0x71, OP_2SWAP: 0x72, OP_IFDUP: 0x73, OP_DEPTH: 0x74, OP_DROP: 0x75,
    OP_DUP: 0x76, OP_NIP: 0x77, OP_OVER: 0x78, OP_PICK: 0x79, OP_ROLL: 0x7a, OP_ROT: 0x7b,
    OP_SWAP: 0x7c, OP_TUCK: 0x7d, OP_CAT: 0x7e, OP_SUBSTR: 0x7f, OP_LEFT: 0x80, OP_RIGHT: 0x81,
    OP_SIZE: 0x82, OP_INVERT: 0x83, OP_AND: 0x84, OP_OR: 0x85, OP_XOR: 0x86,
    OP_EQUAL: 0x87, OP_EQUALVERIFY: 0x88, OP_RESERVED1: 0x89, OP_RESERVED2: 0x8a,
    OP_1ADD: 0x8b, OP_1SUB: 0x8c, OP_2MUL: 0x8d, OP_2DIV: 0x8e, OP_NEGATE: 0x8f, OP_ABS: 0x90,
    OP_NOT: 0x91, OP_0NOTEQUAL: 0x92, OP_ADD: 0x93, OP_SUB: 0x94, OP_MUL: 0x95, OP_DIV: 0x96,
    OP_MOD: 0x97, OP_LSHIFT: 0x98, OP_RSHIFT: 0x99, OP_BOOLAND: 0x9a, OP_BOOLOR: 0x9b,
    OP_NUMEQUAL: 0x9c, OP_NUMEQUALVERIFY: 0x9d, OP_NUMNOTEQUAL: 0x9e, OP_LESSTHAN: 0x9f,
    OP_GREATERTHAN: 0xa0, OP_LESSTHANOREQUAL: 0xa1, OP_GREATERTHANOREQUAL: 0xa2,
    OP_MIN: 0xa3, OP_MAX: 0xa4, OP_WITHIN: 0xa5,
    OP_RIPEMD160: 0xa6, OP_SHA1: 0xa7, OP_SHA256: 0xa8, OP_HASH160: 0xa9, OP_HASH256: 0xaa,
    OP_CODESEPARATOR: 0xab, OP_CHECKSIG: 0xac, OP_CHECKSIGVERIFY: 0xad,
    OP_CHECKMULTISIG: 0xae, OP_CHECKMULTISIGVERIFY: 0xaf,
    OP_NOP1: 0xb0, OP_CHECKLOCKTIMEVERIFY: 0xb1, OP_CLTV: 0xb1, OP_CHECKSEQUENCEVERIFY: 0xb2, OP_CSV: 0xb2,
    OP_NOP4: 0xb3, OP_NOP5: 0xb4, OP_NOP6: 0xb5, OP_NOP7: 0xb6, OP_NOP8: 0xb7, OP_NOP9: 0xb8, OP_NOP10: 0xb9,
    OP_CHECKSIGADD: 0xba, OP_INVALIDOPCODE: 0xff
  };
  const OP_NAME = {};
  for (const k of Object.keys(OPS)) if (OP_NAME[OPS[k]] === undefined) OP_NAME[OPS[k]] = k;
  OP_NAME[0x00] = 'OP_0'; OP_NAME[0x51] = 'OP_1'; OP_NAME[0xb1] = 'OP_CHECKLOCKTIMEVERIFY'; OP_NAME[0xb2] = 'OP_CHECKSEQUENCEVERIFY';

  const OP_GROUPS = [
    { name: 'Push', ops: ['OP_0', 'OP_1NEGATE', 'OP_1', 'OP_2', 'OP_3', 'OP_4', 'OP_5', 'OP_6', 'OP_7', 'OP_8', 'OP_9', 'OP_10', 'OP_11', 'OP_12', 'OP_13', 'OP_14', 'OP_15', 'OP_16', 'OP_PUSHDATA1', 'OP_PUSHDATA2', 'OP_PUSHDATA4'] },
    { name: 'Stack', ops: ['OP_DUP', 'OP_DROP', 'OP_SWAP', 'OP_OVER', 'OP_ROT', 'OP_TUCK', 'OP_NIP', 'OP_PICK', 'OP_ROLL', 'OP_DEPTH', 'OP_IFDUP', 'OP_2DUP', 'OP_3DUP', 'OP_2DROP', 'OP_2OVER', 'OP_2ROT', 'OP_2SWAP', 'OP_TOALTSTACK', 'OP_FROMALTSTACK'] },
    { name: 'Arithmetic', ops: ['OP_ADD', 'OP_SUB', 'OP_1ADD', 'OP_1SUB', 'OP_NEGATE', 'OP_ABS', 'OP_NOT', 'OP_0NOTEQUAL', 'OP_BOOLAND', 'OP_BOOLOR', 'OP_NUMEQUAL', 'OP_NUMEQUALVERIFY', 'OP_NUMNOTEQUAL', 'OP_LESSTHAN', 'OP_GREATERTHAN', 'OP_LESSTHANOREQUAL', 'OP_GREATERTHANOREQUAL', 'OP_MIN', 'OP_MAX', 'OP_WITHIN'] },
    { name: 'Crypto', ops: ['OP_SHA256', 'OP_HASH160', 'OP_HASH256', 'OP_RIPEMD160', 'OP_SHA1', 'OP_CHECKSIG', 'OP_CHECKSIGVERIFY', 'OP_CHECKMULTISIG', 'OP_CHECKMULTISIGVERIFY', 'OP_CHECKSIGADD', 'OP_CODESEPARATOR'] },
    { name: 'Locktime', ops: ['OP_CHECKLOCKTIMEVERIFY', 'OP_CHECKSEQUENCEVERIFY'] },
    { name: 'Control', ops: ['OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF', 'OP_VERIFY', 'OP_RETURN', 'OP_EQUAL', 'OP_EQUALVERIFY', 'OP_SIZE', 'OP_NOP'] },
    { name: 'Disabled / reserved', ops: ['OP_CAT', 'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_INVERT', 'OP_AND', 'OP_OR', 'OP_XOR', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_LSHIFT', 'OP_RSHIFT', 'OP_2MUL', 'OP_2DIV', 'OP_RESERVED', 'OP_VER', 'OP_VERIF', 'OP_VERNOTIF', 'OP_NOP1', 'OP_NOP4', 'OP_NOP10'] }
  ];
  const DISABLED = new Set(['OP_CAT', 'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_INVERT', 'OP_AND', 'OP_OR', 'OP_XOR', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_LSHIFT', 'OP_RSHIFT', 'OP_2MUL', 'OP_2DIV']);

  /* ─────────────── pushes ─────────────── */
  function pushData(data, opts) {
    opts = opts || {};
    const n = data.length;
    const force = opts.force;
    let head;
    if (force === 'pushdata1' || (!force && n > 75 && n <= 0xff)) head = new Uint8Array([0x4c, n]);
    else if (force === 'pushdata2' || (!force && n > 0xff && n <= 0xffff)) { head = new Uint8Array(3); head[0] = 0x4d; new DataView(head.buffer).setUint16(1, n, true); }
    else if (force === 'pushdata4' || (!force && n > 0xffff)) { head = new Uint8Array(5); head[0] = 0x4e; new DataView(head.buffer).setUint32(1, n, true); }
    else if (force === 'direct' || !force) {
      if (n > 75) throw new Error('direct push limited to 75 bytes');
      if (!opts.nonMinimal && n === 0) return new Uint8Array([0x00]);
      if (!opts.nonMinimal && n === 1 && data[0] >= 1 && data[0] <= 16) return new Uint8Array([0x50 + data[0]]);
      if (!opts.nonMinimal && n === 1 && data[0] === 0x81) return new Uint8Array([0x4f]);
      head = new Uint8Array([n]);
    } else throw new Error('unknown push mode ' + force);
    return concat([head, data]);
  }
  function scriptNum(i) {
    i = Number(i);
    if (!Number.isSafeInteger(i)) throw new Error('script number must be an integer within ±2^53');
    if (i === 0) return new Uint8Array(0);
    const neg = i < 0; let abs = Math.abs(i); const out = [];
    while (abs > 0) { out.push(abs % 256); abs = Math.floor(abs / 256); }
    if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0x00);
    else if (neg) out[out.length - 1] |= 0x80;
    return new Uint8Array(out);
  }

  /* ─────────────── ASM ↔ bytes ─────────────── */
  function asmToScript(asm, opts) {
    opts = opts || {};
    const toks = String(asm || '').trim().split(/\s+/).filter(Boolean);
    const parts = [];
    for (let i = 0; i < toks.length; i++) {
      let t = toks[i];
      const up = t.toUpperCase();
      if (OPS[up] !== undefined) {
        if (up === 'OP_PUSHDATA1' || up === 'OP_PUSHDATA2' || up === 'OP_PUSHDATA4') {
          const next = toks[++i];
          if (next === undefined) throw new Error(up + ' with no following data');
          parts.push(pushData(fromHex(next.replace(/^0x/, '')), { force: up.toLowerCase().replace('op_', '') }));
        } else parts.push(new Uint8Array([OPS[up]]));
        continue;
      }
      if (/^<.*>$/.test(t)) t = t.slice(1, -1);
      if (/^'.*'$/.test(t) || /^".*"$/.test(t)) { parts.push(pushData(utf8(t.slice(1, -1)), opts)); continue; }
      /* Decimal tokens: negatives and odd-length digit runs are unambiguous numbers
         (even-length digit runs stay hex so scriptToAsm output round-trips). */
      if (/^-?\d+$/.test(t) && (t[0] === '-' || t.length % 2 === 1)) { parts.push(pushData(scriptNum(parseInt(t, 10)), opts)); continue; }
      const hex = t.replace(/^0x/, '');
      if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2) throw new Error('cannot read token "' + t + '" as an opcode, a number or hex data');
      parts.push(pushData(fromHex(hex), opts));
    }
    return concat(parts);
  }
  function scriptToParts(script) {
    const out = []; let i = 0;
    while (i < script.length) {
      const start = i; const op = script[i++];
      if (op > 0 && op < 0x4c) {
        const d = script.slice(i, i + op); i += op;
        out.push({ type: 'push', op: op, data: d, start: start, end: i, minimal: !(op === 1 && ((d[0] >= 1 && d[0] <= 16) || d[0] === 0x81)) });
      } else if (op === 0x4c || op === 0x4d || op === 0x4e) {
        let n;
        if (op === 0x4c) n = script[i++];
        else if (op === 0x4d) { n = script[i] | (script[i + 1] << 8); i += 2; }
        else { n = (script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24)) >>> 0; i += 4; }
        const d = script.slice(i, i + n); i += n;
        out.push({ type: 'push', op: op, data: d, start: start, end: i, minimal: false, pushdata: op });
      } else {
        out.push({ type: 'op', op: op, name: OP_NAME[op] || ('OP_UNKNOWN_' + op.toString(16)), start: start, end: i });
      }
    }
    return out;
  }
  function scriptToAsm(script, opts) {
    opts = opts || {};
    if (!script || !script.length) return '';
    return scriptToParts(script).map((p) => {
      if (p.type === 'op') return p.name;
      const prefix = p.pushdata ? OP_NAME[p.pushdata] + ' ' : '';
      if (!p.data.length) return prefix + (opts.showEmpty ? '<>' : 'OP_0');
      return prefix + toHex(p.data);
    }).join(' ');
  }

  /* ─────────────── output script templates & detection ─────────────── */
  const p2pkh = (h160) => concat([new Uint8Array([0x76, 0xa9, 0x14]), h160, new Uint8Array([0x88, 0xac])]);
  const p2sh = (h160) => concat([new Uint8Array([0xa9, 0x14]), h160, new Uint8Array([0x87])]);
  const p2pk = (pub) => concat([pushData(pub), new Uint8Array([0xac])]);
  const p2wpkh = (h160) => concat([new Uint8Array([0x00, 0x14]), h160]);
  const p2wsh = (h256) => concat([new Uint8Array([0x00, 0x20]), h256]);
  const p2tr = (x32) => concat([new Uint8Array([0x51, 0x20]), x32]);
  function multisig(m, pubkeys) {
    const n = pubkeys.length;
    if (m < 1 || m > 20 || n < m || n > 20) throw new Error('bare multisig needs 1 ≤ m ≤ n ≤ 20');
    /* OP_1..OP_16 only encode up to 16 — 17..20 need a CScriptNum push (consensus accepts both). */
    const opN = (k) => (k <= 16 ? new Uint8Array([0x50 + k]) : pushData(scriptNum(k)));
    return concat([opN(m), ...pubkeys.map((p) => pushData(p)), opN(n), new Uint8Array([0xae])]);
  }
  function opReturn(payloads, opts) {
    opts = opts || {};
    const parts = [new Uint8Array([0x6a])];
    if (opts.prefixOp) parts.push(new Uint8Array([opts.prefixOp]));
    for (const p of payloads) parts.push(pushData(p, opts));
    return concat(parts);
  }

  function classify(script) {
    if (!script || !script.length) return { type: 'empty', label: 'empty' };
    const h = toHex(script);
    if (script.length === 25 && h.startsWith('76a914') && h.endsWith('88ac')) return { type: 'p2pkh', label: 'P2PKH', hash: script.slice(3, 23) };
    if (script.length === 23 && h.startsWith('a914') && h.endsWith('87')) return { type: 'p2sh', label: 'P2SH', hash: script.slice(2, 22) };
    if (script.length === 22 && script[0] === 0x00 && script[1] === 0x14) return { type: 'p2wpkh', label: 'P2WPKH', hash: script.slice(2) };
    if (script.length === 34 && script[0] === 0x00 && script[1] === 0x20) return { type: 'p2wsh', label: 'P2WSH', hash: script.slice(2) };
    if (script.length === 34 && script[0] === 0x51 && script[1] === 0x20) return { type: 'p2tr', label: 'P2TR', hash: script.slice(2) };
    if ((script.length === 35 || script.length === 67) && script[script.length - 1] === 0xac && script[0] === script.length - 2) return { type: 'p2pk', label: 'P2PK', pubkey: script.slice(1, -1) };
    if (script[0] === 0x6a) return { type: 'nulldata', label: 'OP_RETURN' };
    if (script[script.length - 1] === 0xae && script[0] >= 0x51 && script[0] <= 0x60) return { type: 'multisig', label: 'Bare multisig' };
    if (script.length >= 4 && script.length <= 42 && (script[0] === 0x00 || (script[0] >= 0x51 && script[0] <= 0x60)) && script[1] === script.length - 2)
      return { type: 'witness_unknown', label: 'Witness v' + (script[0] ? script[0] - 0x50 : 0) + ' (unknown program)' };
    return { type: 'nonstandard', label: 'Non-standard' };
  }

  /* ─────────────── addresses ─────────────── */
  function addressFromScript(script, network) {
    const net = NETWORKS[network] || NETWORKS.mainnet;
    const c = classify(script);
    try {
      if (c.type === 'p2pkh') return b58check(concat([new Uint8Array([net.p2pkh]), c.hash]));
      if (c.type === 'p2sh') return b58check(concat([new Uint8Array([net.p2sh]), c.hash]));
      if (c.type === 'p2wpkh' || c.type === 'p2wsh') return bechEncode(net.hrp, [0].concat(convertBits(Array.from(c.hash), 8, 5, true)), 'bech32');
      if (c.type === 'p2tr') return bechEncode(net.hrp, [1].concat(convertBits(Array.from(c.hash), 8, 5, true)), 'bech32m');
      if (c.type === 'witness_unknown') return bechEncode(net.hrp, [script[0] - 0x50].concat(convertBits(Array.from(script.slice(2)), 8, 5, true)), 'bech32m');
    } catch (e) { return null; }
    return null;
  }
  function addressToScript(addr, network) {
    const net = NETWORKS[network] || NETWORKS.mainnet;
    const a = String(addr || '').trim();
    if (!a) throw new Error('empty address');
    if (/^(bc|tb|bcrt)1/i.test(a)) {
      const d = bechDecode(a);
      if (d.hrp !== net.hrp) throw new Error('address is for hrp "' + d.hrp + '", the selected network uses "' + net.hrp + '"');
      const ver = d.data[0];
      if (ver == null || ver > 16) throw new Error('witness version ' + ver + ' is outside the valid 0–16 range');
      const prog = new Uint8Array(convertBits(d.data.slice(1), 5, 8, false));
      if (ver === 0 && d.spec !== 'bech32') throw new Error('witness v0 must use bech32, not bech32m');
      if (ver > 0 && d.spec !== 'bech32m') throw new Error('witness v1+ must use bech32m');
      if (ver === 0 && prog.length !== 20 && prog.length !== 32) throw new Error('witness v0 program must be 20 or 32 bytes');
      if (prog.length < 2 || prog.length > 40) throw new Error('witness program must be 2–40 bytes');
      return { script: concat([new Uint8Array([ver ? 0x50 + ver : 0, prog.length]), prog]), type: ver === 0 ? (prog.length === 20 ? 'p2wpkh' : 'p2wsh') : ver === 1 && prog.length === 32 ? 'p2tr' : 'witness_unknown' };
    }
    const body = b58checkDec(a);
    const v = body[0], h = body.slice(1);
    if (h.length !== 20) throw new Error('base58 address payload must be 20 bytes');
    if (v === net.p2pkh) return { script: p2pkh(h), type: 'p2pkh' };
    if (v === net.p2sh) return { script: p2sh(h), type: 'p2sh' };
    throw new Error('version byte 0x' + v.toString(16) + ' does not belong to ' + net.label);
  }

  /* ─────────────── Taproot ─────────────── */
  /* The leaf version byte always has its parity bit clear (BIP 341) — mask it so a
     control-block first byte pasted with the parity bit set still hashes correctly. */
  const tapLeafHash = (script, ver) => taggedHash('TapLeaf', concat([new Uint8Array([(ver == null ? 0xc0 : ver) & 0xfe]), new Writer().varslice(script).bytes()]));
  function tapBranch(a, b) {
    const [x, y] = toHex(a) <= toHex(b) ? [a, b] : [b, a];
    return taggedHash('TapBranch', concat([x, y]));
  }
  /* leaves: [{script:Uint8Array, version:int, depth:int|null}] — depths optional, else balanced */
  function tapTree(leaves) {
    if (!leaves.length) return { root: null, leaves: [] };
    let items = leaves.map((l, i) => ({ idx: i, depth: l.depth, hash: tapLeafHash(l.script, l.version), path: [] }));
    if (items.some((i) => i.depth == null)) {
      const d = Math.ceil(Math.log2(items.length)) || 0;
      const full = 1 << d, extra = full - items.length;
      items = items.map((it, i) => ({ ...it, depth: i < items.length - extra ? d : Math.max(d - 1, 0) }));
      if (items.length === 1) items[0].depth = 0;
    }
    const stack = [];
    for (const it of items) {
      let node = { depth: it.depth, hash: it.hash, members: [it] };
      while (stack.length && stack[stack.length - 1].depth === node.depth) {
        const prev = stack.pop();
        for (const m of prev.members) m.path.push(node.hash);
        for (const m of node.members) m.path.push(prev.hash);
        node = { depth: node.depth - 1, hash: tapBranch(prev.hash, node.hash), members: prev.members.concat(node.members) };
      }
      stack.push(node);
    }
    while (stack.length > 1) {
      const b = stack.pop(), a = stack.pop();
      for (const m of a.members) m.path.push(b.hash);
      for (const m of b.members) m.path.push(a.hash);
      stack.push({ depth: Math.min(a.depth, b.depth) - 1, hash: tapBranch(a.hash, b.hash), members: a.members.concat(b.members) });
    }
    return { root: stack[0].hash, leaves: items.sort((x, y) => x.idx - y.idx) };
  }
  function tapTweak(internalXOnly, merkleRoot) {
    const t = taggedHash('TapTweak', merkleRoot && merkleRoot.length ? concat([internalXOnly, merkleRoot]) : internalXOnly);
    const tv = bytesToBig(t);
    if (tv >= B.N) throw new Error('TapTweak value is not a valid scalar');
    const Pt = pointFromPubkey(internalXOnly);
    const Q = ptAdd(Pt, ptMul(tv, G));
    if (!Q) throw new Error('tweaked key is the point at infinity');
    return { tweak: t, outputKey: xOnly(Q), parity: (Q.y & 1n) === 1n ? 1 : 0 };
  }
  const controlBlock = (leafVersion, parity, internalXOnly, path) =>
    concat([new Uint8Array([(leafVersion & 0xfe) | (parity & 1)]), internalXOnly, ...path]);

  /* ─────────────── transaction model ─────────────── */
  function serializeTx(tx, opts) {
    opts = opts || {};
    const w = new Writer();
    const useWitness = opts.witness !== false && tx.ins.some((i) => i.witness && i.witness.length);
    w.mark('version', () => w.i32(tx.version), { desc: 'nVersion — transaction version, 4 bytes little-endian' });
    if (useWitness) w.mark('segwit-marker', () => w.raw(new Uint8Array([0x00, 0x01])), { desc: 'SegWit marker 0x00 and flag 0x01 (BIP 144)' });
    w.mark('vin-count', () => w.varint(tx.ins.length), { desc: 'Number of inputs, as a compact-size integer' });
    tx.ins.forEach((inp, i) => {
      w.mark('in' + i + '-txid', () => w.raw(rev(fromHex(inp.txid || '00'.repeat(32)))), { desc: 'Input #' + i + ' previous txid, internal (reversed) byte order', field: 'in.' + i + '.txid' });
      w.mark('in' + i + '-vout', () => w.u32(inp.vout || 0), { desc: 'Input #' + i + ' previous output index', field: 'in.' + i + '.vout' });
      const ss = inp.scriptSig || new Uint8Array(0);
      w.mark('in' + i + '-scriptsig-len', () => w.varint(ss.length), { desc: 'Input #' + i + ' scriptSig length', field: 'in.' + i + '.scriptSig' });
      if (ss.length) w.mark('in' + i + '-scriptsig', () => w.raw(ss), { desc: 'Input #' + i + ' scriptSig', field: 'in.' + i + '.scriptSig' });
      w.mark('in' + i + '-sequence', () => w.u32(inp.sequence >>> 0), { desc: 'Input #' + i + ' nSequence', field: 'in.' + i + '.sequence' });
    });
    w.mark('vout-count', () => w.varint(tx.outs.length), { desc: 'Number of outputs, as a compact-size integer' });
    tx.outs.forEach((o, i) => {
      w.mark('out' + i + '-value', () => w.u64(o.value || 0), { desc: 'Output #' + i + ' amount in satoshis, 8 bytes little-endian', field: 'out.' + i + '.value' });
      w.mark('out' + i + '-spk-len', () => w.varint((o.script || new Uint8Array(0)).length), { desc: 'Output #' + i + ' scriptPubKey length', field: 'out.' + i + '.script' });
      if ((o.script || []).length) w.mark('out' + i + '-spk', () => w.raw(o.script), { desc: 'Output #' + i + ' scriptPubKey', field: 'out.' + i + '.script' });
    });
    if (useWitness) {
      tx.ins.forEach((inp, i) => {
        const stack = inp.witness || [];
        w.mark('wit' + i + '-count', () => w.varint(stack.length), { desc: 'Input #' + i + ' witness item count', field: 'in.' + i + '.witness' });
        stack.forEach((item, j) => w.mark('wit' + i + '-' + j, () => w.varslice(item), { desc: 'Input #' + i + ' witness item ' + j, field: 'in.' + i + '.witness' }));
      });
    }
    w.mark('locktime', () => w.u32(tx.locktime >>> 0), { desc: 'nLockTime' });
    return { bytes: w.bytes(), hex: w.hex(), marks: w.marks, segwit: useWitness };
  }
  function parseTx(bytes) {
    const r = new Reader(bytes);
    const tx = { version: r.i32(), ins: [], outs: [], locktime: 0 };
    let segwit = false;
    let n = r.varint();
    if (n === 0) { const flag = r.u8(); if (flag !== 1) throw new Error('unknown SegWit flag byte 0x' + flag.toString(16)); segwit = true; n = r.varint(); }
    for (let i = 0; i < n; i++) tx.ins.push({ txid: toHex(rev(r.raw(32))), vout: r.u32(), scriptSig: r.varslice(), sequence: r.u32(), witness: [] });
    const m = r.varint();
    for (let i = 0; i < m; i++) tx.outs.push({ value: Number(r.u64()), script: r.varslice() });
    if (segwit) for (let i = 0; i < n; i++) { const c = r.varint(); const st = []; for (let j = 0; j < c; j++) st.push(r.varslice()); tx.ins[i].witness = st; }
    tx.locktime = r.u32();
    tx.segwit = segwit;
    if (r.left) tx.trailing = toHex(r.raw(r.left));
    return tx;
  }
  const txid = (tx) => toHex(rev(hash256(serializeTx(tx, { witness: false }).bytes)));
  const wtxid = (tx) => toHex(rev(hash256(serializeTx(tx).bytes)));
  function measure(tx) {
    const full = serializeTx(tx).bytes.length;
    const base = serializeTx(tx, { witness: false }).bytes.length;
    const weight = base * 3 + full;
    return { size: full, stripped: base, weight: weight, vsize: Math.ceil(weight / 4) };
  }

  /* ─────────────── sighash ─────────────── */
  const SIGHASH = { DEFAULT: 0x00, ALL: 0x01, NONE: 0x02, SINGLE: 0x03, ANYONECANPAY: 0x80 };
  function sighashByte(type, acp) {
    const base = SIGHASH[type] !== undefined ? SIGHASH[type] : 0x01;
    return (base | (acp ? 0x80 : 0)) & 0xff;
  }
  function sighashLabel(byte) {
    const base = byte & 0x7f;
    const names = { 0: 'DEFAULT', 1: 'ALL', 2: 'NONE', 3: 'SINGLE' };
    return (names[base] || 'UNKNOWN(0x' + base.toString(16) + ')') + (byte & 0x80 ? ' | ANYONECANPAY' : '');
  }
  const stripCodeseps = (script) => concat(scriptToParts(script).filter((p) => !(p.type === 'op' && p.op === 0xab)).map((p) => script.slice(p.start, p.end)));

  function sighashLegacy(tx, index, scriptCode, hashType) {
    const acp = !!(hashType & 0x80), base = hashType & 0x1f;
    const code = stripCodeseps(scriptCode);
    const ins = (acp ? [tx.ins[index]] : tx.ins).map((inp, k) => {
      const isCurrent = acp ? true : k === index;
      return {
        txid: inp.txid, vout: inp.vout,
        scriptSig: isCurrent ? code : new Uint8Array(0),
        sequence: !isCurrent && (base === 2 || base === 3) ? 0 : inp.sequence,
        witness: []
      };
    });
    let outs = tx.outs;
    let oneHash = false;
    if (base === 2) outs = [];
    else if (base === 3) {
      if (index >= tx.outs.length) oneHash = true;
      else outs = tx.outs.slice(0, index + 1).map((o, k) => (k === index ? o : { value: -1, script: new Uint8Array(0) }));
    }
    if (oneHash) {
      const one = new Uint8Array(32); one[0] = 1;
      return { preimage: null, digest: one, z: toHex(one), warning: 'SIGHASH_SINGLE with no output at this index — the legacy algorithm returns the constant 1 (the "SIGHASH_SINGLE bug").' };
    }
    const w = new Writer();
    w.i32(tx.version); w.varint(ins.length);
    for (const i2 of ins) { w.raw(rev(fromHex(i2.txid || '00'.repeat(32)))); w.u32(i2.vout || 0); w.varslice(i2.scriptSig); w.u32(i2.sequence >>> 0); }
    w.varint(outs.length);
    for (const o of outs) { w.i64(o.value === -1 ? -1 : (o.value || 0)); w.varslice(o.script || new Uint8Array(0)); }
    w.u32(tx.locktime >>> 0); w.u32(hashType >>> 0);
    const pre = w.bytes();
    const single = sha256(pre), dbl = sha256(single);
    return { preimage: pre, sha256: single, digest: dbl, z: toHex(dbl) };
  }

  function sighashV0(tx, index, scriptCode, amount, hashType) {
    const acp = !!(hashType & 0x80), base = hashType & 0x1f;
    const z32 = new Uint8Array(32);
    const prevoutsW = new Writer(); tx.ins.forEach((i2) => { prevoutsW.raw(rev(fromHex(i2.txid || '00'.repeat(32)))); prevoutsW.u32(i2.vout || 0); });
    const seqW = new Writer(); tx.ins.forEach((i2) => seqW.u32(i2.sequence >>> 0));
    const outsW = new Writer(); tx.outs.forEach((o) => { outsW.u64(o.value || 0); outsW.varslice(o.script || new Uint8Array(0)); });
    const hashPrevouts = acp ? z32 : hash256(prevoutsW.bytes());
    const hashSequence = acp || base === 2 || base === 3 ? z32 : hash256(seqW.bytes());
    let hashOutputs = z32;
    if (base !== 2 && base !== 3) hashOutputs = hash256(outsW.bytes());
    else if (base === 3 && index < tx.outs.length) {
      const o = tx.outs[index]; const ow = new Writer(); ow.u64(o.value || 0); ow.varslice(o.script || new Uint8Array(0));
      hashOutputs = hash256(ow.bytes());
    }
    const inp = tx.ins[index];
    const w = new Writer();
    const marks = [];
    const mk = (label, fn, desc) => { const s = w.len; fn(); marks.push({ label: label, start: s, end: w.len, desc: desc }); };
    mk('nVersion', () => w.i32(tx.version), 'transaction version');
    mk('hashPrevouts', () => w.raw(hashPrevouts), acp ? 'zeroed by ANYONECANPAY' : 'double-SHA256 of every input outpoint');
    mk('hashSequence', () => w.raw(hashSequence), acp || base === 2 || base === 3 ? 'zeroed by this sighash type' : 'double-SHA256 of every nSequence');
    mk('outpoint', () => { w.raw(rev(fromHex(inp.txid || '00'.repeat(32)))); w.u32(inp.vout || 0); }, 'the outpoint being spent');
    mk('scriptCode', () => w.varslice(scriptCode), 'the script executed for this input');
    mk('amount', () => w.u64(amount || 0), 'value of the output being spent — BIP 143 commits to it');
    mk('nSequence', () => w.u32(inp.sequence >>> 0), 'this input’s sequence');
    mk('hashOutputs', () => w.raw(hashOutputs), base === 2 ? 'zeroed by SIGHASH_NONE' : base === 3 ? 'only the matching output' : 'double-SHA256 of every output');
    mk('nLockTime', () => w.u32(tx.locktime >>> 0), 'transaction locktime');
    mk('sighashType', () => w.u32(hashType >>> 0), 'the 4-byte hash type');
    const pre = w.bytes();
    const single = sha256(pre), dbl = sha256(single);
    const res = { preimage: pre, sha256: single, digest: dbl, z: toHex(dbl), marks: marks, hashPrevouts: toHex(hashPrevouts), hashSequence: toHex(hashSequence), hashOutputs: toHex(hashOutputs) };
    if (base === 3 && index >= tx.outs.length) res.warning = 'SIGHASH_SINGLE with no output at this index — hashOutputs is zero under BIP 143.';
    return res;
  }

  function sighashTaproot(tx, index, prevouts, hashType, opts) {
    opts = opts || {};
    const acp = !!(hashType & 0x80), base = hashType & 0x03;
    /* BIP 341 defines exactly {0x00–0x03, 0x81–0x83}; 0x80 (DEFAULT|ANYONECANPAY) is invalid too. */
    if (!(hashType === 0x00 || hashType === 0x01 || hashType === 0x02 || hashType === 0x03 ||
          hashType === 0x81 || hashType === 0x82 || hashType === 0x83))
      throw new Error('invalid Taproot sighash type 0x' + hashType.toString(16).padStart(2, '0') + ' — BIP 341 allows only 0x00–0x03 and 0x81–0x83');
    const w = new Writer(); const marks = [];
    const mk = (label, fn, desc) => { const s = w.len; fn(); marks.push({ label: label, start: s, end: w.len, desc: desc }); };
    const shaOf = (fill) => { const x = new Writer(); fill(x); return sha256(x.bytes()); };
    mk('hash_type', () => w.u8(hashType), 'the sighash byte (0x00 = DEFAULT)');
    mk('nVersion', () => w.i32(tx.version), 'transaction version');
    mk('nLockTime', () => w.u32(tx.locktime >>> 0), 'transaction locktime');
    if (!acp) {
      mk('sha_prevouts', () => w.raw(shaOf((x) => tx.ins.forEach((i2) => { x.raw(rev(fromHex(i2.txid || '00'.repeat(32)))); x.u32(i2.vout || 0); }))), 'SHA256 of all outpoints');
      mk('sha_amounts', () => w.raw(shaOf((x) => prevouts.forEach((p) => x.u64(p.value || 0)))), 'SHA256 of every spent amount');
      mk('sha_scriptpubkeys', () => w.raw(shaOf((x) => prevouts.forEach((p) => x.varslice(p.script || new Uint8Array(0))))), 'SHA256 of every spent scriptPubKey');
      mk('sha_sequences', () => w.raw(shaOf((x) => tx.ins.forEach((i2) => x.u32(i2.sequence >>> 0)))), 'SHA256 of every nSequence');
    }
    if (base !== 2 && base !== 3) mk('sha_outputs', () => w.raw(shaOf((x) => tx.outs.forEach((o) => { x.u64(o.value || 0); x.varslice(o.script || new Uint8Array(0)); }))), 'SHA256 of all outputs');
    const extFlag = opts.scriptPath ? 1 : 0;
    const annex = opts.annex && opts.annex.length ? opts.annex : null;
    mk('spend_type', () => w.u8(extFlag * 2 + (annex ? 1 : 0)), 'ext_flag × 2 + annex present');
    if (acp) {
      const inp = tx.ins[index], pv = prevouts[index] || {};
      mk('outpoint', () => { w.raw(rev(fromHex(inp.txid || '00'.repeat(32)))); w.u32(inp.vout || 0); }, 'this outpoint (ANYONECANPAY)');
      mk('amount', () => w.u64(pv.value || 0), 'this input’s amount');
      mk('scriptPubKey', () => w.varslice(pv.script || new Uint8Array(0)), 'this input’s scriptPubKey');
      mk('nSequence', () => w.u32(inp.sequence >>> 0), 'this input’s sequence');
    } else {
      mk('input_index', () => w.u32(index), 'index of the input being signed');
    }
    if (annex) mk('sha_annex', () => w.raw(sha256(new Writer().varslice(annex).bytes())), 'SHA256 of the length-prefixed annex');
    if (base === 3) {
      const o = tx.outs[index];
      mk('sha_single_output', () => w.raw(o ? shaOf((x) => { x.u64(o.value || 0); x.varslice(o.script || new Uint8Array(0)); }) : new Uint8Array(32)), 'SHA256 of the matching output');
    }
    if (extFlag === 1) {
      mk('tapleaf_hash', () => w.raw(opts.leafHash || new Uint8Array(32)), 'the TapLeaf hash of the script being executed');
      mk('key_version', () => w.u8(0), 'key version, always 0 today');
      mk('codesep_pos', () => w.u32(opts.codesepPos == null ? 0xffffffff : opts.codesepPos), 'position of the last executed OP_CODESEPARATOR');
    }
    const msg = w.bytes();
    const digest = taggedHash('TapSighash', concat([new Uint8Array([0x00]), msg]));
    const res = { sigMsg: msg, preimage: concat([new Uint8Array([0x00]), msg]), digest: digest, z: toHex(digest), marks: marks };
    if (base === 3 && index >= tx.outs.length) res.warning = 'SIGHASH_SINGLE with no output at this index — invalid under BIP 341.';
    return res;
  }

  Object.assign(B, {
    OPS, OP_NAME, OP_GROUPS, DISABLED, pushData, scriptNum,
    asmToScript, scriptToAsm, scriptToParts,
    p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, multisig, opReturn, classify,
    addressFromScript, addressToScript,
    tapLeafHash, tapBranch, tapTree, tapTweak, controlBlock,
    serializeTx, parseTx, txid, wtxid, measure,
    SIGHASH, sighashByte, sighashLabel, stripCodeseps,
    sighashLegacy, sighashV0, sighashTaproot
  });
})(typeof window !== 'undefined' ? window : globalThis);
