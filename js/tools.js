/* ============================================================================
   tools.js — the toolkit: output descriptors, extended-key decoding, taproot
   trees, unit / base / time conversion, size estimation, and signer code
   generation.
   Exposes: window.TOOLS
   ========================================================================== */
(function (global) {
  'use strict';
  const { bytesToHex, hexToBytes, base58checkDecode, base58checkEncode, Writer, Reader, groupNum } = ENC;
  const S = SCRIPT;

  /* ======================================================================
     1. OUTPUT DESCRIPTORS (BIP380) — build + checksum
     ====================================================================== */

  const DESC_INPUT_CHARSET =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
  const DESC_CHECKSUM_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const DESC_GENERATOR = [0xf5dee51989n, 0xa9fdca3312n, 0x1bab10e32dn, 0x3706b1677an, 0x644d626ffdn];

  function descPolymod(symbols) {
    let chk = 1n;
    for (const v of symbols) {
      const top = chk >> 35n;
      chk = ((chk & 0x7ffffffffn) << 5n) ^ BigInt(v);
      for (let i = 0; i < 5; i++) if ((top >> BigInt(i)) & 1n) chk ^= DESC_GENERATOR[i];
    }
    return chk;
  }

  function descExpand(s) {
    const groups = [], symbols = [];
    for (const c of s) {
      const v = DESC_INPUT_CHARSET.indexOf(c);
      if (v < 0) throw new Error(`"${c}" cannot appear in a descriptor`);
      symbols.push(v & 31);
      groups.push(v >> 5);
      if (groups.length === 3) { symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]); groups.length = 0; }
    }
    if (groups.length === 1) symbols.push(groups[0]);
    else if (groups.length === 2) symbols.push(groups[0] * 3 + groups[1]);
    return symbols;
  }

  /** Append the 8-character BIP380 checksum. */
  function descChecksum(desc) {
    const body = desc.split('#')[0];
    const symbols = descExpand(body).concat([0, 0, 0, 0, 0, 0, 0, 0]);
    const chk = descPolymod(symbols) ^ 1n;
    let out = '';
    for (let i = 0; i < 8; i++) out += DESC_CHECKSUM_CHARSET[Number((chk >> BigInt(5 * (7 - i))) & 31n)];
    return body + '#' + out;
  }

  function descVerify(desc) {
    if (!desc.includes('#')) return { ok: false, reason: 'no checksum present', suggested: descChecksum(desc) };
    const [body, given] = desc.split('#');
    const expected = descChecksum(body).split('#')[1];
    return { ok: given === expected, given, expected, suggested: body + '#' + expected };
  }

  /** Derive a descriptor for the current output/input script where possible. */
  function descriptorFor(scriptHex, opts = {}) {
    const script = hexToBytes(scriptHex);
    const c = S.classify(script);
    const key = opts.pubkey || null;
    const inner = opts.innerScript || null;
    const mk = (s) => descChecksum(s);

    switch (c.type) {
      case 'P2PKH':  return key ? mk(`pkh(${key})`) : mk(`addr(${S.scriptToAddress(script, opts.network) || ''})`);
      case 'P2WPKH': return key ? mk(`wpkh(${key})`) : mk(`addr(${S.scriptToAddress(script, opts.network) || ''})`);
      case 'P2PK':   return mk(`pk(${bytesToHex(c.pubkey)})`);
      case 'P2TR':   return opts.internalKey ? mk(`tr(${opts.internalKey})`) : mk(`rawtr(${bytesToHex(c.program)})`);
      case 'MULTISIG': return mk(`multi(${c.m},${c.pubkeys.map(bytesToHex).join(',')})`);
      case 'P2SH': {
        if (!inner) return mk(`addr(${S.scriptToAddress(script, opts.network) || ''})`);
        const ic = S.classify(inner);
        if (ic.type === 'P2WPKH') return mk(`sh(wpkh(${key || bytesToHex(ic.program)}))`);
        if (ic.type === 'P2WSH')  return mk(`sh(wsh(${opts.witnessDesc || 'raw(' + bytesToHex(inner) + ')'}))`);
        if (ic.type === 'MULTISIG') return mk(`sh(multi(${ic.m},${ic.pubkeys.map(bytesToHex).join(',')}))`);
        return mk(`sh(raw(${bytesToHex(inner)}))`);
      }
      case 'P2WSH': {
        if (!inner) return mk(`addr(${S.scriptToAddress(script, opts.network) || ''})`);
        const ic = S.classify(inner);
        if (ic.type === 'MULTISIG') return mk(`wsh(multi(${ic.m},${ic.pubkeys.map(bytesToHex).join(',')}))`);
        return mk(`wsh(raw(${bytesToHex(inner)}))`);
      }
      default: return mk(`raw(${bytesToHex(script)})`);
    }
  }

  const DESC_TEMPLATES = [
    { id: 'wpkh',       label: 'wpkh(KEY) — native segwit single key',        pattern: 'wpkh([FINGERPRINT/84h/0h/0h]XPUB/0/*)' },
    { id: 'pkh',        label: 'pkh(KEY) — legacy single key',                pattern: 'pkh([FINGERPRINT/44h/0h/0h]XPUB/0/*)' },
    { id: 'sh-wpkh',    label: 'sh(wpkh(KEY)) — nested segwit',               pattern: 'sh(wpkh([FINGERPRINT/49h/0h/0h]XPUB/0/*))' },
    { id: 'tr',         label: 'tr(KEY) — taproot key path',                  pattern: 'tr([FINGERPRINT/86h/0h/0h]XPUB/0/*)' },
    { id: 'wsh-multi',  label: 'wsh(multi(m,…)) — segwit multisig',           pattern: 'wsh(multi(2,XPUB1/0/*,XPUB2/0/*,XPUB3/0/*))' },
    { id: 'wsh-sorted', label: 'wsh(sortedmulti(m,…)) — deterministic order', pattern: 'wsh(sortedmulti(2,XPUB1/0/*,XPUB2/0/*))' },
    { id: 'sh-wsh',     label: 'sh(wsh(multi(m,…))) — nested multisig',       pattern: 'sh(wsh(multi(2,XPUB1/0/*,XPUB2/0/*)))' },
    { id: 'tr-tree',    label: 'tr(KEY,{LEAF,LEAF}) — taproot with scripts',  pattern: 'tr(INTERNALKEY,{pk(KEY1),pk(KEY2)})' },
    { id: 'addr',       label: 'addr(ADDRESS) — watch a single address',      pattern: 'addr(ADDRESS)' },
    { id: 'raw',        label: 'raw(HEX) — an arbitrary scriptPubKey',        pattern: 'raw(SCRIPTHEX)' },
    { id: 'combo',      label: 'combo(KEY) — all four single-key forms',      pattern: 'combo(PUBKEY)' }
  ];

  /* ======================================================================
     2. EXTENDED PUBLIC KEYS (BIP32) — decode metadata only
     ====================================================================== */

  const XKEY_VERSIONS = {
    0x0488b21e: { name: 'xpub', net: 'mainnet', kind: 'public',  script: 'P2PKH / P2SH (BIP44)' },
    0x0488ade4: { name: 'xprv', net: 'mainnet', kind: 'PRIVATE', script: 'P2PKH / P2SH (BIP44)' },
    0x049d7cb2: { name: 'ypub', net: 'mainnet', kind: 'public',  script: 'P2SH-P2WPKH (BIP49)' },
    0x049d7878: { name: 'yprv', net: 'mainnet', kind: 'PRIVATE', script: 'P2SH-P2WPKH (BIP49)' },
    0x04b24746: { name: 'zpub', net: 'mainnet', kind: 'public',  script: 'P2WPKH (BIP84)' },
    0x04b2430c: { name: 'zprv', net: 'mainnet', kind: 'PRIVATE', script: 'P2WPKH (BIP84)' },
    0x0295b43f: { name: 'Ypub', net: 'mainnet', kind: 'public',  script: 'P2SH-P2WSH multisig' },
    0x02aa7ed3: { name: 'Zpub', net: 'mainnet', kind: 'public',  script: 'P2WSH multisig' },
    0x043587cf: { name: 'tpub', net: 'testnet', kind: 'public',  script: 'P2PKH / P2SH (BIP44)' },
    0x04358394: { name: 'tprv', net: 'testnet', kind: 'PRIVATE', script: 'P2PKH / P2SH (BIP44)' },
    0x044a5262: { name: 'upub', net: 'testnet', kind: 'public',  script: 'P2SH-P2WPKH (BIP49)' },
    0x045f1cf6: { name: 'vpub', net: 'testnet', kind: 'public',  script: 'P2WPKH (BIP84)' },
    0x024289ef: { name: 'Upub', net: 'testnet', kind: 'public',  script: 'P2SH-P2WSH multisig' },
    0x02575483: { name: 'Vpub', net: 'testnet', kind: 'public',  script: 'P2WSH multisig' }
  };

  /**
   * Decode a BIP32 extended key. Private keys are recognised but their key
   * material is never returned — this tool holds no secrets.
   */
  function decodeXKey(str) {
    const raw = base58checkDecode(String(str).trim());
    if (raw.length !== 78) throw new Error(`extended keys are 78 bytes; this decoded to ${raw.length}`);
    const version = new DataView(raw.buffer, raw.byteOffset, 4).getUint32(0, false);
    const info = XKEY_VERSIONS[version];
    const depth = raw[4];
    const parentFp = bytesToHex(raw.slice(5, 9));
    const childRaw = new DataView(raw.buffer, raw.byteOffset + 9, 4).getUint32(0, false);
    const hardened = !!(childRaw & 0x80000000);
    const childNum = childRaw & 0x7fffffff;
    const chainCode = bytesToHex(raw.slice(13, 45));
    const keyBytes = raw.slice(45, 78);
    const isPrivate = keyBytes[0] === 0x00;

    const out = {
      version: '0x' + version.toString(16).padStart(8, '0'),
      prefix: info ? info.name : 'unknown',
      network: info ? info.net : 'unknown',
      kind: isPrivate ? 'PRIVATE' : 'public',
      scriptHint: info ? info.script : '—',
      depth,
      parentFingerprint: parentFp,
      childNumber: depth === 0 ? '(master)' : `${childNum}${hardened ? "'" : ''}`,
      chainCode,
      isPrivate
    };
    if (isPrivate) {
      out.publicKey = null;
      out.fingerprint = null;
      out.warning = 'This is an extended PRIVATE key. The workbench will not display or store the key material — ' +
                    'derive the matching xpub in your wallet and paste that instead.';
    } else {
      out.publicKey = bytesToHex(keyBytes);
      out.fingerprint = bytesToHex(BC.hash160(keyBytes).slice(0, 4));
      out.pointValid = !!BC.secp.decompressPoint(keyBytes);
      out.xOnly = bytesToHex(keyBytes.slice(1));
    }
    if (depth === 0 && (parentFp !== '00000000' || childRaw !== 0))
      out.anomaly = 'depth is 0 but the parent fingerprint or child number is non-zero';
    return out;
  }

  /* ======================================================================
     3. TAPROOT TREES (BIP341) — merkle root + per-leaf control blocks
     ====================================================================== */

  /**
   * Build a balanced taproot script tree.
   * @param {Array} leaves [{script: Uint8Array, version: number}]
   * @returns {{root: Uint8Array, leaves: Array, layout: string}}
   */
  function buildTapTree(leaves) {
    if (!leaves.length) return { root: null, leaves: [], layout: '(empty)' };
    const nodes = leaves.map((l, i) => ({
      leaf: true, index: i,
      hash: BC.tapLeafHash(l.script, l.version),
      script: l.script, version: l.version, path: []
    }));
    if (nodes.length === 1) {
      return { root: nodes[0].hash, leaves: nodes, layout: 'single leaf (root = tapleaf hash)' };
    }

    /* recursive balanced split, matching the BIP341 reference helper */
    const build = (list) => {
      if (list.length === 1) return list[0];
      const mid = Math.ceil(list.length / 2);
      const left = build(list.slice(0, mid));
      const right = build(list.slice(mid));
      collect(left).forEach(n => n.path.push(right.hash));
      collect(right).forEach(n => n.path.push(left.hash));
      return { leaf: false, hash: BC.tapBranchHash(left.hash, right.hash), left, right };
    };
    const collect = (node) => node.leaf ? [node] : collect(node.left).concat(collect(node.right));

    const root = build(nodes);
    return { root: root.hash, leaves: nodes, tree: root, layout: describeTree(root) };
  }

  function describeTree(node, depth = 0, prefix = '') {
    const pad = '  '.repeat(depth);
    if (node.leaf) return `${pad}${prefix}<span class="lf">leaf ${node.index}</span> <span class="hs">${bytesToHex(node.hash).slice(0, 16)}…</span>`;
    return `${pad}${prefix}<span class="br">branch</span> <span class="hs">${bytesToHex(node.hash).slice(0, 16)}…</span>\n` +
      describeTree(node.left, depth + 1, '├ ') + '\n' + describeTree(node.right, depth + 1, '└ ');
  }

  /** Control block for a leaf: (leafVersion | parity) || internalKey || path… */
  function controlBlock(leafVersion, parity, internalKey, path) {
    return BC.cat(new Uint8Array([(leafVersion & 0xfe) | (parity & 1)]), internalKey, ...path);
  }

  /** Full taproot output computation from an internal key plus a leaf list. */
  function taprootOutput(internalKeyHex, leaves) {
    const internal = hexToBytes(internalKeyHex);
    if (internal.length !== 32) throw new Error(`the internal key must be 32 bytes (x-only); got ${internal.length}`);
    const tree = buildTapTree(leaves);
    const tweak = BC.taprootTweak(internal, tree.root);
    return {
      internalKey: internalKeyHex,
      merkleRoot: tree.root ? bytesToHex(tree.root) : null,
      outputKey: bytesToHex(tweak.outputKey),
      parity: tweak.parity,
      tweak: bytesToHex(tweak.tweak),
      scriptPubKey: bytesToHex(S.p2tr(tweak.outputKey)),
      layout: tree.layout,
      leaves: tree.leaves.map(l => ({
        index: l.index,
        version: l.version,
        script: bytesToHex(l.script),
        asm: S.toAsm(l.script),
        leafHash: bytesToHex(l.hash),
        merklePath: l.path.map(bytesToHex),
        controlBlock: bytesToHex(controlBlock(l.version, tweak.parity, internal, l.path))
      }))
    };
  }

  /* ======================================================================
     4. UNIT / BASE / TIME CONVERSION
     ====================================================================== */

  const UNITS = [
    { id: 'sat',  label: 'satoshi',      per: 1n },
    { id: 'bit',  label: 'bit (µBTC)',   per: 100n },
    { id: 'mbtc', label: 'mBTC',         per: 100000n },
    { id: 'btc',  label: 'BTC',          per: 100000000n }
  ];

  function convertUnits(value, fromId) {
    const from = UNITS.find(u => u.id === fromId) || UNITS[0];
    const s = String(value).replace(/[\s,_]/g, '');
    if (s && !/^-?\d*\.?\d*$/.test(s)) throw new Error('not a valid number');
    const neg = s.startsWith('-');
    const dec = String(from.per).length - 1;
    const [w = '', f = ''] = (neg ? s.slice(1) : s).split('.');
    /* reject only lossy input: excess decimals are fine when they are all zeros */
    if (f.length > dec && f.slice(dec).replace(/0/g, '') !== '')
      throw new Error(dec === 0
        ? 'the satoshi is the smallest unit — fractional sats do not exist'
        : `${from.label} amounts must resolve to whole sats (at most ${dec} decimal places here)`);
    let sats = BigInt(w || '0') * from.per + (dec ? BigInt((f + '0'.repeat(dec)).slice(0, dec) || '0') : 0n);
    if (neg) sats = -sats;
    const fmt = (per) => {
      if (per === 1n) return sats.toString();
      const dec = String(per).length - 1;
      const neg = sats < 0n, v = neg ? -sats : sats;
      return (neg ? '-' : '') + (v / per) + '.' + (v % per).toString().padStart(dec, '0');
    };
    return {
      sats,
      values: UNITS.map(u => ({ id: u.id, label: u.label, value: fmt(u.per) })),
      hex: bytesToHex(new Writer().u64(sats < 0n ? 0n : sats).bytes()),
      isDust: { p2wpkh: sats < 294n, p2pkh: sats < 546n, p2tr: sats < 330n }
    };
  }

  function convertBase(input) {
    const s = String(input).trim().replace(/[\s,_]/g, '');
    if (!s) return null;
    let v;
    try {
      if (/^0x/i.test(s)) v = BigInt(s);
      else if (/^0b/i.test(s)) v = BigInt(s);
      else if (/^-?\d+$/.test(s)) v = BigInt(s);
      else if (/^[0-9a-fA-F]+$/.test(s)) v = BigInt('0x' + s);
      else return { error: 'not a recognisable number (try decimal, 0x hex, or 0b binary)' };
    } catch (e) { return { error: e.message }; }

    const neg = v < 0n, av = neg ? -v : v;
    let hex = av.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const bytes = hexToBytes(hex);
    return {
      decimal: v.toString(),
      hex: (neg ? '-' : '') + hex,
      hexPrefixed: (neg ? '-' : '') + '0x' + hex,
      binary: (neg ? '-' : '') + av.toString(2),
      octal: (neg ? '-' : '') + av.toString(8),
      base58: neg ? '—' : ENC.base58Encode(bytes),
      base64: neg ? '—' : ENC.bytesToBase64(bytes),
      bytes: bytes.length,
      littleEndian: neg ? '—' : bytesToHex(ENC.reverse(bytes)),
      scriptNum: bytesToHex(S.scriptNum(v)),
      varint: (v >= 0n && v <= 0xffffffffffffffffn) ? bytesToHex(ENC.encodeVarInt(v)) : '— out of range',
      fitsU32: v >= 0n && v <= 0xffffffffn,
      fitsI32: v >= -2147483648n && v <= 2147483647n
    };
  }

  const AVG_BLOCK_SECONDS = 600;

  function locktimeInfo(value, mode, refHeight) {
    const v = Number(value) || 0;
    const out = { raw: v, hex: '0x' + (v >>> 0).toString(16).padStart(8, '0') };
    if (v === 0) { out.meaning = 'disabled — final at any height'; out.kind = 'disabled'; return out; }
    if (v < TX.LOCKTIME_THRESHOLD) {
      out.kind = 'height';
      out.meaning = `block height ${groupNum(v)}`;
      if (refHeight) {
        const delta = v - Number(refHeight);
        out.eta = delta <= 0 ? 'already reached'
          : `${groupNum(delta)} blocks away ≈ ${humanDuration(delta * AVG_BLOCK_SECONDS)} (≈ ${new Date(Date.now() + delta * AVG_BLOCK_SECONDS * 1000).toISOString().slice(0, 16).replace('T', ' ')} UTC)`;
      }
    } else {
      out.kind = 'time';
      const d = new Date(v * 1000);
      out.meaning = `unix time ${groupNum(v)}`;
      out.utc = d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
      out.local = d.toLocaleString();
      const delta = v - Math.floor(Date.now() / 1000);
      out.eta = delta <= 0 ? 'already passed' : `${humanDuration(delta)} from now`;
    }
    return out;
  }

  function dateToLocktime(isoString) {
    const t = Math.floor(new Date(isoString).getTime() / 1000);
    if (isNaN(t)) throw new Error('could not parse that date');
    if (t < TX.LOCKTIME_THRESHOLD) throw new Error('dates before 1985-11-05 collide with the block-height range');
    return t;
  }

  /** BIP68 relative timelock encoding. */
  function encodeSequence(opts) {
    if (opts.disabled) return 0xffffffff;
    if (opts.type === 'time') {
      const units = Math.min(0xffff, Math.max(0, Math.ceil(Number(opts.seconds || 0) / 512)));
      return (0x00400000 | units) >>> 0;
    }
    return (Math.min(0xffff, Math.max(0, Number(opts.blocks || 0)))) >>> 0;
  }

  function decodeSequence(seq) {
    seq = seq >>> 0;
    const out = { hex: '0x' + seq.toString(16).padStart(8, '0'), value: seq };
    out.rbf = seq < 0xfffffffe;
    out.locktimeEnabled = seq !== 0xffffffff;
    if (seq & 0x80000000) { out.relative = 'disabled (bit 31 set)'; return out; }
    const units = seq & 0xffff;
    if (seq & 0x00400000) {
      out.relative = `${units} × 512 s = ${humanDuration(units * 512)}`;
      out.relativeType = 'time';
    } else {
      out.relative = `${units} block${units === 1 ? '' : 's'} ≈ ${humanDuration(units * AVG_BLOCK_SECONDS)}`;
      out.relativeType = 'blocks';
    }
    return out;
  }

  function humanDuration(sec) {
    sec = Math.round(sec);
    if (sec < 60) return `${sec} s`;
    const units = [['d', 86400], ['h', 3600], ['m', 60]];
    const parts = [];
    for (const [label, size] of units) {
      const n = Math.floor(sec / size);
      if (n) { parts.push(n + label); sec -= n * size; }
      if (parts.length === 2) break;
    }
    return parts.join(' ') || '0m';
  }

  /* ======================================================================
     5. SIZE / FEE ESTIMATOR for arbitrary input & output mixes
     ====================================================================== */

  const INPUT_COSTS = {
    'P2PKH':       { base: 148, wit: 0,   note: 'legacy single key' },
    'P2SH-2of3':   { base: 297, wit: 0,   note: 'legacy 2-of-3 multisig' },  // 36 outpoint + 3 len varint + 254 scriptSig (OP_0 + 2×73 B sig pushes + PUSHDATA1 105 B redeem) + 4 sequence
    'P2SH-P2WPKH': { base: 64,  wit: 108, note: 'nested segwit key' },   // 36+4+1+23 base; ≈91 vB total
    'P2WPKH':      { base: 41,  wit: 108, note: 'native segwit key' },
    'P2WSH-2of3':  { base: 41,  wit: 256, note: 'native segwit 2-of-3' },
    'P2TR-key':    { base: 41,  wit: 66,  note: 'taproot key path' },
    'P2TR-script': { base: 41,  wit: 160, note: 'taproot script path (varies)' }
  };
  const OUTPUT_COSTS = {
    'P2PKH': 34, 'P2SH': 32, 'P2WPKH': 31, 'P2WSH': 43, 'P2TR': 43, 'OP_RETURN(80)': 92
  };

  function estimate(inputs, outputs, feeRate) {
    let base = 4 + 4, wit = 0, anySegwit = false;
    base += ENC.varIntSize(inputs.reduce((a, i) => a + i.count, 0));
    base += ENC.varIntSize(outputs.reduce((a, o) => a + o.count, 0));
    for (const i of inputs) {
      const c = INPUT_COSTS[i.type];
      if (!c) continue;
      base += c.base * i.count;
      wit += c.wit * i.count;
      if (c.wit) anySegwit = true;
      else wit += 1 * i.count;               // empty witness marker for legacy inputs in a segwit tx
    }
    for (const o of outputs) base += (OUTPUT_COSTS[o.type] || 34) * o.count;
    const marker = anySegwit ? 2 : 0;
    if (!anySegwit) wit = 0;
    const total = base + marker + wit;
    const weight = base * 4 + marker + wit;
    const vsize = Math.ceil(weight / 4);
    return {
      base, total, weight, vsize, segwit: anySegwit,
      fee: Math.ceil(vsize * (Number(feeRate) || 0)),
      discount: anySegwit ? Math.round((1 - vsize / total) * 100) : 0
    };
  }

  /* ======================================================================
     6. MERKLE ROOT (block-style, with the CVE-2012-2459 duplicate rule)
     ====================================================================== */

  function merkleRoot(txidsDisplayOrder) {
    if (!txidsDisplayOrder.length) return null;
    let level = txidsDisplayOrder.map(t => ENC.reverse(hexToBytes(t.trim())));
    const steps = [level.map(bytesToHex)];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const a = level[i], b = level[i + 1] || level[i];   // odd count duplicates the last hash
        next.push(BC.hash256(BC.cat(a, b)));
      }
      level = next;
      steps.push(level.map(bytesToHex));
    }
    return { root: bytesToHex(ENC.reverse(level[0])), internal: bytesToHex(level[0]), steps, levels: steps.length };
  }

  /* ======================================================================
     7. PUBLIC KEY TOOLKIT
     ====================================================================== */

  function pubkeyInfo(hex) {
    const b = hexToBytes(String(hex).trim());
    const out = { input: bytesToHex(b), length: b.length };
    const pt = BC.secp.decompressPoint(b);
    if (!pt) { out.valid = false; out.error = 'not a point on secp256k1 (or an unrecognised encoding)'; return out; }
    out.valid = true;
    out.form = b.length === 33 ? 'compressed' : b.length === 65 ? 'uncompressed' : 'x-only (BIP340)';
    out.compressed = bytesToHex(BC.secp.serPoint(pt, true));
    out.uncompressed = bytesToHex(BC.secp.serPoint(pt, false));
    out.xOnly = bytesToHex(BC.secp.xOnly(pt));
    out.yParity = Number(pt.y & 1n);
    out.hash160 = bytesToHex(BC.hash160(hexToBytes(out.compressed)));
    out.hash160Uncompressed = bytesToHex(BC.hash160(hexToBytes(out.uncompressed)));
    out.sha256 = bytesToHex(BC.sha256(hexToBytes(out.compressed)));
    return out;
  }

  function scriptsForPubkey(hex, network) {
    const info = pubkeyInfo(hex);
    if (!info.valid) return { error: info.error };
    const comp = hexToBytes(info.compressed);
    const h160 = BC.hash160(comp);
    const xonly = hexToBytes(info.xOnly);
    const p2wpkh = S.p2wpkh(h160);
    const trOut = BC.taprootTweak(xonly, null);
    const rows = [
      ['P2PK',        S.p2pk(comp),            null],
      ['P2PKH',       S.p2pkh(h160),           null],
      ['P2WPKH',      p2wpkh,                  null],
      ['P2SH-P2WPKH', S.p2sh(BC.hash160(p2wpkh)), p2wpkh],
      ['P2TR (tweaked key path)', S.p2tr(trOut.outputKey), null]
    ];
    return {
      info,
      rows: rows.map(([label, script, redeem]) => ({
        label,
        script: bytesToHex(script),
        asm: S.toAsm(script),
        address: S.scriptToAddress(script, network) || '—',
        redeemScript: redeem ? bytesToHex(redeem) : null
      }))
    };
  }

  /* ======================================================================
     8. SCRIPT ANALYSER — limits, op counts, sigops
     ====================================================================== */

  function analyseScript(script) {
    const { ops, error } = S.parseScript(script);
    let opCount = 0, sigops = 0, pushBytes = 0, maxPush = 0, lastKeyCount = 0;
    const notes = [];
    for (const o of ops) {
      if (o.op > 0x60) opCount++;
      if (o.data) { pushBytes += o.data.length; maxPush = Math.max(maxPush, o.data.length); }
      if (o.op === 0xac || o.op === 0xad) sigops += 1;
      if (o.op === 0xae || o.op === 0xaf) sigops += lastKeyCount || 20;
      if (o.op >= 0x51 && o.op <= 0x60) lastKeyCount = o.op - 0x50; else if (!o.isPush) lastKeyCount = 0;
      if (!o.minimal) notes.push(`non-minimal push at byte ${o.offset}`);
      if (S.OP_CATEGORIES.disabled.includes(o.name)) notes.push(`${o.name} is disabled — the script always fails`);
      if (S.OP_CATEGORIES.reserved.includes(o.name) && o.name !== 'OP_RESERVED') notes.push(`${o.name} is reserved`);
      if (o.data && o.data.length > 520) notes.push(`push at byte ${o.offset} is ${o.data.length} bytes — over the 520-byte stack element limit`);
    }
    const depth = (() => {
      let d = 0, max = 0, bad = false;
      for (const o of ops) {
        if (o.op === 0x63 || o.op === 0x64) { d++; max = Math.max(max, d); }
        if (o.op === 0x68) { d--; if (d < 0) bad = true; }
      }
      if (d !== 0 || bad) notes.push('unbalanced OP_IF / OP_ENDIF');
      return max;
    })();

    return {
      size: script.length, opCount, sigops, pushBytes, maxPush, ifDepth: depth,
      parseError: error,
      overSizeLimit: script.length > 10000,
      overOpLimit: opCount > 201,
      p2shOverSize: script.length > 520,
      notes: [...new Set(notes)],
      type: S.classify(script).type,
      hash160: bytesToHex(BC.hash160(script)),
      sha256: bytesToHex(BC.sha256(script))
    };
  }

  /* ======================================================================
     9. SIGNER CODE GENERATION
     ====================================================================== */

  const CODE_LANGS = [
    { id: 'py-coincurve', label: 'Python · coincurve' },
    { id: 'py-ecdsa',     label: 'Python · ecdsa (pure)' },
    { id: 'py-btclib',    label: 'Python · python-bitcoinlib' },
    { id: 'js-noble',     label: 'JavaScript · @noble/curves' },
    { id: 'cli',          label: 'Bitcoin Core CLI' },
    { id: 'verify-py',    label: 'Python · verify only' }
  ];

  /** @param pkgs array of signing packages (from the Signing workspace) */
  function generateCode(lang, pkgs, extra = {}) {
    const p = pkgs[0] || {};
    const list = pkgs.filter(x => x.z);
    const zList = list.map(x => `    {"input": ${x.input}, "z": "${x.z}", "sighash": ${parseInt(x.sighashByte || '0x01', 16)}, "algorithm": "${x.algorithm}"},`).join('\n');

    switch (lang) {
      case 'py-coincurve': return `#!/usr/bin/env python3
"""
Sign digests exported from Bitcoin Transaction Workbench.

    pip install coincurve
    python sign.py > signatures.json

Paste signatures.json back into  Finalize -> Signing JSON.
The workbench never sees your private keys.
"""
import json
from coincurve import PrivateKey

# ---- fill these in ---------------------------------------------------------
PRIVATE_KEYS = {
    0: "REPLACE_WITH_32_BYTE_PRIVATE_KEY_HEX",   # key for input 0
}
# ---------------------------------------------------------------------------

DIGESTS = [
${zList || '    # no digests available — fill in the inputs first'}
]

out = []
for d in DIGESTS:
    idx = d["input"]
    if idx not in PRIVATE_KEYS:
        continue
    key = PrivateKey(bytes.fromhex(PRIVATE_KEYS[idx]))
    z = bytes.fromhex(d["z"])

    if d["algorithm"] == "schnorr":
        # BIP340: sign the 32-byte message directly
        sig = key.sign_schnorr(z)
        out.append({"input": idx, "schnorr": sig.hex(),
                    "pubkey": key.public_key.format().hex()[2:]})   # x-only
    else:
        # hasher=None signs the digest as-is; coincurve already produces low-S DER
        der = key.sign(z, hasher=None)
        out.append({"input": idx,
                    "der": der.hex() + format(d["sighash"], "02x"),
                    "pubkey": key.public_key.format().hex()})

print(json.dumps(out, indent=2))
`;

      case 'py-ecdsa': return `#!/usr/bin/env python3
"""
Sign digests exported from Bitcoin Transaction Workbench (pure-Python ECDSA).

    pip install ecdsa
    python sign.py > signatures.json

Emits r and s so you can inspect them; the workbench DER-encodes on import.
"""
import json, hashlib
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_strings_canonize

N = SECP256k1.order

PRIVATE_KEYS = {
    0: "REPLACE_WITH_32_BYTE_PRIVATE_KEY_HEX",
}

DIGESTS = [
${zList || '    # no digests available'}
]

out = []
for d in DIGESTS:
    idx = d["input"]
    if idx not in PRIVATE_KEYS:
        continue
    sk = SigningKey.from_string(bytes.fromhex(PRIVATE_KEYS[idx]), curve=SECP256k1)
    z = int(d["z"], 16)

    # sign the digest directly — do NOT hash it again
    r, s = sk.sign_number(z, entropy=None)
    if s > N // 2:                     # BIP146 low-S
        s = N - s

    out.append({
        "input":   idx,
        "r":       format(r, "064x"),
        "s":       format(s, "064x"),
        "sighash": d["sighash"],
        "pubkey":  sk.get_verifying_key().to_string("compressed").hex(),
    })

print(json.dumps(out, indent=2))
`;

      case 'py-btclib': return `#!/usr/bin/env python3
"""
Round-trip the workbench PSBT through python-bitcoinlib / bitcoinlib tooling.

    pip install python-bitcoinlib

This variant works from the PSBT rather than the raw digest, so the library
recomputes the sighash itself — a useful cross-check of the workbench.
"""
import base64
from bitcoin.core import CTransaction, x, lx, b2x
from bitcoin.core.script import CScript, SignatureHash, SIGHASH_ALL
from bitcoin.wallet import CBitcoinSecret
import bitcoin
bitcoin.SelectParams(${JSON.stringify(extra.network === 'mainnet' ? 'mainnet' : extra.network === 'regtest' ? 'regtest' : 'testnet')})

UNSIGNED_TX = "${p.unsignedTx || ''}"
INPUT_INDEX = ${p.input || 0}
SCRIPT_CODE = "${p.scriptCode || ''}"
AMOUNT      = ${p.amount || 0}
SECRET      = "REPLACE_WITH_WIF"

tx  = CTransaction.deserialize(x(UNSIGNED_TX))
key = CBitcoinSecret(SECRET)

sighash = SignatureHash(CScript(x(SCRIPT_CODE)), tx, INPUT_INDEX, SIGHASH_ALL${p.hashAlgorithm === 'bip143' ? ', amount=AMOUNT, sigversion=1' : ''})
print("library sighash :", b2x(sighash))
print("workbench z     : ${p.z || ''}")
assert b2x(sighash) == "${p.z || ''}", "sighash mismatch — investigate before signing"

sig = key.sign(sighash) + bytes([SIGHASH_ALL])
print('{"input": %d, "der": "%s", "pubkey": "%s"}' % (INPUT_INDEX, b2x(sig), b2x(key.pub)))
`;

      case 'js-noble': return `// Sign digests exported from Bitcoin Transaction Workbench.
//   npm i @noble/curves
//   node sign.mjs > signatures.json

import { secp256k1, schnorr } from '@noble/curves/secp256k1';

const PRIVATE_KEYS = {
  0: 'REPLACE_WITH_32_BYTE_PRIVATE_KEY_HEX',
};

const DIGESTS = [
${list.map(x => `  { input: ${x.input}, z: '${x.z}', sighash: ${parseInt(x.sighashByte || '0x01', 16)}, algorithm: '${x.algorithm}' },`).join('\n') || '  // no digests available'}
];

const hex = (b) => Buffer.from(b).toString('hex');
const out = [];

for (const d of DIGESTS) {
  const priv = PRIVATE_KEYS[d.input];
  if (!priv) continue;

  if (d.algorithm === 'schnorr') {
    const sig = schnorr.sign(d.z, priv);            // BIP340 over the 32-byte message
    out.push({ input: d.input, schnorr: hex(sig), pubkey: hex(schnorr.getPublicKey(priv)) });
  } else {
    const sig = secp256k1.sign(d.z, priv, { prehash: false });   // z is already the digest
    const der = sig.normalizeS().toDERHex();        // low-S, per BIP146
    out.push({
      input: d.input,
      der: der + d.sighash.toString(16).padStart(2, '0'),
      pubkey: hex(secp256k1.getPublicKey(priv, true)),
    });
  }
}

console.log(JSON.stringify(out, null, 2));
`;

      case 'cli': return `# Bitcoin Core workflow for this transaction (${extra.network || 'mainnet'})
# The workbench holds no RPC credentials and makes no network calls — run these yourself.

# 1. Inspect what you built
bitcoin-cli -${extra.network === 'mainnet' ? 'chain=main' : extra.network === 'regtest' ? 'regtest' : extra.network === 'signet' ? 'signet' : 'testnet'} decoderawtransaction "${p.unsignedTx || '<hex>'}"

# 2. Inspect the PSBT and see what is still missing
bitcoin-cli decodepsbt "${extra.psbt || '<psbt>'}"
bitcoin-cli analyzepsbt "${extra.psbt || '<psbt>'}"

# 3. Sign it with a loaded wallet
bitcoin-cli walletprocesspsbt "${extra.psbt || '<psbt>'}"

# 4. Finalize and extract — or bring the signed PSBT back into the workbench
bitcoin-cli finalizepsbt "<signed psbt>"

# 5. Dry-run acceptance before you broadcast anything
bitcoin-cli testmempoolaccept '["<final hex>"]'

# 6. Broadcast
bitcoin-cli sendrawtransaction "<final hex>"

# --- alternative: sign a raw transaction with explicit prevouts ---
bitcoin-cli signrawtransactionwithkey "${p.unsignedTx || '<hex>'}" \\
  '["<WIF>"]' \\
  '[{"txid":"${p.txid || '<txid>'}","vout":${p.vout || 0},"scriptPubKey":"${p.scriptPubKey || '<spk>'}","amount":${p.amount ? (Number(p.amount) / 1e8).toFixed(8) : '0.00000000'}}]'
`;

      case 'verify-py': return `#!/usr/bin/env python3
"""
Verify a signature against the digest the workbench computed —
without ever loading a private key.

    pip install coincurve
"""
from coincurve import PublicKey
from coincurve.ecdsa import deserialize_recoverable  # noqa: F401  (import check)

Z      = bytes.fromhex("${p.z || ''}")
PUBKEY = bytes.fromhex("REPLACE_WITH_PUBLIC_KEY_HEX")
DER    = bytes.fromhex("REPLACE_WITH_DER_SIGNATURE_HEX")   # drop the trailing sighash byte

pk = PublicKey(PUBKEY)
print("valid:", pk.verify(DER, Z, hasher=None))

# Schnorr / taproot instead:
# from coincurve import PublicKeyXOnly
# print("valid:", PublicKeyXOnly(bytes.fromhex(XONLY)).verify(bytes.fromhex(SIG64), Z))
`;
      default: return '';
    }
  }

  global.TOOLS = {
    descChecksum, descVerify, descriptorFor, DESC_TEMPLATES,
    decodeXKey, XKEY_VERSIONS,
    buildTapTree, taprootOutput, controlBlock,
    UNITS, convertUnits, convertBase,
    locktimeInfo, dateToLocktime, encodeSequence, decodeSequence, humanDuration,
    INPUT_COSTS, OUTPUT_COSTS, estimate,
    merkleRoot, pubkeyInfo, scriptsForPubkey, analyseScript,
    CODE_LANGS, generateCode
  };
})(window);
