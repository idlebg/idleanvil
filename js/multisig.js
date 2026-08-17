/* ============================================================================
   multisig.js — build m-of-n multisig from PUBLIC KEYS ONLY.
   Produces every script variant at once so the effect of any edit is visible
   immediately. No private keys, no derivation of secrets.
   Exposes: window.MULTISIG
   ========================================================================== */
(function (global) {
  'use strict';
  const { bytesToHex, hexToBytes, Writer } = ENC;
  const S = SCRIPT;

  /* BIP341's suggested NUMS point: a key nobody knows the discrete log of, so a
     taproot output built on it has no usable key path. */
  const NUMS = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

  const LIMITS = {
    CHECKMULTISIG_KEYS: 20,      // consensus limit on OP_CHECKMULTISIG
    P2SH_SCRIPT: 520,            // a P2SH redeemScript is a stack item
    P2WSH_SCRIPT_POLICY: 3600,   // standardness
    SCRIPT_CONSENSUS: 10000,
    BARE_STANDARD_N: 3           // bare multisig is only relayed up to 3 keys
  };

  /* ------------------------------------------------------------- one key */

  function analyseKey(raw, index) {
    const out = { index, raw: String(raw || '').trim(), valid: false };
    const hex = out.raw.replace(/[\s:]/g, '').toLowerCase();
    out.hex = hex;
    if (!hex) { out.error = 'empty'; return out; }
    if (!/^[0-9a-f]*$/.test(hex)) { out.error = 'contains non-hex characters'; return out; }
    if (hex.length % 2) { out.error = `odd length (${hex.length} hex characters)`; return out; }

    const bytes = hexToBytes(hex);
    out.length = bytes.length;
    if (![32, 33, 65].includes(bytes.length)) {
      out.error = `${bytes.length} bytes — expected 33 (compressed), 65 (uncompressed) or 32 (x-only)`;
      return out;
    }
    const pt = BC.secp.decompressPoint(bytes);
    if (!pt) { out.error = 'not a point on secp256k1'; return out; }

    out.valid = true;
    out.form = bytes.length === 33 ? 'compressed' : bytes.length === 65 ? 'uncompressed' : 'x-only';
    out.compressed = bytesToHex(BC.secp.serPoint(pt, true));
    out.uncompressed = bytesToHex(BC.secp.serPoint(pt, false));
    out.xonly = bytesToHex(BC.secp.xOnly(pt));
    out.parity = Number(pt.y & 1n);
    out.hash160 = bytesToHex(BC.hash160(bytes));
    return out;
  }

  /* -------------------------------------------------------- the builder */

  /**
   * @param {object} cfg
   *   keys    [{ raw, enabled, useUncompressed }]
   *   m       required signatures
   *   sort    'entered' | 'bip67'
   *   network network id
   *   leafVersion  taproot leaf version (default 0xc0)
   *   internalKey  taproot internal key (default the NUMS point)
   */
  function build(cfg) {
    const network = cfg.network || 'mainnet';
    const sort = cfg.sort || 'entered';
    const analysed = (cfg.keys || []).map((k, i) => {
      const a = analyseKey(k.raw, i);
      a.enabled = k.enabled !== false;
      a.useUncompressed = !!k.useUncompressed;
      /*
       * What actually goes into the script. A key pasted in uncompressed form
       * stays uncompressed — silently compressing it would produce a different
       * script, a different address, and funds nobody expected. The flag is an
       * explicit override for keys entered compressed. An x-only key is lifted
       * to its even-Y compressed form, which is what CHECKMULTISIG needs.
       */
      if (a.valid) {
        a.usesUncompressed = a.useUncompressed || a.form === 'uncompressed';
        a.scriptBytes = hexToBytes(a.usesUncompressed ? a.uncompressed : a.compressed);
      }
      return a;
    });

    const usable = analysed.filter(a => a.enabled && a.valid);
    let ordered = usable.slice();
    if (sort === 'bip67') {
      ordered.sort((x, y) => {
        const a = x.scriptBytes, b = y.scriptBytes;
        const n = Math.min(a.length, b.length);
        for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
        return a.length - b.length;
      });
    }
    ordered.forEach((k, i) => { k.finalPosition = i; });

    const n = ordered.length;
    const m = Math.max(1, Math.min(Number(cfg.m || 1), Math.max(1, n)));

    const result = {
      network, sort, m, n,
      keys: analysed,
      ordered,
      warnings: [],
      errors: [],
      variants: [],
      complete: n > 0 && m >= 1 && m <= n
    };

    /* -------- problems worth reporting before anything is built -------- */
    const invalid = analysed.filter(a => a.enabled && !a.valid && a.raw);
    invalid.forEach(a => result.errors.push(`Key ${a.index + 1}: ${a.error}`));
    if (!n) { result.errors.push('No usable public keys yet.'); return result; }
    if (Number(cfg.m || 1) > n) result.warnings.push(`m was ${cfg.m} but there are only ${n} keys — clamped to ${m}.`);

    const seen = new Map();
    ordered.forEach(k => {
      const key = bytesToHex(k.scriptBytes);
      if (seen.has(key)) result.warnings.push(`Key ${k.index + 1} duplicates key ${seen.get(key) + 1} — the same signer would be counted twice.`);
      else seen.set(key, k.index);
    });
    if (ordered.some(k => k.usesUncompressed))
      result.warnings.push('Uncompressed keys are legal but non-standard inside P2WSH and P2SH-P2WSH, and make every script larger.');
    if (n > LIMITS.CHECKMULTISIG_KEYS)
      result.errors.push(`OP_CHECKMULTISIG accepts at most ${LIMITS.CHECKMULTISIG_KEYS} keys; you have ${n}. Only the taproot variant can go higher.`);
    if (sort === 'bip67' && ordered.some((k, i) => k !== usable[i]))
      result.reordered = true;

    /* -------- the core script -------- */
    let core = null;
    if (n <= LIMITS.CHECKMULTISIG_KEYS) {
      try { core = S.multisig(m, ordered.map(k => k.scriptBytes)); }
      catch (e) { result.errors.push(e.message); }
    }

    const addr = (script) => S.scriptToAddress(script, network);
    const push = (v) => { result.variants.push(v); return v; };

    /* -------- bare multisig -------- */
    if (core) {
      push({
        id: 'bare', label: 'Bare multisig', hint: 'the script sits directly in the output',
        spk: core,
        address: null,
        addressNote: 'bare multisig has no address encoding — it can only be referenced by its script',
        size: core.length,
        standard: n <= LIMITS.BARE_STANDARD_N,
        notes: n > LIMITS.BARE_STANDARD_N
          ? [`non-standard above ${LIMITS.BARE_STANDARD_N} keys — will not relay`]
          : ['relayed, but everyone can see the policy and every key on chain'],
        spend: 'scriptSig: OP_0 <sig>×m'
      });

      /* -------- P2SH -------- */
      const p2shSpk = S.p2sh(BC.hash160(core));
      push({
        id: 'p2sh', label: 'P2SH', hint: 'legacy wrapped — starts with 3 (or 2 on test chains)',
        spk: p2shSpk, redeemScript: core, address: addr(p2shSpk),
        size: p2shSpk.length, innerSize: core.length,
        standard: core.length <= LIMITS.P2SH_SCRIPT,
        notes: core.length > LIMITS.P2SH_SCRIPT
          ? [`redeemScript is ${core.length} B — over the ${LIMITS.P2SH_SCRIPT} B stack-item limit, so this is unspendable`]
          : [`redeemScript ${core.length} B of the ${LIMITS.P2SH_SCRIPT} B budget`],
        spend: 'scriptSig: OP_0 <sig>×m <redeemScript>'
      });

      /* -------- P2WSH -------- */
      const p2wshSpk = S.p2wsh(BC.sha256(core));
      push({
        id: 'p2wsh', label: 'P2WSH', hint: 'native segwit — cheapest to spend',
        spk: p2wshSpk, witnessScript: core, address: addr(p2wshSpk),
        size: p2wshSpk.length, innerSize: core.length,
        standard: core.length <= LIMITS.P2WSH_SCRIPT_POLICY && !ordered.some(k => k.scriptBytes.length === 65),
        notes: [
          `witnessScript ${core.length} B of the ${LIMITS.P2WSH_SCRIPT_POLICY} B policy limit`,
          ...(ordered.some(k => k.scriptBytes.length === 65) ? ['uncompressed keys are non-standard inside P2WSH'] : [])
        ],
        spend: 'witness: <empty> <sig>×m <witnessScript>'
      });

      /* -------- P2SH-P2WSH -------- */
      const nested = S.p2wsh(BC.sha256(core));
      const nestedSpk = S.p2sh(BC.hash160(nested));
      push({
        id: 'p2sh-p2wsh', label: 'P2SH-P2WSH', hint: 'segwit hidden behind a legacy address',
        spk: nestedSpk, redeemScript: nested, witnessScript: core, address: addr(nestedSpk),
        size: nestedSpk.length, innerSize: core.length,
        standard: core.length <= LIMITS.P2WSH_SCRIPT_POLICY,
        notes: ['compatible with wallets that cannot send to bech32'],
        spend: 'scriptSig: <redeemScript>; witness: <empty> <sig>×m <witnessScript>'
      });
    }

    /* -------- P2TR: k-of-n via OP_CHECKSIGADD in a single tapleaf -------- */
    try {
      const leafVersion = Number(cfg.leafVersion) || 0xc0;
      const internalHex = (cfg.internalKey || NUMS).trim();
      const w = new Writer();
      ordered.forEach((k, i) => {
        w.push(S.pushData(hexToBytes(k.xonly)));
        w.u8(i === 0 ? 0xac : 0xba);            // CHECKSIG, then CHECKSIGADD
      });
      w.push(S.pushData(S.scriptNum(BigInt(m))));
      w.u8(0x9c);                                // OP_NUMEQUAL
      const leaf = w.bytes();
      const leafHash = BC.tapLeafHash(leaf, leafVersion);
      const tweak = BC.taprootTweak(hexToBytes(internalHex), leafHash);
      const trSpk = S.p2tr(tweak.outputKey);
      const controlBlock = BC.cat(new Uint8Array([(leafVersion & 0xfe) | tweak.parity]), hexToBytes(internalHex));

      push({
        id: 'p2tr', label: 'P2TR', hint: 'taproot k-of-n with OP_CHECKSIGADD',
        spk: trSpk, address: addr(trSpk),
        tapLeaf: leaf, leafHash, controlBlock, outputKey: tweak.outputKey,
        internalKey: internalHex, merkleRoot: leafHash, parity: tweak.parity,
        size: trSpk.length, innerSize: leaf.length,
        standard: true,
        notes: [
          internalHex === NUMS
            ? 'internal key is the NUMS point, so there is no key-path escape hatch'
            : 'a key-path spend bypasses the script entirely — make sure that is intended',
          'x-only keys; no 20-key CHECKMULTISIG limit applies',
          'signatures are positional: supply an empty item for each key that does not sign'
        ],
        spend: 'witness: <sig-or-empty>×n <tapleaf> <control block>'
      });
    } catch (e) {
      result.warnings.push('Taproot variant unavailable: ' + e.message);
    }

    /* -------- descriptors -------- */
    const keyList = ordered.map(k => k.usesUncompressed ? k.uncompressed : k.compressed).join(',');
    const fn = sort === 'bip67' ? 'sortedmulti' : 'multi';
    const ck = (s) => { try { return TOOLS.descChecksum(s); } catch (e) { return s; } };
    result.descriptors = {
      bare:         ck(`${fn}(${m},${keyList})`),
      p2sh:         ck(`sh(${fn}(${m},${keyList}))`),
      p2wsh:        ck(`wsh(${fn}(${m},${keyList}))`),
      'p2sh-p2wsh': ck(`sh(wsh(${fn}(${m},${keyList})))`),
      p2tr:         ck(`tr(${cfg.internalKey || NUMS},multi_a(${m},${ordered.map(k => k.xonly).join(',')}))`)
    };

    /* -------- spending cost, per variant -------- */
    const sigLen = 72, xSig = 64;
    for (const v of result.variants) {
      if (v.id === 'bare') v.spendCost = { scriptSig: 1 + m * (1 + sigLen), witness: 0 };
      else if (v.id === 'p2sh') v.spendCost = { scriptSig: 1 + m * (1 + sigLen) + 2 + core.length, witness: 0 };
      else if (v.id === 'p2wsh') v.spendCost = { scriptSig: 0, witness: 1 + 1 + m * (1 + sigLen) + 3 + core.length };
      else if (v.id === 'p2sh-p2wsh') v.spendCost = { scriptSig: 1 + 34, witness: 1 + 1 + m * (1 + sigLen) + 3 + core.length };
      else if (v.id === 'p2tr') v.spendCost = { scriptSig: 0, witness: 1 + n * (1 + xSig) + 2 + v.innerSize + 1 + 33 };
      if (v.spendCost) {
        v.spendVbytes = Math.ceil((36 + 4 + (v.spendCost.scriptSig ? 1 + v.spendCost.scriptSig : 1)) +
          (v.spendCost.witness ? v.spendCost.witness / 4 : 0));
      }
    }

    return result;
  }

  /** Character-level diff, for showing what an edit did to an address. */
  function diffString(before, after) {
    if (!before || !after) return { chars: (after || '').split('').map(c => ({ c, changed: false })), changed: 0, total: (after || '').length };
    const chars = [];
    let changed = 0;
    const len = Math.max(before.length, after.length);
    for (let i = 0; i < after.length; i++) {
      const same = i < before.length && before[i] === after[i];
      if (!same) changed++;
      chars.push({ c: after[i], changed: !same });
    }
    return { chars, changed, total: after.length, lengthChanged: before.length !== after.length, before, after, span: len };
  }

  /** Flip a single hex digit in a key — the fastest way to see the avalanche. */
  function flipDigit(hex, position, to) {
    const chars = hex.split('');
    const pos = position === undefined
      ? 2 + Math.floor(Math.random() * (chars.length - 2))   // never the 02/03 prefix
      : position;
    const digits = '0123456789abcdef';
    const cur = chars[pos];
    let next = to;
    if (next === undefined) {
      do { next = digits[Math.floor(Math.random() * 16)]; } while (next === cur);
    }
    chars[pos] = next;
    return { hex: chars.join(''), position: pos, from: cur, to: next };
  }

  /** n valid example keys: 8·G, 15·G, 22·G … — real curve points, no secrets implied. */
  function exampleKeys(count) {
    const out = [];
    for (let i = 1; i <= count; i++) {
      const pt = BC.secp.ptMul(BigInt(i * 7 + 1), BC.secp.G);
      out.push(bytesToHex(BC.secp.serPoint(pt, true)));
    }
    return out;
  }

  global.MULTISIG = { NUMS, LIMITS, analyseKey, build, diffString, flipDigit, exampleKeys };
})(window);
