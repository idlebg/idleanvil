/* ============================================================================
   sighash.js — legacy, BIP143 (segwit v0) and BIP341 (taproot) signature hashes
   Every function returns the full preimage as well as the digest, so the
   signing workspace can show exactly what gets hashed.
   Exposes: window.SIGHASH
   ========================================================================== */
(function (global) {
  'use strict';
  const { Writer, hexToBytes, bytesToHex, reverse } = ENC;
  const S = SCRIPT;

  const ALL = 0x01, NONE = 0x02, SINGLE = 0x03, DEFAULT = 0x00, ANYONECANPAY = 0x80;

  const TYPES = [
    { v: 0x00, name: 'DEFAULT',              taprootOnly: true,  label: 'SIGHASH_DEFAULT (0x00)' },
    { v: 0x01, name: 'ALL',                  taprootOnly: false, label: 'SIGHASH_ALL (0x01)' },
    { v: 0x02, name: 'NONE',                 taprootOnly: false, label: 'SIGHASH_NONE (0x02)' },
    { v: 0x03, name: 'SINGLE',               taprootOnly: false, label: 'SIGHASH_SINGLE (0x03)' },
    { v: 0x81, name: 'ALL|ANYONECANPAY',     taprootOnly: false, label: 'SIGHASH_ALL | ANYONECANPAY (0x81)' },
    { v: 0x82, name: 'NONE|ANYONECANPAY',    taprootOnly: false, label: 'SIGHASH_NONE | ANYONECANPAY (0x82)' },
    { v: 0x83, name: 'SINGLE|ANYONECANPAY',  taprootOnly: false, label: 'SIGHASH_SINGLE | ANYONECANPAY (0x83)' }
  ];

  /** The only sighash bytes BIP341 defines — anything else is consensus-invalid for taproot. */
  const isValidTaprootType = (v) => TYPES.some(t => t.v === v);

  const nameOf = (v) => {
    const t = TYPES.find(t => t.v === v);
    if (t) return t.name;
    const base = v & 0x1f, acp = v & ANYONECANPAY;
    const b = base === 1 ? 'ALL' : base === 2 ? 'NONE' : base === 3 ? 'SINGLE' : `UNKNOWN(0x${base.toString(16)})`;
    return b + (acp ? '|ANYONECANPAY' : '');
  };

  const isNone   = (t) => (t & 0x1f) === NONE;
  const isSingle = (t) => (t & 0x1f) === SINGLE;
  const isAcp    = (t) => (t & ANYONECANPAY) !== 0;

  const ZERO32 = new Uint8Array(32);
  const ONE32 = (() => { const b = new Uint8Array(32); b[0] = 1; return b; })();

  /* ------------------------------------------------------------ legacy */

  /**
   * Pre-segwit signature hash (the original algorithm, SIGHASH_SINGLE bug included).
   */
  function legacy(tx, index, scriptCode, hashType) {
    const inputs = tx.inputs, outputs = tx.outputs;
    scriptCode = S.stripCodeSeparators(scriptCode || new Uint8Array(0));

    if (isSingle(hashType) && index >= outputs.length) {
      return {
        preimage: null, digest: ONE32, sha256: null,
        note: 'SIGHASH_SINGLE with no matching output — the legacy algorithm returns the constant 1 ' +
              '(the "SIGHASH_SINGLE bug"). Signing this digest is dangerous.',
        bug: true
      };
    }

    const w = new Writer();
    w.i32(tx.version);

    const ins = isAcp(hashType) ? [inputs[index]] : inputs;
    w.varint(ins.length);
    for (let k = 0; k < ins.length; k++) {
      const inp = ins[k];
      const realIdx = isAcp(hashType) ? index : k;
      w.push(reverse(TX.padTxid(inp.txid)));
      w.u32(inp.vout >>> 0);
      if (realIdx === index) w.varslice(scriptCode);
      else w.varslice(new Uint8Array(0));
      const blank = (isNone(hashType) || isSingle(hashType)) && realIdx !== index;
      w.u32(blank ? 0 : (inp.sequence >>> 0));
    }

    let outs;
    if (isNone(hashType)) outs = [];
    else if (isSingle(hashType)) outs = outputs.slice(0, index + 1);
    else outs = outputs;

    w.varint(outs.length);
    for (let k = 0; k < outs.length; k++) {
      if (isSingle(hashType) && k < index) { w.u64(-1n); w.varslice(new Uint8Array(0)); }
      else {
        w.u64(BigInt(outs[k].amount || 0));
        w.varslice(TX.resolveOutput(outs[k], tx.network).script);
      }
    }
    w.u32(tx.locktime >>> 0);
    w.u32(hashType >>> 0);

    const preimage = w.bytes();
    const first = BC.sha256(preimage);
    return { preimage, sha256: first, digest: BC.sha256(first), algo: 'legacy' };
  }

  /* ------------------------------------------------------------ BIP143 */

  function bip143(tx, index, scriptCode, amount, hashType) {
    const inputs = tx.inputs, outputs = tx.outputs;
    const acp = isAcp(hashType), none = isNone(hashType), single = isSingle(hashType);

    const prevoutsW = new Writer(), seqW = new Writer(), outsW = new Writer();
    for (const inp of inputs) { prevoutsW.push(reverse(TX.padTxid(inp.txid))).u32(inp.vout >>> 0); }
    for (const inp of inputs) seqW.u32(inp.sequence >>> 0);
    for (const out of outputs) { outsW.u64(BigInt(out.amount || 0)).varslice(TX.resolveOutput(out, tx.network).script); }

    const hashPrevouts = acp ? ZERO32 : BC.hash256(prevoutsW.bytes());
    const hashSequence = (acp || none || single) ? ZERO32 : BC.hash256(seqW.bytes());
    let hashOutputs;
    if (!none && !single) hashOutputs = BC.hash256(outsW.bytes());
    else if (single && index < outputs.length) {
      const o = new Writer();
      o.u64(BigInt(outputs[index].amount || 0)).varslice(TX.resolveOutput(outputs[index], tx.network).script);
      hashOutputs = BC.hash256(o.bytes());
    } else hashOutputs = ZERO32;

    const inp = inputs[index];
    const w = new Writer();
    w.i32(tx.version);
    w.push(hashPrevouts);
    w.push(hashSequence);
    w.push(reverse(TX.padTxid(inp.txid))).u32(inp.vout >>> 0);
    w.varslice(scriptCode || new Uint8Array(0));
    w.u64(BigInt(amount || 0));
    w.u32(inp.sequence >>> 0);
    w.push(hashOutputs);
    w.u32(tx.locktime >>> 0);
    w.u32(hashType >>> 0);

    const preimage = w.bytes();
    const first = BC.sha256(preimage);
    return {
      preimage, sha256: first, digest: BC.sha256(first), algo: 'bip143',
      parts: { hashPrevouts, hashSequence, hashOutputs },
      note: single && index >= outputs.length
        ? 'SIGHASH_SINGLE with no matching output — BIP143 uses a zero hashOutputs instead of the legacy bug.'
        : ''
    };
  }

  /* ------------------------------------------------------------ BIP341 */

  /**
   * @param opts { leafHash: Uint8Array|null, annex: Uint8Array|null, codesepPos: number }
   */
  function bip341(tx, index, hashType, opts = {}) {
    const inputs = tx.inputs, outputs = tx.outputs;
    const acp = isAcp(hashType), none = isNone(hashType), single = isSingle(hashType);
    if (!isValidTaprootType(hashType))
      throw new Error(`sighash byte 0x${hashType.toString(16).padStart(2, '0')} is invalid for taproot — ` +
        'BIP341 defines only 0x00–0x03 and 0x81–0x83; any other byte fails signature validation outright');

    const prevW = new Writer(), amtW = new Writer(), spkW = new Writer(), seqW = new Writer();
    for (const inp of inputs) {
      prevW.push(reverse(TX.padTxid(inp.txid))).u32(inp.vout >>> 0);
      amtW.u64(BigInt(inp.amount || 0));
      spkW.varslice(hexToBytes(inp.scriptPubKey || ''));
      seqW.u32(inp.sequence >>> 0);
    }
    const shaPrevouts = BC.sha256(prevW.bytes());
    const shaAmounts = BC.sha256(amtW.bytes());
    const shaScriptPubKeys = BC.sha256(spkW.bytes());
    const shaSequences = BC.sha256(seqW.bytes());

    const outW = new Writer();
    for (const out of outputs) outW.u64(BigInt(out.amount || 0)).varslice(TX.resolveOutput(out, tx.network).script);
    const shaOutputs = BC.sha256(outW.bytes());

    const annex = opts.annex && opts.annex.length ? opts.annex : null;
    const extFlag = opts.leafHash ? 1 : 0;
    const spendType = extFlag * 2 + (annex ? 1 : 0);

    const w = new Writer();
    w.u8(hashType & 0xff);
    w.i32(tx.version);
    w.u32(tx.locktime >>> 0);
    if (!acp) { w.push(shaPrevouts).push(shaAmounts).push(shaScriptPubKeys).push(shaSequences); }
    if (!none && !single) w.push(shaOutputs);
    w.u8(spendType);
    if (acp) {
      const inp = inputs[index];
      w.push(reverse(TX.padTxid(inp.txid))).u32(inp.vout >>> 0);
      w.u64(BigInt(inp.amount || 0));
      w.varslice(hexToBytes(inp.scriptPubKey || ''));
      w.u32(inp.sequence >>> 0);
    } else {
      w.u32(index);
    }
    if (annex) w.push(BC.sha256(new Writer().varslice(annex).bytes()));
    if (single) {
      if (index < outputs.length) {
        const o = new Writer();
        o.u64(BigInt(outputs[index].amount || 0)).varslice(TX.resolveOutput(outputs[index], tx.network).script);
        w.push(BC.sha256(o.bytes()));
      } else {
        throw new Error('SIGHASH_SINGLE requires an output at the same index as the input');
      }
    }
    if (opts.leafHash) {
      w.push(opts.leafHash);
      w.u8(0x00);                                     // key_version
      w.u32(opts.codesepPos === undefined ? 0xffffffff : opts.codesepPos);
    }

    const sigMsg = w.bytes();
    const full = BC.cat(new Uint8Array([0x00]), sigMsg);   // 0x00 sighash epoch
    return {
      preimage: full, sigMsg, digest: BC.taggedHash('TapSighash', full), algo: 'bip341',
      parts: { shaPrevouts, shaAmounts, shaScriptPubKeys, shaSequences, shaOutputs },
      spendType, extFlag
    };
  }

  /* -------------------------------------------------- unified entry point */

  /**
   * Compute the signature hash for input `index` of `tx`, choosing the
   * algorithm from the prevout script type. Returns a rich package.
   */
  function forInput(tx, index) {
    const inp = tx.inputs[index];
    if (!inp) throw new Error(`there is no input at index ${index}`);
    const spk = hexToBytes(inp.scriptPubKey || '');
    const cls = S.classify(spk);
    const hashType = effectiveType(inp);

    const pkg = {
      index, hashType, hashTypeName: nameOf(hashType),
      algorithm: inp.algorithm, scriptType: cls.type,
      warnings: [], scriptCode: null, leafHash: null
    };

    let isTaproot = cls.type === 'P2TR';
    if (inp.spendType === 'p2tr') isTaproot = true;
    if (inp.spendType && inp.spendType !== 'auto' && inp.spendType !== 'p2tr' && cls.type !== 'P2TR') isTaproot = false;

    if (isTaproot) {
      const tr = inp.taproot || {};
      let leafHash = null;
      if (tr.path === 'script') {
        if (!tr.leafScript) { pkg.warnings.push('script-path spend selected but no tapleaf script is set'); }
        else leafHash = BC.tapLeafHash(hexToBytes(tr.leafScript), Number(tr.leafVersion) || 0xc0);
      }
      if (tx.inputs.some(i => !i.scriptPubKey))
        pkg.warnings.push('taproot commits to every input scriptPubKey — fill in all prevout scripts');
      if (tx.inputs.some(i => !BigInt(i.amount || 0)))
        pkg.warnings.push('taproot commits to every input amount — fill in all prevout amounts');
      try {
        const res = bip341(tx, index, hashType, {
          leafHash,
          annex: tr.annex ? hexToBytes(tr.annex) : null,
          codesepPos: 0xffffffff
        });
        Object.assign(pkg, res);
        pkg.leafHash = leafHash;
        pkg.algorithmUsed = 'BIP341 / Schnorr (secp256k1 x-only)';
        if (inp.algorithm !== 'schnorr') pkg.warnings.push('taproot inputs must be signed with Schnorr, not ECDSA');
      } catch (e) { pkg.error = e.message; }
      return pkg;
    }

    const sc = S.deriveScriptCode(inp);
    pkg.scriptCode = sc.scriptCode;
    pkg.scriptCodeNote = sc.note;
    if (!sc.scriptCode) { pkg.error = sc.note; return pkg; }

    let segwit = sc.kind === 'bip143';
    if (inp.spendType === 'p2wpkh' || inp.spendType === 'p2wsh' ||
        inp.spendType === 'p2sh-p2wpkh' || inp.spendType === 'p2sh-p2wsh') segwit = true;
    if (inp.spendType === 'p2pkh' || inp.spendType === 'p2sh' || inp.spendType === 'p2pk') segwit = false;

    try {
      if (segwit) {
        if (!BigInt(inp.amount || 0)) pkg.warnings.push('BIP143 commits to the input amount — it is currently zero');
        Object.assign(pkg, bip143(tx, index, sc.scriptCode, BigInt(inp.amount || 0), hashType));
        pkg.algorithmUsed = 'BIP143 / ECDSA (segwit v0)';
      } else {
        Object.assign(pkg, legacy(tx, index, sc.scriptCode, hashType));
        pkg.algorithmUsed = 'Legacy / ECDSA';
        if (pkg.bug) pkg.warnings.push(pkg.note);
      }
      if (inp.algorithm === 'schnorr') pkg.warnings.push('Schnorr selected on a non-taproot input — signers expect ECDSA here');
    } catch (e) { pkg.error = e.message; }
    return pkg;
  }

  /** The sighash byte actually used for an input, honouring the forensic override. */
  function effectiveType(inp) {
    if (inp.sighashCustom !== '' && inp.sighashCustom !== null && inp.sighashCustom !== undefined) {
      const v = parseInt(String(inp.sighashCustom).replace(/^0x/i, ''), 16);
      if (!isNaN(v)) return v & 0xff;
    }
    let t = inp.sighashType & 0x1f;
    if (inp.sighashType === 0) t = 0;
    return t | (inp.sighashAnyoneCanPay ? ANYONECANPAY : 0);
  }

  /* ------------------------------------------------ commitment description */

  /** What a given sighash type commits to — drives the visualizer. */
  function commitment(hashType, algo) {
    const acp = isAcp(hashType), none = isNone(hashType), single = isSingle(hashType);
    const taproot = algo === 'bip341';
    return {
      version:      { on: true },
      locktime:     { on: true },
      thisInput:    { on: true },
      otherInputs:  { on: !acp, note: acp ? 'ANYONECANPAY removes every other input' : '' },
      inputAmounts: {
        /* taproot ACP still commits this input's amount directly in the SigMsg */
        on: algo !== 'legacy',
        partial: algo !== 'legacy' && (!taproot || acp),
        note: algo === 'legacy' ? 'the legacy algorithm never commits to amounts' :
              taproot ? (acp ? 'ANYONECANPAY commits to this input’s amount only' : 'taproot commits to every input amount')
                      : 'BIP143 commits to this input’s amount only'
      },
      inputScriptPubKeys: {
        on: taproot,
        partial: taproot && acp,
        note: !taproot ? 'only taproot commits to prevout scripts'
              : acp ? 'ANYONECANPAY commits to this input’s scriptPubKey only' : ''
      },
      sequences: {
        /* BIP341 includes sha_sequences whenever !ACP, even for NONE/SINGLE */
        on: taproot ? !acp : (!acp && !none && !single),
        note: taproot
          ? (acp ? 'ANYONECANPAY removes the other sequences' : (none || single) ? 'unlike legacy/BIP143, taproot keeps every sequence under NONE/SINGLE' : '')
          : (none || single) ? 'NONE/SINGLE blank the other sequences' : ''
      },
      outputs:      {
        on: !none, partial: single,
        note: none ? 'NONE commits to no outputs' : single ? 'SINGLE commits only to the matching output' : ''
      },
      scriptCode:   { on: !taproot, note: taproot ? 'replaced by the tapleaf hash for script paths' : '' },
      sighashByte:  { on: true }
    };
  }

  global.SIGHASH = {
    ALL, NONE, SINGLE, DEFAULT, ANYONECANPAY, TYPES,
    nameOf, isNone, isSingle, isAcp, isValidTaprootType, effectiveType,
    legacy, bip143, bip341, forInput, commitment
  };
})(window);
