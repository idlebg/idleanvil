/* ============================================================================
   validate.js — structural / consensus / policy checks + input finalization
   Nothing here blocks construction: everything is reported, never enforced.
   Exposes: window.VALIDATE, window.FINALIZE
   ========================================================================== */
(function (global) {
  'use strict';
  const { hexToBytes, bytesToHex, Writer } = ENC;
  const S = SCRIPT;

  const SEV = { VALID: 'valid', NONSTANDARD: 'nonstandard', INVALID: 'invalid', UNKNOWN: 'unknown', INFO: 'info' };

  const MAX_SCRIPT_SIZE = 10000;
  const MAX_STANDARD_TX_WEIGHT = 400000;
  const MAX_DATACARRIER_BYTES = 83;   // OP_RETURN + push opcodes + up to 80 payload bytes

  /**
   * Bitcoin Core's GetDustThreshold at the default 3 sat/vB dust relay fee:
   * 3 × (serialized output size + size of a typical input spending it —
   * 148 bytes legacy, 67 vbytes for witness programs).
   * Gives 546 P2PKH · 540 P2SH · 294 P2WPKH · 330 P2WSH/P2TR · 576 P2PK.
   */
  function dustThreshold(script) {
    const t = S.classify(script).type;
    if (t === 'OP_RETURN') return 0n;
    const witness = t === 'P2WPKH' || t === 'P2WSH' || t === 'P2TR' || t === 'WITNESS_UNKNOWN';
    const outSize = 8 + ENC.varIntSize(script.length) + script.length;
    return BigInt(3 * (outSize + (witness ? 67 : 148)));
  }

  /** Run every check. Returns { rows, worst, counts }. */
  function run(tx) {
    const rows = [];
    const add = (sev, title, detail, loc) => rows.push({ sev, title, detail, loc });

    /* ---- structure ---- */
    if (!tx.inputs.length) add(SEV.INVALID, 'No inputs', 'A transaction with zero inputs is rejected by consensus (except coinbase).', 'tx');
    if (!tx.outputs.length) add(SEV.INVALID, 'No outputs', 'A transaction must have at least one output.', 'tx');

    if (tx.version < 1 || tx.version > 3)
      add(SEV.NONSTANDARD, `Transaction version ${tx.version}`, 'Only versions 1–3 are relayed by default policy; other values are consensus-valid but will not propagate.', 'tx.version');
    if (tx.version < 2 && tx.inputs.some(i => !(i.sequence & 0x80000000)))
      add(SEV.INFO, 'Version 1 with a relative timelock', 'BIP68 relative timelocks only take effect for version ≥ 2.', 'tx.version');

    /* ---- inputs ---- */
    const seen = new Map();
    tx.inputs.forEach((inp, i) => {
      const loc = `input ${i}`;
      if (!/^[0-9a-fA-F]{64}$/.test((inp.txid || '').trim()))
        add(SEV.INVALID, `Input ${i}: previous TXID is not 32 bytes`, 'A txid must be exactly 64 hex characters.', loc);
      const key = `${inp.txid}:${inp.vout}`;
      if (seen.has(key)) add(SEV.INVALID, `Input ${i} duplicates input ${seen.get(key)}`, `Both spend ${key}. Consensus rejects duplicate outpoints.`, loc);
      else seen.set(key, i);

      if (!inp.scriptPubKey)
        add(SEV.UNKNOWN, `Input ${i}: no prevout scriptPubKey`, 'Without it the spend type, scriptCode and signature hash cannot be derived.', loc);
      if (!BigInt(inp.amount || 0))
        add(SEV.UNKNOWN, `Input ${i}: prevout amount is zero`, 'Segwit and taproot signature hashes commit to the amount; the fee calculation also depends on it.', loc);

      if (inp.scriptPubKey) {
        const spk = safeHex(inp.scriptPubKey);
        if (spk) {
          const c = S.classify(spk);
          if (c.type === 'P2SH' && !inp.redeemScript)
            add(SEV.UNKNOWN, `Input ${i}: P2SH without a redeemScript`, 'The redeemScript is required to build the scriptCode and to finalize.', loc);
          if (c.type === 'P2WSH' && !inp.witnessScript)
            add(SEV.UNKNOWN, `Input ${i}: P2WSH without a witnessScript`, 'The witnessScript is required to build the scriptCode and to finalize.', loc);
          if (c.type === 'P2TR' && inp.algorithm !== 'schnorr')
            add(SEV.INVALID, `Input ${i}: taproot input set to ECDSA`, 'Taproot spends require Schnorr signatures (BIP340).', loc);
          if (c.type === 'P2SH' && inp.redeemScript) {
            const rs = safeHex(inp.redeemScript);
            if (rs && bytesToHex(BC.hash160(rs)) !== bytesToHex(c.hash))
              add(SEV.INVALID, `Input ${i}: redeemScript does not match the P2SH hash`, `HASH160(redeemScript) = ${bytesToHex(BC.hash160(rs))}, scriptPubKey expects ${bytesToHex(c.hash)}.`, loc);
          }
          if (c.type === 'P2WSH' && inp.witnessScript) {
            const ws = safeHex(inp.witnessScript);
            if (ws && bytesToHex(BC.sha256(ws)) !== bytesToHex(c.program))
              add(SEV.INVALID, `Input ${i}: witnessScript does not match the P2WSH program`, `SHA256(witnessScript) = ${bytesToHex(BC.sha256(ws))}, scriptPubKey expects ${bytesToHex(c.program)}.`, loc);
          }
          if (c.type === 'P2TR' && inp.taproot && inp.taproot.internalKey) {
            try {
              const t = BC.taprootTweak(hexToBytes(inp.taproot.internalKey),
                inp.taproot.merkleRoot ? hexToBytes(inp.taproot.merkleRoot) : null);
              if (bytesToHex(t.outputKey) !== bytesToHex(c.program))
                add(SEV.INVALID, `Input ${i}: taproot output key mismatch`, `Tweaking the internal key gives ${bytesToHex(t.outputKey)}, but the scriptPubKey commits to ${bytesToHex(c.program)}.`, loc);
            } catch (e) { add(SEV.UNKNOWN, `Input ${i}: taproot tweak failed`, e.message, loc); }
          }
        }
      }

      const ss = safeHex(inp.scriptSig);
      if (ss && ss.length > 1650)
        add(SEV.NONSTANDARD, `Input ${i}: scriptSig is ${ss.length} bytes`, 'Policy limits scriptSig to 1650 bytes.', loc);
      if (ss && ss.length) {
        const { ops, error } = S.parseScript(ss);
        if (error) add(SEV.INVALID, `Input ${i}: scriptSig does not parse`, error, loc);
        else if (ops.some(o => !o.isPush))
          add(SEV.NONSTANDARD, `Input ${i}: scriptSig contains non-push opcodes`, 'Policy requires scriptSig to be push-only (this is also a consensus rule for P2SH).', loc);
        for (const o of ops) if (!o.minimal) {
          add(SEV.NONSTANDARD, `Input ${i}: non-minimal push in scriptSig at byte ${o.offset}`, 'Policy requires minimal push encodings.', loc);
          break;
        }
      }

      for (const ps of (inp.partialSigs || [])) {
        const sig = safeHex(ps.signature);
        if (!sig) continue;
        const d = BC.derDecode(sig);
        if (!d.ok) add(SEV.INVALID, `Input ${i}: signature is not valid DER`, d.error, loc);
        else {
          if (!d.strictDER) add(SEV.NONSTANDARD, `Input ${i}: signature is not strict DER`, d.issues.join('; '), loc);
          if (!d.lowS) add(SEV.NONSTANDARD, `Input ${i}: high-S signature`, `BIP62/BIP146 require the low-S form. N − s = ${bytesToHex(d.sComplement)}.`, loc);
          if (d.sighash === null) add(SEV.INVALID, `Input ${i}: signature has no sighash byte`, 'Script signatures must be followed by a one-byte sighash flag.', loc);
        }
      }

      const st = SIGHASH.effectiveType(inp);
      const base = st & 0x1f;
      const spkForSt = safeHex(inp.scriptPubKey);
      const isTaprootIn = !!(spkForSt && S.classify(spkForSt).type === 'P2TR') || inp.spendType === 'p2tr';
      if (isTaprootIn && !SIGHASH.isValidTaprootType(st))
        add(SEV.INVALID, `Input ${i}: sighash byte 0x${st.toString(16).padStart(2, '0')} is invalid for taproot`, 'BIP341 defines only 0x00–0x03 and 0x81–0x83 — Schnorr signature validation fails outright with any other byte.', loc);
      else if (!isTaprootIn && (base === 0 || base > 3 || (st & ~0x9f)))
        add(SEV.NONSTANDARD, `Input ${i}: unusual sighash byte 0x${st.toString(16).padStart(2, '0')}`, 'Policy accepts only 0x01–0x03 / 0x81–0x83 for ECDSA inputs (0x00 exists only for taproot).', loc);
      if (SIGHASH.isSingle(st) && i >= tx.outputs.length) {
        const spk = safeHex(inp.scriptPubKey);
        const isTr = spk && S.classify(spk).type === 'P2TR';
        add(isTr ? SEV.INVALID : SEV.NONSTANDARD,
          `Input ${i}: SIGHASH_SINGLE with no output at index ${i}`,
          isTr ? 'Taproot rejects this outright.'
               : 'The legacy algorithm signs the constant 1 — a well-known footgun that lets anyone reuse the signature.', loc);
      }
    });

    /* ---- outputs ---- */
    let opReturnCount = 0;
    tx.outputs.forEach((out, i) => {
      const loc = `output ${i}`;
      const r = TX.resolveOutput(out, tx.network);
      if (r.error) { add(SEV.INVALID, `Output ${i}: ${r.error}`, 'The scriptPubKey could not be built.', loc); return; }
      const spk = r.script;
      if (!spk.length) { add(SEV.INVALID, `Output ${i}: empty scriptPubKey`, 'An empty output script is unspendable and non-standard.', loc); return; }

      const c = S.classify(spk);
      const amt = BigInt(out.amount || 0);

      if (amt < 0n) add(SEV.INVALID, `Output ${i}: negative amount`, 'Output values must be ≥ 0.', loc);
      if (amt > 2100000000000000n) add(SEV.INVALID, `Output ${i}: amount exceeds 21 M BTC`, 'Consensus caps any single value at MAX_MONEY.', loc);

      if (c.type === 'OP_RETURN') {
        opReturnCount++;
        if (amt > 0n) add(SEV.NONSTANDARD, `Output ${i}: OP_RETURN carries ${amt} sat`, 'Burning value in a data output is legal but pointless and non-standard for relay.', loc);
        if (spk.length > MAX_DATACARRIER_BYTES)
          add(SEV.NONSTANDARD, `Output ${i}: OP_RETURN script is ${spk.length} bytes (${c.dataLen} B payload)`, `Default relay policy caps the data carrier at ${MAX_DATACARRIER_BYTES} script bytes — 80 bytes of payload. It is consensus-valid but most nodes will not forward it.`, loc);
        if (!c.standard && spk.length <= MAX_DATACARRIER_BYTES)
          add(SEV.NONSTANDARD, `Output ${i}: OP_RETURN contains non-push opcodes`, 'The data carrier must be push-only to be standard.', loc);
      } else if (amt === 0n) {
        add(SEV.NONSTANDARD, `Output ${i}: zero value`, 'A zero-value non-OP_RETURN output is below dust and will not relay.', loc);
      } else {
        const dust = dustThreshold(spk);
        if (amt < dust) add(SEV.NONSTANDARD, `Output ${i}: dust (${amt} sat < ${dust} sat)`, `Outputs below the ${c.type} dust threshold are not relayed.`, loc);
      }

      if (c.type === 'NONSTANDARD')
        add(SEV.NONSTANDARD, `Output ${i}: non-standard script`, `Script does not match a known template: ${S.toAsm(spk).slice(0, 140)}`, loc);
      if (c.type === 'WITNESS_UNKNOWN')
        add(SEV.NONSTANDARD, `Output ${i}: unknown witness version ${c.version}`, 'Anyone-can-spend under current rules; reserved for future soft forks.', loc);
      if (c.type === 'MULTISIG' && c.n > 3)
        add(SEV.NONSTANDARD, `Output ${i}: bare ${c.m}-of-${c.n} multisig`, 'Bare multisig is only standard up to 3 keys — use P2SH or P2WSH instead.', loc);
      if (spk.length > MAX_SCRIPT_SIZE)
        add(SEV.INVALID, `Output ${i}: script is ${spk.length} bytes`, `The consensus limit is ${MAX_SCRIPT_SIZE} bytes.`, loc);
      const parsed = S.parseScript(spk);
      if (parsed.error) add(SEV.INVALID, `Output ${i}: script does not parse`, parsed.error, loc);
    });

    if (opReturnCount > 1)
      add(SEV.NONSTANDARD, `${opReturnCount} OP_RETURN outputs`, 'Default policy relays at most one data-carrier output per transaction.', 'tx');

    /* ---- economics ---- */
    const m = TX.measure(tx);
    if (tx.inputs.every(i => BigInt(i.amount || 0) > 0n)) {
      if (m.fee < 0n)
        add(SEV.INVALID, `Outputs exceed inputs by ${ENC.groupNum(-m.fee)} sat`, 'The transaction spends more than it takes in.', 'tx');
      else if (m.fee === 0n)
        add(SEV.NONSTANDARD, 'Zero fee', 'Will not be relayed or mined without a package/CPFP parent.', 'tx');
      else if (m.feeRate < 1)
        add(SEV.NONSTANDARD, `Fee rate ${m.feeRate.toFixed(3)} sat/vB`, 'Below the default 1 sat/vB minimum relay fee.', 'tx');
      else if (m.feeRate > 1000)
        add(SEV.INFO, `Fee rate ${m.feeRate.toFixed(1)} sat/vB`, 'That is unusually high — check the amounts.', 'tx');
    }
    if (m.weight > MAX_STANDARD_TX_WEIGHT)
      add(SEV.NONSTANDARD, `Weight ${ENC.groupNum(m.weight)} WU`, `Policy limits standard transactions to ${ENC.groupNum(MAX_STANDARD_TX_WEIGHT)} WU.`, 'tx');
    if (m.base < 65)
      add(SEV.NONSTANDARD, `Non-witness size ${m.base} bytes`, 'Relay policy rejects transactions whose non-witness serialization is under 65 bytes (protection against CVE-2017-12842 / 64-byte transactions).', 'tx');

    /* ---- locktime coherence ---- */
    if (tx.locktime > 0 && tx.inputs.every(i => (i.sequence >>> 0) === 0xffffffff))
      add(SEV.INFO, 'nLockTime is set but every sequence is 0xffffffff', 'A final sequence on all inputs disables nLockTime entirely.', 'tx.locktime');
    if (tx.inputs.some(i => (i.sequence >>> 0) < 0xfffffffe))
      add(SEV.INFO, 'Signals opt-in RBF (BIP125)', 'At least one input has a sequence below 0xfffffffe.', 'tx');

    if (!rows.length) add(SEV.VALID, 'No issues found', 'The transaction is structurally sound and matches standard policy.', 'tx');

    const counts = { invalid: 0, nonstandard: 0, unknown: 0, info: 0, valid: 0 };
    for (const r of rows) counts[r.sev]++;
    const worst = counts.invalid ? SEV.INVALID : counts.nonstandard ? SEV.NONSTANDARD : counts.unknown ? SEV.UNKNOWN : SEV.VALID;
    return { rows, worst, counts, measure: m };
  }

  function safeHex(h) {
    try { return h ? hexToBytes(h) : null; } catch (e) { return null; }
  }

  /* ======================================================================
     FINALIZE — turn collected signatures into scriptSig / witness
     ====================================================================== */

  /**
   * Build the final unlocking data for one input from its collected signatures.
   * Returns { scriptSig, witness, ok, note }.
   */
  function finalizeInput(inp) {
    const spk = safeHex(inp.scriptPubKey) || new Uint8Array(0);
    const redeem = safeHex(inp.redeemScript);
    const witScript = safeHex(inp.witnessScript);
    const cls = S.classify(spk);
    const sigs = (inp.partialSigs || []).filter(s => s.signature);
    const hex = bytesToHex;

    const need = (what) => ({ ok: false, note: `needs ${what}`, scriptSig: '', witness: [] });

    switch (cls.type) {
      case 'P2PK': {
        if (!sigs.length) return need('one signature');
        return { ok: true, scriptSig: hex(S.pushData(hexToBytes(sigs[0].signature))), witness: [], note: '<sig>' };
      }
      case 'P2PKH': {
        if (!sigs.length) return need('one signature');
        const s = sigs[0];
        if (!s.pubkey) return need('the matching public key');
        return {
          ok: true, witness: [],
          scriptSig: hex(BC.cat(S.pushData(hexToBytes(s.signature)), S.pushData(hexToBytes(s.pubkey)))),
          note: '<sig> <pubkey>'
        };
      }
      case 'P2WPKH': {
        if (!sigs.length) return need('one signature');
        const s = sigs[0];
        if (!s.pubkey) return need('the matching public key');
        return { ok: true, scriptSig: '', witness: [s.signature, s.pubkey], note: 'witness: <sig> <pubkey>' };
      }
      case 'P2TR': {
        if (inp.taproot && inp.taproot.path === 'script') {
          const tss = (inp.tapScriptSigs || []).filter(t => t.signature);
          if (!tss.length) return need('a tapscript signature');
          if (!inp.taproot.leafScript || !inp.taproot.controlBlock) return need('the leaf script and control block');
          const stack = tapscriptStack(safeHex(inp.taproot.leafScript), tss);
          return {
            ok: true, scriptSig: '',
            witness: [...stack, inp.taproot.leafScript, inp.taproot.controlBlock],
            note: 'witness: <sig-or-empty per key, reverse key order> <leaf script> <control block>'
          };
        }
        if (!inp.tapKeySig) return need('a taproot key-path signature');
        return { ok: true, scriptSig: '', witness: [inp.tapKeySig], note: 'witness: <schnorr sig>' };
      }
      case 'P2WSH': {
        if (!witScript) return need('the witnessScript');
        const stack = orderedStack(witScript, sigs);
        if (!stack) return need('enough signatures for the witness script');
        /* CHECKMULTISIG pops one extra element; BIP147 requires it to be empty */
        const dummy = S.classify(witScript).type === 'MULTISIG' ? [''] : [];
        return { ok: true, scriptSig: '', witness: [...dummy, ...stack, hex(witScript)], note: 'witness: [<empty>] <stack…> <witnessScript>' };
      }
      case 'P2SH': {
        if (!redeem) return need('the redeemScript');
        const rc = S.classify(redeem);
        if (rc.type === 'P2WPKH') {
          if (!sigs.length) return need('one signature');
          const s = sigs[0];
          if (!s.pubkey) return need('the matching public key');
          return {
            ok: true, scriptSig: hex(S.pushData(redeem)), witness: [s.signature, s.pubkey],
            note: 'scriptSig: <redeemScript>; witness: <sig> <pubkey>'
          };
        }
        if (rc.type === 'P2WSH') {
          if (!witScript) return need('the witnessScript');
          const stack = orderedStack(witScript, sigs);
          if (!stack) return need('enough signatures for the witness script');
          const dummy = S.classify(witScript).type === 'MULTISIG' ? [''] : [];
          return {
            ok: true, scriptSig: hex(S.pushData(redeem)), witness: [...dummy, ...stack, hex(witScript)],
            note: 'scriptSig: <redeemScript>; witness: [<empty>] <stack…> <witnessScript>'
          };
        }
        const stack = orderedStack(redeem, sigs);
        if (!stack) return need('enough signatures for the redeem script');
        const w = new Writer();
        const rcls = S.classify(redeem);
        if (rcls.type === 'MULTISIG') w.u8(0x00);      // CHECKMULTISIG off-by-one
        for (const item of stack) w.push(S.pushData(hexToBytes(item)));
        w.push(S.pushData(redeem));
        return { ok: true, scriptSig: hex(w.bytes()), witness: [], note: 'scriptSig: [OP_0] <sigs…> <redeemScript>' };
      }
      case 'MULTISIG': {
        const stack = orderedStack(spk, sigs);
        if (!stack) return need(`${cls.m} signature(s)`);
        const w = new Writer();
        w.u8(0x00);
        for (const item of stack) w.push(S.pushData(hexToBytes(item)));
        return { ok: true, scriptSig: hex(w.bytes()), witness: [], note: 'scriptSig: OP_0 <sigs…>' };
      }
      default:
        return { ok: false, note: 'unknown script type — set the scriptSig and witness manually', scriptSig: '', witness: [] };
    }
  }

  /** For a multisig script, order the signatures to match the pubkey order. */
  function orderedStack(script, sigs) {
    const c = S.classify(script);
    if (c.type === 'MULTISIG') {
      const ordered = [];
      for (const pk of c.pubkeys) {
        const hit = sigs.find(s => s.pubkey && s.pubkey.toLowerCase() === bytesToHex(pk));
        if (hit) ordered.push(hit.signature);
      }
      if (ordered.length < c.m) return null;
      return ordered.slice(0, c.m);   // exactly m, in key order
    }
    if (!sigs.length) return null;
    return sigs.map(s => s.signature);
  }

  /**
   * Order tapscript signatures for a CHECKSIG/CHECKSIGADD leaf.
   * Execution checks keys in script order, consuming from the top of the stack,
   * so the witness carries one item per key in REVERSE key order, with an empty
   * item for every key that does not sign (BIP342 / multi_a semantics).
   * Falls back to the raw signature list when the keys cannot be recovered.
   */
  function tapscriptStack(leafScript, tss) {
    if (leafScript) {
      const parsed = S.parseScript(leafScript);
      const keys = [];
      if (!parsed.error) {
        for (let i = 0; i + 1 < parsed.ops.length; i++) {
          const o = parsed.ops[i], nxt = parsed.ops[i + 1].op;
          if (o.data && o.data.length === 32 && (nxt === 0xac || nxt === 0xad || nxt === 0xba))
            keys.push(bytesToHex(o.data));
        }
      }
      const byKey = new Map();
      for (const t of tss) if (t.pubkey) byKey.set(t.pubkey.toLowerCase(), t.signature);
      if (keys.length && keys.some(k => byKey.has(k)))
        return keys.map(k => byKey.get(k) || '').reverse();
    }
    return tss.map(t => t.signature);
  }

  /** Finalize every input that can be finalized. Returns a per-input report. */
  function finalizeAll(tx) {
    const report = [];
    for (let i = 0; i < tx.inputs.length; i++) {
      const inp = tx.inputs[i];
      if (inp.manualScriptSig || inp.manualWitness) {
        report.push({ index: i, ok: true, note: 'kept the manually specified unlocking data', manual: true });
        continue;
      }
      const r = finalizeInput(inp);
      /* empty items are kept — they are meaningful on a witness stack
         (CHECKMULTISIG dummy, unused CHECKSIGADD slots, IF-branch selectors) */
      if (r.ok) { inp.scriptSig = r.scriptSig; inp.witness = r.witness.slice(); }
      report.push({ index: i, ...r });
    }
    return report;
  }

  global.VALIDATE = { SEV, run, dustThreshold };
  global.FINALIZE = { finalizeInput, finalizeAll };
})(window);
