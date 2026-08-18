/* btc-psbt.js — PSBT v0 (BIP 174) and PSBT v2 (BIP 370) with the Taproot fields of BIP 371.
   Requires btc-core.js and btc-tx.js. */
(function (g) {
  const B = g.BTC;
  const { toHex, fromHex, concat, rev, b64enc, b64dec, Writer, Reader, serializeTx, parseTx } = B;

  const MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

  const GLOBAL = {
    0x00: 'UNSIGNED_TX', 0x01: 'XPUB', 0x02: 'TX_VERSION', 0x03: 'FALLBACK_LOCKTIME',
    0x04: 'INPUT_COUNT', 0x05: 'OUTPUT_COUNT', 0x06: 'TX_MODIFIABLE', 0xfb: 'VERSION', 0xfc: 'PROPRIETARY'
  };
  const IN = {
    0x00: 'NON_WITNESS_UTXO', 0x01: 'WITNESS_UTXO', 0x02: 'PARTIAL_SIG', 0x03: 'SIGHASH_TYPE',
    0x04: 'REDEEM_SCRIPT', 0x05: 'WITNESS_SCRIPT', 0x06: 'BIP32_DERIVATION', 0x07: 'FINAL_SCRIPTSIG',
    0x08: 'FINAL_SCRIPTWITNESS', 0x09: 'POR_COMMITMENT', 0x0a: 'RIPEMD160', 0x0b: 'SHA256',
    0x0c: 'HASH160', 0x0d: 'HASH256', 0x0e: 'PREVIOUS_TXID', 0x0f: 'OUTPUT_INDEX',
    0x10: 'SEQUENCE', 0x11: 'REQUIRED_TIME_LOCKTIME', 0x12: 'REQUIRED_HEIGHT_LOCKTIME',
    0x13: 'TAP_KEY_SIG', 0x14: 'TAP_SCRIPT_SIG', 0x15: 'TAP_LEAF_SCRIPT',
    0x16: 'TAP_BIP32_DERIVATION', 0x17: 'TAP_INTERNAL_KEY', 0x18: 'TAP_MERKLE_ROOT', 0xfc: 'PROPRIETARY'
  };
  const OUT = {
    0x00: 'REDEEM_SCRIPT', 0x01: 'WITNESS_SCRIPT', 0x02: 'BIP32_DERIVATION', 0x03: 'AMOUNT',
    0x04: 'SCRIPT', 0x05: 'TAP_INTERNAL_KEY', 0x06: 'TAP_TREE', 0x07: 'TAP_BIP32_DERIVATION', 0xfc: 'PROPRIETARY'
  };

  const kv = (w, type, keyData, value) => { w.varslice(concat([new Uint8Array([type]), keyData || new Uint8Array(0)])); w.varslice(value); };

  /* craft: {version, locktime, inputs:[…], outputs:[…]} in the workbench's own shape */
  function buildPsbt(model, psbtVersion) {
    const w = new Writer();
    w.raw(MAGIC);
    const ins = model.inputs, outs = model.outputs;
    if (psbtVersion === 2) {
      kv(w, 0x02, null, new Writer().u32(model.version).bytes());
      kv(w, 0x03, null, new Writer().u32(model.locktime >>> 0).bytes());
      kv(w, 0x04, null, new Writer().varint(ins.length).bytes());
      kv(w, 0x05, null, new Writer().varint(outs.length).bytes());
      if (model.txModifiable != null) kv(w, 0x06, null, new Uint8Array([model.txModifiable & 0xff]));
      kv(w, 0xfb, null, new Writer().u32(2).bytes());
    } else {
      const unsigned = serializeTx({
        version: model.version, locktime: model.locktime,
        ins: ins.map((i) => ({ txid: i.txid, vout: i.vout, sequence: i.sequence, scriptSig: new Uint8Array(0), witness: [] })),
        outs: outs.map((o) => ({ value: o.value, script: o.script }))
      }, { witness: false }).bytes;
      kv(w, 0x00, null, unsigned);
    }
    w.u8(0x00);

    for (const i of ins) {
      if (psbtVersion === 2) {
        kv(w, 0x0e, null, rev(fromHex(i.txid || '00'.repeat(32))));
        kv(w, 0x0f, null, new Writer().u32(i.vout || 0).bytes());
        kv(w, 0x10, null, new Writer().u32(i.sequence >>> 0).bytes());
      }
      if (i.nonWitnessUtxo && i.nonWitnessUtxo.length) kv(w, 0x00, null, i.nonWitnessUtxo);
      if (i.witnessUtxo) kv(w, 0x01, null, concat([new Writer().u64(i.value || 0).bytes(), new Writer().varslice(i.script || new Uint8Array(0)).bytes()]));
      for (const ps of i.partialSigs || []) kv(w, 0x02, ps.pubkey, ps.signature);
      if (i.sighashType != null) kv(w, 0x03, null, new Writer().u32(i.sighashType).bytes());
      if (i.redeemScript && i.redeemScript.length) kv(w, 0x04, null, i.redeemScript);
      if (i.witnessScript && i.witnessScript.length) kv(w, 0x05, null, i.witnessScript);
      if (i.finalScriptSig && i.finalScriptSig.length) kv(w, 0x07, null, i.finalScriptSig);
      if (i.finalWitness && i.finalWitness.length) {
        const ww = new Writer(); ww.varint(i.finalWitness.length); i.finalWitness.forEach((it) => ww.varslice(it));
        kv(w, 0x08, null, ww.bytes());
      }
      if (i.tapKeySig && i.tapKeySig.length) kv(w, 0x13, null, i.tapKeySig);
      for (const ls of i.tapLeafScripts || []) kv(w, 0x15, ls.controlBlock, concat([ls.script, new Uint8Array([ls.leafVersion & 0xff])]));
      if (i.tapInternalKey && i.tapInternalKey.length === 32) kv(w, 0x17, null, i.tapInternalKey);
      if (i.tapMerkleRoot && i.tapMerkleRoot.length === 32) kv(w, 0x18, null, i.tapMerkleRoot);
      w.u8(0x00);
    }
    for (const o of outs) {
      if (psbtVersion === 2) {
        kv(w, 0x03, null, new Writer().u64(o.value || 0).bytes());
        kv(w, 0x04, null, o.script || new Uint8Array(0));
      }
      if (o.redeemScript && o.redeemScript.length) kv(w, 0x00, null, o.redeemScript);
      if (o.witnessScript && o.witnessScript.length) kv(w, 0x01, null, o.witnessScript);
      if (o.tapInternalKey && o.tapInternalKey.length === 32) kv(w, 0x05, null, o.tapInternalKey);
      w.u8(0x00);
    }
    const bytes = w.bytes();
    return { bytes: bytes, hex: toHex(bytes), base64: b64enc(bytes) };
  }

  function readMap(r) {
    const map = [];
    for (;;) {
      if (!r.left) throw new Error('PSBT ended before a map separator');
      const keyLen = r.varint();
      if (keyLen === 0) return map;
      const key = r.raw(keyLen);
      const value = r.varslice();
      map.push({ type: key[0], keyData: key.slice(1), value: value });
    }
  }
  function parsePsbt(input) {
    let bytes;
    const s = String(input || '').trim();
    if (!s) throw new Error('nothing to decode');
    if (/^[0-9a-fA-F\s]+$/.test(s) && s.replace(/\s/g, '').length % 2 === 0) bytes = fromHex(s);
    else bytes = b64dec(s);
    const r = new Reader(bytes);
    const magic = r.raw(5);
    if (toHex(magic) !== '70736274ff') throw new Error('missing PSBT magic 0x70736274ff');
    const global = readMap(r);
    let version = 0, inCount = null, outCount = null, unsignedTx = null;
    for (const e of global) {
      if (e.type === 0xfb) version = new Reader(e.value).u32();
      if (e.type === 0x04) inCount = new Reader(e.value).varint();
      if (e.type === 0x05) outCount = new Reader(e.value).varint();
      if (e.type === 0x00) unsignedTx = parseTx(e.value);
    }
    if (version === 0 && !unsignedTx) throw new Error('PSBT v0 without a global unsigned transaction');
    const nIn = version >= 2 ? inCount : unsignedTx.ins.length;
    const nOut = version >= 2 ? outCount : unsignedTx.outs.length;
    if (nIn == null || nOut == null) throw new Error('PSBT v2 without input/output counts');
    const inputs = [], outputs = [];
    for (let i = 0; i < nIn; i++) inputs.push(readMap(r));
    for (let i = 0; i < nOut; i++) outputs.push(readMap(r));
    return {
      version: version, global: global, inputs: inputs, outputs: outputs, unsignedTx: unsignedTx,
      trailing: r.left ? toHex(r.raw(r.left)) : null, bytes: bytes
    };
  }

  function describe(psbt) {
    const dumpEntry = (e, names) => ({
      type: '0x' + e.type.toString(16).padStart(2, '0'),
      name: names[e.type] || 'UNKNOWN',
      keyData: toHex(e.keyData),
      value: toHex(e.value),
      length: e.value.length
    });
    const summary = {
      version: psbt.version,
      global: psbt.global.map((e) => dumpEntry(e, GLOBAL)),
      inputs: psbt.inputs.map((m) => m.map((e) => dumpEntry(e, IN))),
      outputs: psbt.outputs.map((m) => m.map((e) => dumpEntry(e, OUT))),
      signatures: []
    };
    psbt.inputs.forEach((m, i) => {
      const sigs = m.filter((e) => e.type === 0x02 || e.type === 0x13 || e.type === 0x14);
      const finals = m.filter((e) => e.type === 0x07 || e.type === 0x08);
      summary.signatures.push({
        index: i,
        partial: sigs.map((e) => ({ kind: e.type === 0x02 ? 'ECDSA' : e.type === 0x13 ? 'Schnorr (key path)' : 'Schnorr (script path)', pubkey: toHex(e.keyData), signature: toHex(e.value) })),
        finalised: finals.length > 0
      });
    });
    return summary;
  }

  /* Merge signatures from an imported PSBT into the crafting model */
  function extractSignatures(psbt) {
    return psbt.inputs.map((m) => {
      const out = { partialSigs: [], tapKeySig: null, tapScriptSigs: [], finalScriptSig: null, finalWitness: null, sighashType: null };
      for (const e of m) {
        if (e.type === 0x02) out.partialSigs.push({ pubkey: toHex(e.keyData), signature: toHex(e.value) });
        if (e.type === 0x03) out.sighashType = new Reader(e.value).u32();
        if (e.type === 0x13) out.tapKeySig = toHex(e.value);
        if (e.type === 0x14) out.tapScriptSigs.push({ key: toHex(e.keyData), signature: toHex(e.value) });
        if (e.type === 0x07) out.finalScriptSig = toHex(e.value);
        if (e.type === 0x08) {
          const r = new Reader(e.value); const n = r.varint(); const st = [];
          for (let i = 0; i < n; i++) st.push(toHex(r.varslice()));
          out.finalWitness = st;
        }
      }
      return out;
    });
  }

  Object.assign(B, { PSBT_GLOBAL: GLOBAL, PSBT_IN: IN, PSBT_OUT: OUT, buildPsbt, parsePsbt, describePsbt: describe, extractSignatures });
})(typeof window !== 'undefined' ? window : globalThis);
