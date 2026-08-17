/* ============================================================================
   psbt.js — PSBT v0 (BIP174) and v2 (BIP370) build / parse / describe
   Exposes: window.PSBT
   ========================================================================== */
(function (global) {
  'use strict';
  const { Writer, Reader, hexToBytes, bytesToHex, reverse, bytesToBase64, base64ToBytes } = ENC;
  const S = SCRIPT;

  const MAGIC = new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]);

  const GLOBAL = {
    UNSIGNED_TX: 0x00, XPUB: 0x01, TX_VERSION: 0x02, FALLBACK_LOCKTIME: 0x03,
    INPUT_COUNT: 0x04, OUTPUT_COUNT: 0x05, TX_MODIFIABLE: 0x06, VERSION: 0xfb, PROPRIETARY: 0xfc
  };
  const IN = {
    NON_WITNESS_UTXO: 0x00, WITNESS_UTXO: 0x01, PARTIAL_SIG: 0x02, SIGHASH_TYPE: 0x03,
    REDEEM_SCRIPT: 0x04, WITNESS_SCRIPT: 0x05, BIP32_DERIVATION: 0x06,
    FINAL_SCRIPTSIG: 0x07, FINAL_SCRIPTWITNESS: 0x08, POR_COMMITMENT: 0x09,
    RIPEMD160: 0x0a, SHA256: 0x0b, HASH160: 0x0c, HASH256: 0x0d,
    PREVIOUS_TXID: 0x0e, OUTPUT_INDEX: 0x0f, SEQUENCE: 0x10,
    REQUIRED_TIME_LOCKTIME: 0x11, REQUIRED_HEIGHT_LOCKTIME: 0x12,
    TAP_KEY_SIG: 0x13, TAP_SCRIPT_SIG: 0x14, TAP_LEAF_SCRIPT: 0x15,
    TAP_BIP32_DERIVATION: 0x16, TAP_INTERNAL_KEY: 0x17, TAP_MERKLE_ROOT: 0x18
  };
  const OUT = {
    REDEEM_SCRIPT: 0x00, WITNESS_SCRIPT: 0x01, BIP32_DERIVATION: 0x02,
    AMOUNT: 0x03, SCRIPT: 0x04, TAP_INTERNAL_KEY: 0x05, TAP_TREE: 0x06, TAP_BIP32_DERIVATION: 0x07
  };

  const GLOBAL_NAME = inv(GLOBAL), IN_NAME = inv(IN), OUT_NAME = inv(OUT);
  function inv(o) { const m = {}; for (const [k, v] of Object.entries(o)) m[v] = k; return m; }

  /* ----------------------------------------------------------- low level */

  function kv(w, type, keyData, value) {
    const key = keyData && keyData.length
      ? BC.cat(new Uint8Array([type]), keyData)
      : new Uint8Array([type]);
    w.varslice(key);
    w.varslice(value);
  }

  function u32le(v) { const w = new Writer(); w.u32(v >>> 0); return w.bytes(); }
  function u64le(v) { const w = new Writer(); w.u64(BigInt(v)); return w.bytes(); }

  /* -------------------------------------------------------------- build */

  /**
   * Build a PSBT from the workbench transaction model.
   * @param {object} tx
   * @param {number} version 0 or 2
   */
  function build(tx, version) {
    version = Number(version) === 2 ? 2 : 0;
    const w = new Writer();
    w.push(MAGIC);

    /* ------- global map ------- */
    if (version === 0) {
      const unsigned = TX.serialize(tx, { final: false, forceWitness: false });
      kv(w, GLOBAL.UNSIGNED_TX, null, unsigned);
    } else {
      kv(w, GLOBAL.TX_VERSION, null, u32le(tx.version));
      kv(w, GLOBAL.FALLBACK_LOCKTIME, null, u32le(tx.locktime));
      kv(w, GLOBAL.INPUT_COUNT, null, ENC.encodeVarInt(tx.inputs.length));
      kv(w, GLOBAL.OUTPUT_COUNT, null, ENC.encodeVarInt(tx.outputs.length));
      kv(w, GLOBAL.TX_MODIFIABLE, null, new Uint8Array([tx.psbtModifiable === undefined ? 0x03 : tx.psbtModifiable]));
      kv(w, GLOBAL.VERSION, null, u32le(2));
    }
    w.u8(0x00);

    /* ------- inputs ------- */
    for (const inp of tx.inputs) {
      const spk = hexToBytes(inp.scriptPubKey || '');
      const cls = S.classify(spk);
      const redeem = inp.redeemScript ? hexToBytes(inp.redeemScript) : null;
      const isSegwit = ['P2WPKH', 'P2WSH', 'P2TR'].includes(cls.type) ||
        (redeem && ['P2WPKH', 'P2WSH'].includes(S.classify(redeem).type));

      if (inp.prevTxHex) kv(w, IN.NON_WITNESS_UTXO, null, hexToBytes(inp.prevTxHex));
      if (isSegwit && spk.length) {
        const u = new Writer();
        u.u64(BigInt(inp.amount || 0)).varslice(spk);
        kv(w, IN.WITNESS_UTXO, null, u.bytes());
      }
      for (const ps of (inp.partialSigs || [])) {
        if (ps.pubkey && ps.signature) kv(w, IN.PARTIAL_SIG, hexToBytes(ps.pubkey), hexToBytes(ps.signature));
      }
      const st = SIGHASH.effectiveType(inp);
      if (st !== 0 || cls.type !== 'P2TR') kv(w, IN.SIGHASH_TYPE, null, u32le(st));
      if (redeem) kv(w, IN.REDEEM_SCRIPT, null, redeem);
      if (inp.witnessScript) kv(w, IN.WITNESS_SCRIPT, null, hexToBytes(inp.witnessScript));
      for (const d of (inp.bip32 || [])) {
        if (!d.pubkey) continue;
        kv(w, IN.BIP32_DERIVATION, hexToBytes(d.pubkey), encodeDerivation(d.fingerprint, d.path));
      }
      if (version === 2) {
        kv(w, IN.PREVIOUS_TXID, null, reverse(TX.padTxid(inp.txid)));
        kv(w, IN.OUTPUT_INDEX, null, u32le(inp.vout));
        kv(w, IN.SEQUENCE, null, u32le(inp.sequence));
      }
      const tr = inp.taproot || {};
      if (inp.tapKeySig) kv(w, IN.TAP_KEY_SIG, null, hexToBytes(inp.tapKeySig));
      for (const tss of (inp.tapScriptSigs || [])) {
        if (tss.pubkey && tss.leafHash && tss.signature)
          kv(w, IN.TAP_SCRIPT_SIG, BC.cat(hexToBytes(tss.pubkey), hexToBytes(tss.leafHash)), hexToBytes(tss.signature));
      }
      if (tr.leafScript) {
        const cb = tr.controlBlock ? hexToBytes(tr.controlBlock) : new Uint8Array(0);
        kv(w, IN.TAP_LEAF_SCRIPT, cb,
          BC.cat(hexToBytes(tr.leafScript), new Uint8Array([Number(tr.leafVersion) || 0xc0])));
      }
      if (tr.internalKey) kv(w, IN.TAP_INTERNAL_KEY, null, hexToBytes(tr.internalKey));
      if (tr.merkleRoot) kv(w, IN.TAP_MERKLE_ROOT, null, hexToBytes(tr.merkleRoot));
      if (inp.scriptSig && inp.manualScriptSig) kv(w, IN.FINAL_SCRIPTSIG, null, hexToBytes(inp.scriptSig));
      if ((inp.witness || []).length && inp.manualWitness) {
        const ww = new Writer();
        ww.varint(inp.witness.length);
        for (const it of inp.witness) ww.varslice(hexToBytes(it || ''));
        kv(w, IN.FINAL_SCRIPTWITNESS, null, ww.bytes());
      }
      w.u8(0x00);
    }

    /* ------- outputs ------- */
    for (const out of tx.outputs) {
      const r = TX.resolveOutput(out, tx.network);
      if (out.redeemScript) kv(w, OUT.REDEEM_SCRIPT, null, hexToBytes(out.redeemScript));
      if (out.witnessScript) kv(w, OUT.WITNESS_SCRIPT, null, hexToBytes(out.witnessScript));
      if (r.sub && r.sub.redeemScript) kv(w, OUT.REDEEM_SCRIPT, null, r.sub.redeemScript);
      if (r.sub && r.sub.witnessScript) kv(w, OUT.WITNESS_SCRIPT, null, r.sub.witnessScript);
      if (version === 2) {
        kv(w, OUT.AMOUNT, null, u64le(out.amount || 0));
        kv(w, OUT.SCRIPT, null, r.script);
      }
      w.u8(0x00);
    }
    return w.bytes();
  }

  function encodeDerivation(fingerprint, path) {
    const w = new Writer();
    const fp = hexToBytes((fingerprint || '00000000').padStart(8, '0').slice(0, 8));
    w.push(fp);
    const parts = String(path || '').replace(/^m\/?/, '').split('/').filter(Boolean);
    for (const p of parts) {
      const hard = /['h]$/i.test(p);
      const n = parseInt(p.replace(/['h]$/i, ''), 10) || 0;
      w.u32(hard ? (n | 0x80000000) >>> 0 : n);
    }
    return w.bytes();
  }
  function decodeDerivation(bytes) {
    if (bytes.length < 4) return { fingerprint: '', path: '' };
    const fp = bytesToHex(bytes.slice(0, 4));
    let path = 'm';
    for (let i = 4; i + 3 < bytes.length; i += 4) {
      const v = new DataView(bytes.buffer, bytes.byteOffset + i, 4).getUint32(0, true);
      path += '/' + (v & 0x80000000 ? `${v & 0x7fffffff}'` : v);
    }
    return { fingerprint: fp, path };
  }

  /* -------------------------------------------------------------- parse */

  function readMap(r) {
    const map = [];
    for (;;) {
      if (r.eof) throw new Error('PSBT ended without a map separator');
      const keyLen = r.varint();
      if (keyLen === 0) break;
      const key = r.take(keyLen);
      const value = r.varslice();
      map.push({ type: key[0], keyData: key.slice(1), value });
    }
    return map;
  }

  function parse(input) {
    let bytes;
    if (input instanceof Uint8Array) bytes = input;
    else {
      const s = String(input).trim();
      if (/^70736274ff/i.test(s.replace(/\s/g, ''))) bytes = hexToBytes(s);
      else bytes = base64ToBytes(s);
    }
    for (let i = 0; i < 5; i++) if (bytes[i] !== MAGIC[i]) throw new Error('missing PSBT magic bytes (70 73 62 74 ff)');
    const r = new Reader(bytes);
    r.take(5);

    const globals = readMap(r);
    const g = index(globals);

    let version = 0;
    if (g[GLOBAL.VERSION]) version = new DataView(g[GLOBAL.VERSION].value.buffer, g[GLOBAL.VERSION].value.byteOffset, 4).getUint32(0, true);

    let unsigned = null, nIn = 0, nOut = 0;
    if (g[GLOBAL.UNSIGNED_TX]) {
      unsigned = TX.decodeRaw(g[GLOBAL.UNSIGNED_TX].value);
      nIn = unsigned.inputs.length; nOut = unsigned.outputs.length;
    } else {
      if (!g[GLOBAL.INPUT_COUNT]) throw new Error('PSBT has neither an unsigned transaction nor an input count');
      nIn = new Reader(g[GLOBAL.INPUT_COUNT].value).varint();
      nOut = new Reader(g[GLOBAL.OUTPUT_COUNT].value).varint();
      version = version || 2;
    }

    const inputs = [], outputs = [];
    for (let i = 0; i < nIn; i++) inputs.push(readMap(r));
    for (let i = 0; i < nOut; i++) outputs.push(readMap(r));

    return { version, globals, inputs, outputs, unsigned, bytes, trailing: r.left };
  }

  function index(map) {
    const m = {};
    for (const e of map) if (m[e.type] === undefined) m[e.type] = e;
    return m;
  }
  const all = (map, type) => map.filter(e => e.type === type);

  /* --------------------------------------------------- describe (for UI) */

  function describe(psbt) {
    const out = { version: psbt.version, global: [], inputs: [], outputs: [], summary: {} };

    for (const e of psbt.globals) {
      out.global.push(field(GLOBAL_NAME[e.type] || `UNKNOWN_0x${e.type.toString(16)}`, e, (v) => {
        if (e.type === GLOBAL.UNSIGNED_TX) {
          const d = TX.decodeRaw(v);
          return `${d.inputs.length} in / ${d.outputs.length} out · txid ${d.txid}`;
        }
        if (e.type === GLOBAL.TX_VERSION || e.type === GLOBAL.FALLBACK_LOCKTIME || e.type === GLOBAL.VERSION)
          return String(new DataView(v.buffer, v.byteOffset, 4).getUint32(0, true));
        if (e.type === GLOBAL.INPUT_COUNT || e.type === GLOBAL.OUTPUT_COUNT) return String(new Reader(v).varint());
        if (e.type === GLOBAL.TX_MODIFIABLE) {
          const f = v[0];
          const flags = [];
          if (f & 1) flags.push('inputs modifiable');
          if (f & 2) flags.push('outputs modifiable');
          if (f & 4) flags.push('has SIGHASH_SINGLE');
          return `0x${f.toString(16).padStart(2, '0')} — ${flags.join(', ') || 'none'}`;
        }
        return bytesToHex(v);
      }));
    }

    let signedCount = 0;
    psbt.inputs.forEach((map, i) => {
      const rows = [];
      let hasSig = false;
      for (const e of map) {
        const name = IN_NAME[e.type] || `UNKNOWN_0x${e.type.toString(16)}`;
        if (e.type === IN.PARTIAL_SIG || e.type === IN.TAP_KEY_SIG || e.type === IN.TAP_SCRIPT_SIG) hasSig = true;
        rows.push(field(name, e, (v) => {
          switch (e.type) {
            case IN.WITNESS_UTXO: {
              const rr = new Reader(v);
              const amt = rr.u64(); const spk = rr.varslice();
              return `${ENC.groupNum(amt)} sat → ${S.classify(spk).type} ${bytesToHex(spk)}`;
            }
            case IN.NON_WITNESS_UTXO: {
              const d = TX.decodeRaw(v);
              return `full previous tx, txid ${d.txid}`;
            }
            case IN.SIGHASH_TYPE: {
              const t = new DataView(v.buffer, v.byteOffset, 4).getUint32(0, true);
              return `0x${t.toString(16).padStart(2, '0')} — ${SIGHASH.nameOf(t)}`;
            }
            case IN.PARTIAL_SIG: {
              const d = BC.derDecode(v);
              return `sig for ${bytesToHex(e.keyData).slice(0, 16)}… · ${v.length} bytes` +
                (d.ok ? ` · sighash 0x${(d.sighash || 0).toString(16).padStart(2, '0')} · ${d.lowS ? 'low-S' : 'HIGH-S'}` : ' · unparsable DER');
            }
            case IN.REDEEM_SCRIPT:
            case IN.WITNESS_SCRIPT:
              return `${S.classify(v).type} · ${S.toAsm(v).slice(0, 120)}`;
            case IN.BIP32_DERIVATION: {
              const d = decodeDerivation(v);
              return `${bytesToHex(e.keyData).slice(0, 16)}… ← ${d.fingerprint}:${d.path}`;
            }
            case IN.PREVIOUS_TXID: return bytesToHex(reverse(v));
            case IN.OUTPUT_INDEX:
            case IN.SEQUENCE: return String(new DataView(v.buffer, v.byteOffset, 4).getUint32(0, true));
            case IN.TAP_LEAF_SCRIPT:
              return `leaf v0x${v[v.length - 1].toString(16)} · ${S.toAsm(v.slice(0, -1)).slice(0, 100)}`;
            case IN.FINAL_SCRIPTWITNESS: {
              const rr = new Reader(v); const n = rr.varint(); const items = [];
              for (let k = 0; k < n; k++) items.push(bytesToHex(rr.varslice()));
              return `${n} item(s): ${items.map(x => x.slice(0, 20) + (x.length > 20 ? '…' : '')).join(' | ')}`;
            }
            default: return bytesToHex(v);
          }
        }));
      }
      if (hasSig) signedCount++;
      out.inputs.push({ index: i, rows, signed: hasSig });
    });

    psbt.outputs.forEach((map, i) => {
      const rows = map.map(e => field(OUT_NAME[e.type] || `UNKNOWN_0x${e.type.toString(16)}`, e, (v) => {
        if (e.type === OUT.AMOUNT) { const rr = new Reader(v); return `${ENC.groupNum(rr.u64())} sat`; }
        if (e.type === OUT.SCRIPT) return `${S.classify(v).type} · ${bytesToHex(v)}`;
        if (e.type === OUT.BIP32_DERIVATION || e.type === OUT.TAP_BIP32_DERIVATION) {
          const d = decodeDerivation(v); return `${d.fingerprint}:${d.path}`;
        }
        return bytesToHex(v);
      }));
      out.outputs.push({ index: i, rows });
    });

    out.summary = {
      version: psbt.version,
      inputs: psbt.inputs.length,
      outputs: psbt.outputs.length,
      signedInputs: signedCount,
      xpubs: all(psbt.globals, GLOBAL.XPUB).length,
      size: psbt.bytes.length
    };
    return out;
  }

  function field(name, e, fmt) {
    let display;
    try { display = fmt(e.value); } catch (err) { display = `⚠ ${err.message} — raw ${bytesToHex(e.value)}`; }
    return {
      name, type: e.type,
      keyData: e.keyData.length ? bytesToHex(e.keyData) : null,
      hex: bytesToHex(e.value), display, size: e.value.length
    };
  }

  /* ------------------------------------------------ import into the model */

  /** Merge a parsed PSBT into a workbench tx model. Returns {tx, report}. */
  function toModel(psbt, network) {
    const report = { inputs: [], outputs: [], notes: [] };
    let tx;

    if (psbt.unsigned) {
      tx = TX.fromDecoded(psbt.unsigned, network);
    } else {
      tx = TX.newTx();
      tx.network = network;
      const g = index(psbt.globals);
      if (g[GLOBAL.TX_VERSION]) tx.version = new DataView(g[GLOBAL.TX_VERSION].value.buffer, g[GLOBAL.TX_VERSION].value.byteOffset, 4).getUint32(0, true);
      if (g[GLOBAL.FALLBACK_LOCKTIME]) tx.locktime = new DataView(g[GLOBAL.FALLBACK_LOCKTIME].value.buffer, g[GLOBAL.FALLBACK_LOCKTIME].value.byteOffset, 4).getUint32(0, true);
      tx.inputs = psbt.inputs.map(() => TX.newInput());
      tx.outputs = psbt.outputs.map(() => TX.newOutput());
    }
    tx.psbtVersion = psbt.version === 2 ? 2 : 0;

    psbt.inputs.forEach((map, i) => {
      const inp = tx.inputs[i] || (tx.inputs[i] = TX.newInput());
      const m = index(map);
      const changes = [];

      if (m[IN.PREVIOUS_TXID]) { inp.txid = bytesToHex(reverse(m[IN.PREVIOUS_TXID].value)); }
      if (m[IN.OUTPUT_INDEX]) inp.vout = new DataView(m[IN.OUTPUT_INDEX].value.buffer, m[IN.OUTPUT_INDEX].value.byteOffset, 4).getUint32(0, true);
      if (m[IN.SEQUENCE]) inp.sequence = new DataView(m[IN.SEQUENCE].value.buffer, m[IN.SEQUENCE].value.byteOffset, 4).getUint32(0, true);

      if (m[IN.WITNESS_UTXO]) {
        const rr = new Reader(m[IN.WITNESS_UTXO].value);
        inp.amount = rr.u64();
        inp.scriptPubKey = bytesToHex(rr.varslice());
        changes.push('witness UTXO');
      }
      if (m[IN.NON_WITNESS_UTXO]) {
        inp.prevTxHex = bytesToHex(m[IN.NON_WITNESS_UTXO].value);
        try {
          const d = TX.decodeRaw(m[IN.NON_WITNESS_UTXO].value);
          const po = d.outputs[inp.vout];
          if (po) { inp.amount = po.amount; inp.scriptPubKey = po.script; }
          if (!inp.txid) inp.txid = d.txid;
          changes.push('non-witness UTXO');
        } catch (e) { report.notes.push(`input ${i}: could not decode the non-witness UTXO — ${e.message}`); }
      }
      if (m[IN.SIGHASH_TYPE]) {
        const t = new DataView(m[IN.SIGHASH_TYPE].value.buffer, m[IN.SIGHASH_TYPE].value.byteOffset, 4).getUint32(0, true);
        inp.sighashType = t & 0x1f || (t === 0 ? 0 : 1);
        inp.sighashAnyoneCanPay = !!(t & 0x80);
      }
      if (m[IN.REDEEM_SCRIPT]) inp.redeemScript = bytesToHex(m[IN.REDEEM_SCRIPT].value);
      if (m[IN.WITNESS_SCRIPT]) inp.witnessScript = bytesToHex(m[IN.WITNESS_SCRIPT].value);
      if (m[IN.TAP_INTERNAL_KEY]) { inp.taproot.internalKey = bytesToHex(m[IN.TAP_INTERNAL_KEY].value); inp.algorithm = 'schnorr'; }
      if (m[IN.TAP_MERKLE_ROOT]) inp.taproot.merkleRoot = bytesToHex(m[IN.TAP_MERKLE_ROOT].value);
      if (m[IN.TAP_LEAF_SCRIPT]) {
        const v = m[IN.TAP_LEAF_SCRIPT].value;
        inp.taproot.leafScript = bytesToHex(v.slice(0, -1));
        inp.taproot.leafVersion = v[v.length - 1];
        inp.taproot.controlBlock = bytesToHex(m[IN.TAP_LEAF_SCRIPT].keyData);
        inp.taproot.path = 'script';
      }
      inp.bip32 = all(map, IN.BIP32_DERIVATION).map(e => {
        const d = decodeDerivation(e.value);
        return { pubkey: bytesToHex(e.keyData), fingerprint: d.fingerprint, path: d.path };
      });
      inp.partialSigs = all(map, IN.PARTIAL_SIG).map(e => ({
        pubkey: bytesToHex(e.keyData), signature: bytesToHex(e.value)
      }));
      if (inp.partialSigs.length) changes.push(`${inp.partialSigs.length} partial signature(s)`);
      if (m[IN.TAP_KEY_SIG]) { inp.tapKeySig = bytesToHex(m[IN.TAP_KEY_SIG].value); changes.push('taproot key signature'); }
      inp.tapScriptSigs = all(map, IN.TAP_SCRIPT_SIG).map(e => ({
        pubkey: bytesToHex(e.keyData.slice(0, 32)), leafHash: bytesToHex(e.keyData.slice(32)),
        signature: bytesToHex(e.value)
      }));
      if (inp.tapScriptSigs.length) changes.push(`${inp.tapScriptSigs.length} tapscript signature(s)`);
      if (m[IN.FINAL_SCRIPTSIG]) { inp.scriptSig = bytesToHex(m[IN.FINAL_SCRIPTSIG].value); inp.manualScriptSig = true; changes.push('final scriptSig'); }
      if (m[IN.FINAL_SCRIPTWITNESS]) {
        const rr = new Reader(m[IN.FINAL_SCRIPTWITNESS].value);
        const n = rr.varint(); const items = [];
        for (let k = 0; k < n; k++) items.push(bytesToHex(rr.varslice()));
        inp.witness = items; inp.manualWitness = true;
        changes.push('final witness');
      }
      report.inputs.push({ index: i, changes, signed: inp.partialSigs.length > 0 || !!inp.tapKeySig || inp.tapScriptSigs.length > 0 });
    });

    psbt.outputs.forEach((map, i) => {
      const out = tx.outputs[i] || (tx.outputs[i] = TX.newOutput());
      const m = index(map);
      const changes = [];
      if (m[OUT.AMOUNT]) { out.amount = new Reader(m[OUT.AMOUNT].value).u64(); changes.push('amount'); }
      if (m[OUT.SCRIPT]) {
        const spk = m[OUT.SCRIPT].value;
        const addr = S.scriptToAddress(spk, network);
        if (addr) { out.mode = 'address'; out.address = addr; }
        else { out.mode = 'raw'; out.rawAsm = S.toAsm(spk); }
        out.script = bytesToHex(spk);
        changes.push('script');
      }
      if (m[OUT.REDEEM_SCRIPT]) out.redeemScript = bytesToHex(m[OUT.REDEEM_SCRIPT].value);
      if (m[OUT.WITNESS_SCRIPT]) out.witnessScript = bytesToHex(m[OUT.WITNESS_SCRIPT].value);
      report.outputs.push({ index: i, changes });
    });

    return { tx, report };
  }

  /* ---------------------------------------------------------- comparison */

  /** Compare a freshly imported PSBT against the current model, per input. */
  function diff(currentTx, parsed) {
    const rows = [];
    parsed.inputs.forEach((map, i) => {
      const m = index(map);
      const cur = currentTx.inputs[i];
      const sigs = all(map, IN.PARTIAL_SIG).length + (m[IN.TAP_KEY_SIG] ? 1 : 0) + all(map, IN.TAP_SCRIPT_SIG).length;
      const had = cur ? ((cur.partialSigs || []).length + (cur.tapKeySig ? 1 : 0) + (cur.tapScriptSigs || []).length) : 0;
      rows.push({
        index: i,
        added: sigs - had,
        total: sigs,
        finalized: !!(m[IN.FINAL_SCRIPTSIG] || m[IN.FINAL_SCRIPTWITNESS]),
        status: sigs > had ? 'signature added' : sigs > 0 ? 'already signed' : 'no signature'
      });
    });
    return rows;
  }

  global.PSBT = {
    MAGIC, GLOBAL, IN, OUT, GLOBAL_NAME, IN_NAME, OUT_NAME,
    build, parse, describe, toModel, diff,
    encodeDerivation, decodeDerivation,
    toBase64: (bytes) => bytesToBase64(bytes),
    toHex: (bytes) => bytesToHex(bytes)
  };
})(window);
