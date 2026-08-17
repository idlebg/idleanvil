/* ============================================================================
   tx.js — transaction model, serialization, weight accounting, raw decoding
   Exposes: window.TX
   ========================================================================== */
(function (global) {
  'use strict';
  const { Writer, Reader, hexToBytes, bytesToHex, reverse } = ENC;
  const S = SCRIPT;

  const SEQ_FINAL = 0xffffffff;
  const SEQ_RBF   = 0xfffffffd;
  const SEQ_LOCKTIME_DISABLE_FLAG = 0x80000000;
  const SEQ_TYPE_FLAG = 0x00400000;
  const LOCKTIME_THRESHOLD = 500000000;

  /* ------------------------------------------------------------ new models */

  function newInput(over = {}) {
    return {
      id: 'i' + Math.random().toString(36).slice(2, 9),
      txid: '', vout: 0, sequence: SEQ_RBF,
      amount: 0n,                     // prevout value in sats (BigInt)
      scriptPubKey: '',               // hex
      redeemScript: '', witnessScript: '',
      spendType: 'auto',              // auto | p2pkh | p2sh | p2wpkh | p2wsh | p2sh-p2wpkh | p2sh-p2wsh | p2tr | custom
      scriptSig: '',                  // hex, manual/final
      witness: [],                    // array of hex strings
      manualScriptSig: false, manualWitness: false,
      sighashType: 0x01, sighashAnyoneCanPay: false, sighashCustom: '',
      algorithm: 'ecdsa',             // ecdsa | schnorr
      scriptCodeOverride: '',
      taproot: {
        internalKey: '', merkleRoot: '', leafScript: '', leafVersion: 0xc0,
        controlBlock: '', annex: '', path: 'key'   // key | script
      },
      bip32: [],                      // [{pubkey, fingerprint, path}]
      prevTxHex: '',                  // full previous tx (PSBT non-witness utxo)
      partialSigs: [],                // [{pubkey, signature}]
      tapKeySig: '', tapScriptSigs: [],
      label: '', collapsed: false, ...over
    };
  }

  function newOutput(over = {}) {
    return {
      id: 'o' + Math.random().toString(36).slice(2, 9),
      amount: 0n,
      mode: 'address',                // address | template | raw | opreturn
      address: '',
      template: 'p2wpkh', templateVals: {},
      script: '',                     // hex — the resolved scriptPubKey
      rawAsm: '',
      opret: {
        encoding: 'utf8', payload: '', pushdata: 'auto',
        nonMinimal: false, multiPush: false, prefixOpcode: '', extraPayloads: []
      },
      redeemScript: '', witnessScript: '',
      subtractFee: false, label: '', collapsed: false, ...over
    };
  }

  function newTx() {
    return {
      network: 'mainnet',
      version: 2,
      locktime: 0,
      locktimeMode: 'disabled',       // disabled | height | time
      serialization: 'auto',          // auto | legacy | segwit
      psbtVersion: 0,
      inputs: [newInput()],
      outputs: [newOutput()],
      forensic: {},
      feeRate: 10
    };
  }

  /* ------------------------------------------------------ output resolution */

  /** Compute the scriptPubKey bytes for an output. Returns {script, error, note}. */
  function resolveOutput(out, network) {
    try {
      if (out.mode === 'address') {
        if (!out.address.trim()) return { script: new Uint8Array(0), error: null, empty: true };
        const r = S.addressToScript(out.address, network);
        return { script: r.script, type: r.type };
      }
      if (out.mode === 'template') {
        const r = S.buildTemplate(out.template, out.templateVals || {});
        return { script: r.script, note: r.note, sub: r.sub };
      }
      if (out.mode === 'raw') {
        const t = (out.rawAsm || '').trim();
        if (!t) return { script: hexToBytes(out.script || ''), error: null };
        return { script: S.fromAsm(t) };
      }
      if (out.mode === 'opreturn') return { script: buildOpReturn(out.opret) };
      return { script: hexToBytes(out.script || '') };
    } catch (e) {
      return { script: new Uint8Array(0), error: e.message };
    }
  }

  function encodePayload(text, encoding) {
    switch (encoding) {
      case 'utf8':  return ENC.utf8ToBytes(text);
      case 'ascii': return ENC.asciiToBytes(text);
      case 'hex':   return hexToBytes(text);
      case 'int': {
        const n = BigInt(String(text).trim() || '0');
        return S.scriptNum(n);
      }
      case 'int-le8': {
        const w = new Writer(); w.u64(BigInt(String(text).trim() || '0')); return w.bytes();
      }
      case 'base64': return ENC.base64ToBytes(text);
      default: return ENC.utf8ToBytes(text);
    }
  }

  function buildOpReturn(o) {
    const payloads = [];
    const main = encodePayload(o.payload || '', o.encoding);
    payloads.push(main);
    if (o.multiPush) for (const extra of (o.extraPayloads || [])) payloads.push(encodePayload(extra.value || '', extra.encoding || o.encoding));
    return S.opReturn(payloads, {
      pushdata: o.pushdata, nonMinimal: o.nonMinimal,
      prefixOpcode: o.prefixOpcode === '' ? null : o.prefixOpcode,
      keepEmpty: true
    });
  }

  /* --------------------------------------------------------- serialization */

  function hasWitness(tx) {
    if (tx.serialization === 'legacy') return false;
    if (tx.serialization === 'segwit') return true;
    return tx.inputs.some(i => (i.witness || []).some(w => w && w.length));
  }

  function inputScriptSig(inp, final) {
    if (!final) return new Uint8Array(0);
    return hexToBytes(inp.scriptSig || '');
  }

  /**
   * Serialize the transaction.
   * @param {object} tx
   * @param {object} opts { final:boolean, forceWitness:boolean|null }
   */
  function serialize(tx, opts = {}) {
    const final = !!opts.final;
    const wit = opts.forceWitness !== undefined && opts.forceWitness !== null
      ? opts.forceWitness
      : (final ? hasWitness(tx) : (tx.serialization === 'segwit'));
    const w = new Writer();
    w.i32(tx.version);
    if (wit) { w.u8(0x00); w.u8(0x01); }
    w.varint(tx.inputs.length);
    for (const inp of tx.inputs) {
      w.push(reverse(padTxid(inp.txid)));
      w.u32(inp.vout >>> 0);
      w.varslice(inputScriptSig(inp, final));
      w.u32(inp.sequence >>> 0);
    }
    w.varint(tx.outputs.length);
    for (const out of tx.outputs) {
      w.u64(BigInt(out.amount || 0));
      w.varslice(resolveOutput(out, tx.network).script);
    }
    if (wit) {
      for (const inp of tx.inputs) {
        const stack = final ? (inp.witness || []).filter(x => x !== null && x !== undefined) : [];
        w.varint(stack.length);
        for (const item of stack) w.varslice(hexToBytes(item || ''));
      }
    }
    w.u32(tx.locktime >>> 0);
    return w.bytes();
  }

  function padTxid(txid) {
    const t = String(txid || '').trim().replace(/^0x/, '');
    if (!t) return new Uint8Array(32);
    const b = hexToBytes(t.padStart(64, '0').slice(-64));
    return b;
  }

  /** txid = hash256 of the legacy (no-witness) serialization, displayed reversed */
  function txid(tx, final = true) {
    const raw = serialize(tx, { final, forceWitness: false });
    return bytesToHex(reverse(BC.hash256(raw)));
  }
  function wtxid(tx) {
    const raw = serialize(tx, { final: true, forceWitness: hasWitness(tx) });
    return bytesToHex(reverse(BC.hash256(raw)));
  }

  /* ------------------------------------------------------------ size model */

  /** Estimated witness/scriptSig size for an unsigned input, by type. */
  function estimateInputSpend(inp) {
    const spk = inp.scriptPubKey ? hexToBytes(inp.scriptPubKey) : new Uint8Array(0);
    const redeem = inp.redeemScript ? hexToBytes(inp.redeemScript) : null;
    let type = S.classify(spk).type;
    if (inp.spendType && inp.spendType !== 'auto') type = inp.spendType.toUpperCase();

    const sigLen = 72, pkLen = 33;
    if (type === 'P2WPKH') return { scriptSig: 0, witness: 1 + 1 + sigLen + 1 + pkLen };
    if (type === 'P2TR') {
      if (inp.taproot && inp.taproot.path === 'script') {
        const leaf = inp.taproot.leafScript ? hexToBytes(inp.taproot.leafScript).length : 34;
        const cb = inp.taproot.controlBlock ? hexToBytes(inp.taproot.controlBlock).length : 33;
        return { scriptSig: 0, witness: 1 + (1 + 65) + (1 + leaf) + (1 + cb) };
      }
      return { scriptSig: 0, witness: 1 + 1 + 64 };
    }
    if (type === 'P2PKH') return { scriptSig: 1 + sigLen + 1 + pkLen, witness: 0 };
    if (type === 'P2PK') return { scriptSig: 1 + sigLen, witness: 0 };
    if (type === 'P2WSH') {
      const ws = inp.witnessScript ? hexToBytes(inp.witnessScript).length : 34;
      return { scriptSig: 0, witness: 1 + (1 + sigLen) + (1 + ws) };
    }
    if (type === 'P2SH') {
      if (redeem) {
        const rc = S.classify(redeem).type;
        if (rc === 'P2WPKH') return { scriptSig: 1 + 1 + 22, witness: 1 + 1 + sigLen + 1 + pkLen };
        if (rc === 'P2WSH') {
          const ws = inp.witnessScript ? hexToBytes(inp.witnessScript).length : 34;
          return { scriptSig: 1 + 1 + 34, witness: 1 + (1 + sigLen) + (1 + ws) };
        }
        return { scriptSig: 1 + (1 + sigLen) + (redeem.length < 76 ? 1 : 2) + redeem.length, witness: 0 };
      }
      return { scriptSig: 1 + sigLen + 1 + pkLen, witness: 0 };
    }
    return { scriptSig: 1 + sigLen + 1 + pkLen, witness: 0 };
  }

  /**
   * Size accounting. When `final` the real scriptSig/witness are used; otherwise
   * a standard-spend estimate is applied so the fee rate is meaningful up front.
   */
  function measure(tx, opts = {}) {
    const final = !!opts.final;
    let base = 4 + ENC.varIntSize(tx.inputs.length) + ENC.varIntSize(tx.outputs.length) + 4;
    let witBytes = 0;
    let anyWitness = false;

    for (const inp of tx.inputs) {
      base += 36;
      if (final) {
        const ss = hexToBytes(inp.scriptSig || '');
        base += ENC.varIntSize(ss.length) + ss.length;
        const stack = inp.witness || [];
        if (stack.length) {
          anyWitness = true;
          witBytes += ENC.varIntSize(stack.length);
          for (const it of stack) {
            const b = hexToBytes(it || '');
            witBytes += ENC.varIntSize(b.length) + b.length;
          }
        } else witBytes += 1;
      } else {
        const est = estimateInputSpend(inp);
        base += ENC.varIntSize(est.scriptSig) + est.scriptSig;
        if (est.witness) { anyWitness = true; witBytes += est.witness; }
        else witBytes += 1;
      }
      base += 4;
    }
    for (const out of tx.outputs) {
      const spk = resolveOutput(out, tx.network).script;
      base += 8 + ENC.varIntSize(spk.length) + spk.length;
    }
    if (tx.serialization === 'segwit') anyWitness = true;
    if (tx.serialization === 'legacy') { anyWitness = false; witBytes = 0; }

    const marker = anyWitness ? 2 : 0;
    const total = base + marker + (anyWitness ? witBytes : 0);
    const weight = base * 4 + marker + (anyWitness ? witBytes : 0);
    const vsize = Math.ceil(weight / 4);

    const inTotal = tx.inputs.reduce((a, i) => a + BigInt(i.amount || 0), 0n);
    const outTotal = tx.outputs.reduce((a, o) => a + BigInt(o.amount || 0), 0n);
    const fee = inTotal - outTotal;

    return {
      base, total, weight, vsize, witBytes: anyWitness ? witBytes : 0, segwit: anyWitness,
      inTotal, outTotal, fee,
      feeRate: vsize ? Number(fee) / vsize : 0,
      estimated: !final
    };
  }

  /* ---------------------------------------------------------- raw decoding */

  /** Decode a raw transaction hex into a structured object with byte offsets. */
  function decodeRaw(hexOrBytes) {
    const bytes = hexOrBytes instanceof Uint8Array ? hexOrBytes : hexToBytes(hexOrBytes);
    const r = new Reader(bytes);
    const fields = [];       // {start, len, kind, label, value, path}
    const mark = (start, kind, label, value, path) =>
      fields.push({ start, len: r.o - start, kind, label, value, path });

    let p = r.o; const version = r.i32(); mark(p, 'version', 'nVersion', version, 'version');
    let segwit = false, flag = 0;
    if (bytes[r.o] === 0x00 && bytes[r.o + 1] !== 0x00) {
      p = r.o; r.u8(); flag = r.u8(); segwit = true;
      mark(p, 'marker', 'SegWit marker + flag', `00 ${flag.toString(16).padStart(2, '0')}`, 'marker');
    }
    p = r.o; const nIn = r.varint(); mark(p, 'count', 'Input count', nIn, 'incount');
    const inputs = [];
    for (let i = 0; i < nIn; i++) {
      p = r.o; const txidBytes = r.take(32);
      mark(p, 'txid', `Input ${i} — previous TXID`, bytesToHex(reverse(txidBytes)), `in${i}.txid`);
      p = r.o; const vout = r.u32(); mark(p, 'vout', `Input ${i} — vout`, vout, `in${i}.vout`);
      p = r.o; const sl = r.varint(); mark(p, 'scriptlen', `Input ${i} — scriptSig length`, sl, `in${i}.scriptlen`);
      p = r.o; const ss = r.take(sl);
      if (sl) mark(p, 'script', `Input ${i} — scriptSig`, bytesToHex(ss), `in${i}.scriptsig`);
      p = r.o; const seq = r.u32(); mark(p, 'sequence', `Input ${i} — nSequence`, '0x' + seq.toString(16).padStart(8, '0'), `in${i}.sequence`);
      inputs.push({ txid: bytesToHex(reverse(txidBytes)), vout, scriptSig: bytesToHex(ss), sequence: seq, witness: [] });
    }
    p = r.o; const nOut = r.varint(); mark(p, 'count', 'Output count', nOut, 'outcount');
    const outputs = [];
    for (let i = 0; i < nOut; i++) {
      p = r.o; const val = r.u64(); mark(p, 'amount', `Output ${i} — value`, `${val} sat`, `out${i}.value`);
      p = r.o; const sl = r.varint(); mark(p, 'scriptlen', `Output ${i} — scriptPubKey length`, sl, `out${i}.scriptlen`);
      p = r.o; const spk = r.take(sl);
      if (sl) mark(p, 'script', `Output ${i} — scriptPubKey`, bytesToHex(spk), `out${i}.spk`);
      outputs.push({ amount: val, script: bytesToHex(spk) });
    }
    if (segwit) {
      for (let i = 0; i < nIn; i++) {
        p = r.o; const n = r.varint(); mark(p, 'witness', `Input ${i} — witness item count`, n, `in${i}.witcount`);
        for (let j = 0; j < n; j++) {
          p = r.o; const item = r.varslice();
          mark(p, 'witness', `Input ${i} — witness[${j}] (${item.length} bytes)`, bytesToHex(item), `in${i}.wit${j}`);
          inputs[i].witness.push(bytesToHex(item));
        }
      }
    }
    p = r.o; const locktime = r.u32(); mark(p, 'locktime', 'nLockTime', locktime, 'locktime');
    const trailing = r.left;

    const noWit = (() => {
      const w = new Writer();
      w.i32(version).varint(nIn);
      for (const i of inputs) { w.push(reverse(hexToBytes(i.txid))).u32(i.vout).varslice(hexToBytes(i.scriptSig)).u32(i.sequence); }
      w.varint(nOut);
      for (const o of outputs) { w.u64(o.amount).varslice(hexToBytes(o.script)); }
      w.u32(locktime);
      return w.bytes();
    })();

    const baseSize = noWit.length;
    const totalSize = bytes.length - trailing;
    const weight = baseSize * 3 + totalSize;

    return {
      version, segwit, flag, locktime, inputs, outputs, fields, trailing,
      txid: bytesToHex(reverse(BC.hash256(noWit))),
      wtxid: bytesToHex(reverse(BC.hash256(bytes.slice(0, totalSize)))),
      size: totalSize, baseSize, weight, vsize: Math.ceil(weight / 4),
      outTotal: outputs.reduce((a, o) => a + o.amount, 0n),
      bytes: bytes.slice(0, totalSize)
    };
  }

  /** Turn a decoded raw tx back into the editable model. */
  function fromDecoded(dec, network) {
    const tx = newTx();
    tx.network = network;
    tx.version = dec.version;
    tx.locktime = dec.locktime;
    tx.locktimeMode = dec.locktime === 0 ? 'disabled' : (dec.locktime < LOCKTIME_THRESHOLD ? 'height' : 'time');
    tx.serialization = dec.segwit ? 'segwit' : 'legacy';
    tx.inputs = dec.inputs.map(i => {
      const inp = newInput();
      inp.txid = i.txid; inp.vout = i.vout; inp.sequence = i.sequence;
      inp.scriptSig = i.scriptSig; inp.witness = i.witness.slice();
      inp.manualScriptSig = !!i.scriptSig; inp.manualWitness = !!i.witness.length;
      return inp;
    });
    tx.outputs = dec.outputs.map(o => {
      const out = newOutput();
      out.amount = o.amount;
      const spk = hexToBytes(o.script);
      const cls = S.classify(spk);
      if (cls.type === 'OP_RETURN') {
        out.mode = 'raw'; out.rawAsm = S.toAsm(spk); out.script = o.script;
      } else {
        const addr = S.scriptToAddress(spk, network);
        if (addr) { out.mode = 'address'; out.address = addr; }
        else { out.mode = 'raw'; out.rawAsm = S.toAsm(spk); }
        out.script = o.script;
      }
      return out;
    });
    return tx;
  }

  /* ------------------------------------------------------- locktime helper */

  function describeLocktime(lt) {
    if (lt === 0) return 'disabled — the transaction is final at any height';
    if (lt < LOCKTIME_THRESHOLD) return `block height ${ENC.groupNum(lt)} — not mineable until then`;
    const d = new Date(lt * 1000);
    return `unix time ${ENC.groupNum(lt)} — ${d.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
  }

  function describeSequence(seq) {
    const notes = [];
    if (seq === SEQ_FINAL) notes.push('final — opts out of RBF and disables nLockTime for this input');
    else if (seq === SEQ_FINAL - 1) notes.push('leaves nLockTime enabled but does not signal RBF (BIP125 needs < 0xfffffffe)');
    else notes.push('signals RBF (BIP125) and leaves nLockTime enabled');
    if (!(seq & SEQ_LOCKTIME_DISABLE_FLAG)) {
      const val = seq & 0x0000ffff;
      if (seq & SEQ_TYPE_FLAG) notes.push(`relative timelock: ${val} × 512 s = ${val * 512} s`);
      else notes.push(`relative timelock: ${val} block${val === 1 ? '' : 's'}`);
    } else notes.push('relative timelock disabled');
    return notes.join(' · ');
  }

  global.TX = {
    SEQ_FINAL, SEQ_RBF, LOCKTIME_THRESHOLD,
    newTx, newInput, newOutput,
    resolveOutput, buildOpReturn, encodePayload,
    serialize, txid, wtxid, hasWitness, measure, estimateInputSpend,
    decodeRaw, fromDecoded, padTxid,
    describeLocktime, describeSequence
  };
})(window);
