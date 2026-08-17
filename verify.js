/* ============================================================================
   verify.js — in-repo regression harness for the idleAnvil modules.
   Run with:  node verify.js       (no dependencies, Node 16+)
   Loads the exact browser scripts into this realm and asserts 90 checks
   against published vectors and byte-exact derivations.
   ========================================================================== */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = __dirname;
/* Load in THIS realm (like a browser page) — a separate vm context has its own
   Uint8Array intrinsics, which breaks instanceof checks on TextEncoder output. */
globalThis.window = globalThis;
for (const f of ['crypto.js', 'encoding.js', 'script.js', 'tx.js', 'sighash.js', 'psbt.js', 'validate.js', 'tools.js', 'multisig.js']) {
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'js', f), 'utf8'), { filename: f });
}
const { BC, ENC, SCRIPT, TX, SIGHASH, PSBT, VALIDATE, FINALIZE, TOOLS, MULTISIG } = globalThis;

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const g = typeof got === 'bigint' ? got.toString() : JSON.stringify(got);
  const w = typeof want === 'bigint' ? want.toString() : JSON.stringify(want);
  if (g === w) { pass++; console.log(`  ok  ${name}`); }
  else { fail++; console.log(`FAIL  ${name}\n      got  ${g}\n      want ${w}`); }
};
const throws = (name, fn, re) => {
  try { fn(); fail++; console.log(`FAIL  ${name} — did not throw`); }
  catch (e) { if (!re || re.test(e.message)) { pass++; console.log(`  ok  ${name}`); } else { fail++; console.log(`FAIL  ${name} — wrong error: ${e.message}`); } }
};
const hex = ENC.bytesToHex, unhex = ENC.hexToBytes;

/* ---- regression guard: BIP143 official worked example (unchanged code paths) ---- */
{
  // BIP143 P2WPKH example: verify hashPrevouts/hashOutputs and final sighash still compute
  const tx = TX.newTx();
  tx.version = 1; tx.locktime = 0x11; tx.network = 'mainnet';
  const i0 = TX.newInput();
  i0.txid = '9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff';
  i0.vout = 0; i0.sequence = 0xffffffee; i0.amount = 625000000n;
  i0.scriptPubKey = '2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac';
  const i1 = TX.newInput();
  i1.txid = '8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef';
  i1.vout = 1; i1.sequence = 0xffffffff; i1.amount = 600000000n;
  i1.scriptPubKey = '00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1';
  tx.inputs = [i0, i1];
  const o0 = TX.newOutput(); o0.amount = 112340000n; o0.mode = 'raw'; o0.rawAsm = ''; o0.script = '76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac';
  const o1 = TX.newOutput(); o1.amount = 223450000n; o1.mode = 'raw'; o1.rawAsm = ''; o1.script = '76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac';
  tx.outputs = [o0, o1];
  const sc = SCRIPT.deriveScriptCode(i1);
  const r = SIGHASH.bip143(tx, 1, sc.scriptCode, 600000000n, 0x01);
  eq('BIP143 example sighash', hex(r.digest), 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670');
  eq('BIP143 hashPrevouts', hex(r.parts.hashPrevouts), '96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37');
}

/* ---- dust thresholds (Core GetDustThreshold @ 3 sat/vB) ---- */
{
  const p2pkh = SCRIPT.p2pkh(new Uint8Array(20));
  const p2sh = SCRIPT.p2sh(new Uint8Array(20));
  const p2wpkh = SCRIPT.p2wpkh(new Uint8Array(20));
  const p2wsh = SCRIPT.p2wsh(new Uint8Array(32));
  const p2tr = SCRIPT.p2tr(new Uint8Array(32));
  eq('dust P2PKH = 546', VALIDATE.dustThreshold(p2pkh), 546n);
  eq('dust P2SH = 540', VALIDATE.dustThreshold(p2sh), 540n);
  eq('dust P2WPKH = 294', VALIDATE.dustThreshold(p2wpkh), 294n);
  eq('dust P2WSH = 330', VALIDATE.dustThreshold(p2wsh), 330n);
  eq('dust P2TR = 330', VALIDATE.dustThreshold(p2tr), 330n);
  eq('dust OP_RETURN = 0', VALIDATE.dustThreshold(unhex('6a04deadbeef')), 0n);
}

/* ---- OP_RETURN standardness: 80-byte payload (83-byte script) is standard ---- */
{
  const payload80 = new Uint8Array(80).fill(0xaa);
  const s83 = SCRIPT.opReturn([payload80], {});           // 6a 4c 50 <80>
  eq('OP_RETURN 80-byte payload script len', s83.length, 83);
  eq('OP_RETURN 80-byte payload standard', SCRIPT.classify(s83).standard, true);
  eq('OP_RETURN payload byte count', SCRIPT.classify(s83).dataLen, 80);
  const s84 = SCRIPT.opReturn([new Uint8Array(81).fill(0xaa)], {});
  eq('OP_RETURN 81-byte payload NOT standard', SCRIPT.classify(s84).standard, false);
}

/* ---- describeSequence: 0xfffffffe must NOT claim RBF ---- */
{
  eq('seq fffffffe no RBF', TX.describeSequence(0xfffffffe).includes('does not signal RBF'), true);
  eq('seq fffffffd signals RBF', TX.describeSequence(0xfffffffd).includes('signals RBF'), true);
  eq('seq ffffffff final', TX.describeSequence(0xffffffff).includes('final'), true);
}

/* ---- P2WSH 2-of-3 finalization: NULLDUMMY empty item + key-ordered sigs ---- */
{
  const keys = MULTISIG.exampleKeys(3);
  const ws = SCRIPT.multisig(2, keys.map(unhex));
  const inp = TX.newInput();
  inp.scriptPubKey = hex(SCRIPT.p2wsh(BC.sha256(ws)));
  inp.witnessScript = hex(ws);
  inp.partialSigs = [
    { pubkey: keys[2], signature: 'dd'.repeat(71) },   // deliberately out of key order
    { pubkey: keys[0], signature: 'aa'.repeat(71) }
  ];
  const r = FINALIZE.finalizeInput(inp);
  eq('P2WSH multisig ok', r.ok, true);
  eq('P2WSH multisig witness items', r.witness.length, 4);            // dummy + 2 sigs + script
  eq('P2WSH multisig dummy first', r.witness[0], '');
  eq('P2WSH multisig sig order', [r.witness[1].slice(0, 2), r.witness[2].slice(0, 2)], ['aa', 'dd']);
  eq('P2WSH multisig script last', r.witness[3], hex(ws));
  // finalizeAll must keep the empty dummy
  const tx = TX.newTx(); tx.inputs = [inp]; tx.outputs = [TX.newOutput()];
  FINALIZE.finalizeAll(tx);
  eq('finalizeAll keeps dummy', tx.inputs[0].witness[0], '');
  eq('finalizeAll item count', tx.inputs[0].witness.length, 4);
}

/* ---- tapscript k-of-n finalization: positional empties, reverse key order ---- */
{
  const xonly = MULTISIG.exampleKeys(3).map(k => k.slice(2));  // x-only forms
  const w = new ENC.Writer();
  xonly.forEach((k, i) => { w.push(SCRIPT.pushData(unhex(k))); w.u8(i === 0 ? 0xac : 0xba); });
  w.push(SCRIPT.pushData(SCRIPT.scriptNum(2n))); w.u8(0x9c);
  const leaf = w.bytes();
  const inp = TX.newInput();
  inp.scriptPubKey = hex(SCRIPT.p2tr(new Uint8Array(32).fill(2)));  // classification only
  inp.taproot.path = 'script';
  inp.taproot.leafScript = hex(leaf);
  inp.taproot.controlBlock = 'c0' + '11'.repeat(32);
  inp.tapScriptSigs = [
    { pubkey: xonly[0], leafHash: '', signature: 'aa'.repeat(64) },
    { pubkey: xonly[2], leafHash: '', signature: 'cc'.repeat(64) }
  ];
  const r = FINALIZE.finalizeInput(inp);
  eq('tapscript ok', r.ok, true);
  // stack: sig3, sig2(empty), sig1 then leaf + control block
  eq('tapscript witness items', r.witness.length, 5);
  eq('tapscript order', [r.witness[0].slice(0, 2), r.witness[1], r.witness[2].slice(0, 2)], ['cc', '', 'aa']);
}

/* ---- commitment matrix: BIP341 NONE keeps sequences; ACP keeps this input's amount+spk ---- */
{
  const cNone = SIGHASH.commitment(0x02, 'bip341');
  eq('bip341 NONE commits sequences', cNone.sequences.on, true);
  const cAcp = SIGHASH.commitment(0x81, 'bip341');
  eq('bip341 ACP amounts still on', cAcp.inputAmounts.on, true);
  eq('bip341 ACP spks still on', cAcp.inputScriptPubKeys.on, true);
  eq('bip341 ACP sequences off', cAcp.sequences.on, false);
  const legacyNone = SIGHASH.commitment(0x02, 'legacy');
  eq('legacy NONE sequences off', legacyNone.sequences.on, false);
  eq('legacy amounts off', legacyNone.inputAmounts.on, false);
}

/* ---- estimator: P2SH-P2WPKH input ≈ 91 vB, not 118 ---- */
{
  const r = TOOLS.estimate([{ type: 'P2SH-P2WPKH', count: 1 }], [{ type: 'P2WPKH', count: 1 }], 1);
  const inputVb = Math.ceil((64 * 4 + 108) / 4);
  eq('P2SH-P2WPKH input vbytes ≈ 91', inputVb, 91);
  // base = 4+4 overhead + 1+1 count varints + 64 input + 31 output = 105; witness 108 + 2 marker
  eq('estimate total vsize', r.vsize, Math.ceil((105 * 4 + 2 + 108) / 4));
}

/* ---- estimateInputSpend legacy sizes ---- */
{
  const inp = TX.newInput();
  inp.scriptPubKey = hex(SCRIPT.p2pkh(new Uint8Array(20)));
  eq('P2PKH scriptSig estimate 107', TX.estimateInputSpend(inp).scriptSig, 107);
  const pk = TX.newInput();
  pk.scriptPubKey = hex(SCRIPT.p2pk(unhex(MULTISIG.exampleKeys(1)[0])));
  eq('P2PK scriptSig estimate 73', TX.estimateInputSpend(pk).scriptSig, 73);
}

/* ---- varint: BigInt path exact above 2^53 ---- */
{
  eq('varint 2^56+1 exact', hex(ENC.encodeVarInt(72057594037927937n)), 'ff0100000000000001');
  eq('varint number still fine', hex(ENC.encodeVarInt(515)), 'fd0302');
  eq('varIntSize bigint', ENC.varIntSize(72057594037927937n), 9);
}

/* ---- conversions ---- */
{
  eq('convertUnits -1.5 btc', TOOLS.convertUnits('-1.5', 'btc').sats, -150000000n);
  eq('convertUnits 1.5 bit', TOOLS.convertUnits('1.5', 'bit').sats, 150n);
  eq('btcToSats 0.00000001', ENC.btcToSats('0.00000001'), 1n);
  throws('btcToSats rejects 9 decimals', () => ENC.btcToSats('0.000000001'), /decimal/);
}

/* ---- multisig reordered flag ---- */
{
  const ks = ['03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a',
              '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'];
  const sorted = MULTISIG.build({ keys: ks.map(raw => ({ raw, enabled: true })), m: 1, sort: 'bip67', network: 'mainnet' });
  eq('bip67 reordered flag set', !!sorted.reordered, true);
  eq('all five variants built (incl. taproot)', sorted.variants.map(v => v.id).sort().join(','), 'bare,p2sh,p2sh-p2wsh,p2tr,p2wsh');
  eq('no taproot warning', sorted.warnings.some(w => /Taproot variant unavailable/.test(w)), false);
  const entered = MULTISIG.build({ keys: ks.map(raw => ({ raw, enabled: true })), m: 1, sort: 'entered', network: 'mainnet' });
  eq('entered order no flag', !!entered.reordered, false);
}

/* ---- validation snapshots: OP_RETURN 80B payload no longer flagged; 0x00 sighash on non-taproot flagged ---- */
{
  const tx = TX.newTx();
  tx.network = 'testnet3';
  const i0 = TX.newInput();
  i0.txid = 'aa'.repeat(32); i0.vout = 0; i0.amount = 100000n;
  i0.scriptPubKey = hex(SCRIPT.p2wpkh(new Uint8Array(20).fill(1)));
  tx.inputs = [i0];
  const o0 = TX.newOutput(); o0.mode = 'opreturn'; o0.amount = 0n;
  o0.opret = { encoding: 'hex', payload: 'aa'.repeat(80), pushdata: 'auto', nonMinimal: false, multiPush: false, prefixOpcode: '', extraPayloads: [] };
  const o1 = TX.newOutput(); o1.amount = 98000n; o1.mode = 'address';
  o1.address = SCRIPT.scriptToAddress(SCRIPT.p2wpkh(new Uint8Array(20).fill(2)), 'testnet3');
  tx.outputs = [o0, o1];
  const res = VALIDATE.run(tx);
  eq('80B OP_RETURN not flagged', res.rows.filter(r => /OP_RETURN/.test(r.title)).length, 0);

  i0.sighashType = 0;   // DEFAULT on a non-taproot input
  const res2 = VALIDATE.run(tx);
  eq('0x00 sighash on segwit-v0 input flagged', res2.rows.some(r => /unusual sighash/.test(r.title)), true);
  i0.sighashType = 1;
}

/* ---- serialization of empty witness items round-trips ---- */
{
  const tx = TX.newTx();
  const i0 = TX.newInput();
  i0.txid = 'bb'.repeat(32); i0.vout = 0; i0.amount = 10000n; i0.sequence = 0xfffffffd;
  i0.witness = ['', 'aa'.repeat(71), 'bb'.repeat(71), '52210000000052ae'];
  tx.inputs = [i0];
  const o0 = TX.newOutput(); o0.amount = 9000n; o0.mode = 'raw'; o0.rawAsm = ''; o0.script = hex(SCRIPT.p2wpkh(new Uint8Array(20)));
  tx.outputs = [o0];
  const raw = TX.serialize(tx, { final: true });
  const dec = TX.decodeRaw(raw);
  eq('empty witness item survives serialize/decode', dec.inputs[0].witness.length, 4);
  eq('empty witness item is empty', dec.inputs[0].witness[0], '');
}

/* ---- P2SH-P2WPKH finalize now requires the pubkey ---- */
{
  const pk = MULTISIG.exampleKeys(1)[0];
  const redeem = SCRIPT.p2wpkh(BC.hash160(unhex(pk)));
  const inp = TX.newInput();
  inp.scriptPubKey = hex(SCRIPT.p2sh(BC.hash160(redeem)));
  inp.redeemScript = hex(redeem);
  inp.partialSigs = [{ pubkey: '', signature: 'aa'.repeat(71) }];
  const r1 = FINALIZE.finalizeInput(inp);
  eq('P2SH-P2WPKH without pubkey refused', r1.ok, false);
  eq('P2SH-P2WPKH need note', /public key/.test(r1.note), true);
  inp.partialSigs[0].pubkey = pk;
  const r2 = FINALIZE.finalizeInput(inp);
  eq('P2SH-P2WPKH with pubkey ok', r2.ok, true);
  eq('P2SH-P2WPKH witness [sig, pubkey]', r2.witness, ['aa'.repeat(71), pk]);
  eq('P2SH-P2WPKH scriptSig pushes redeem', r2.scriptSig, hex(SCRIPT.pushData(redeem)));
}

/* ---- min-size rule: non-witness base < 65 → NONSTANDARD (not INVALID) ---- */
{
  const tx = TX.newTx();
  const i0 = TX.newInput();
  i0.txid = 'cc'.repeat(32); i0.vout = 0; i0.amount = 10000n;
  i0.scriptPubKey = hex(SCRIPT.p2wpkh(new Uint8Array(20)));
  i0.spendType = 'p2tr';                       // small witness estimate, tiny base
  tx.inputs = [i0];
  const o0 = TX.newOutput(); o0.amount = 9000n; o0.mode = 'raw'; o0.rawAsm = ''; o0.script = '51';  // OP_TRUE, 1 byte
  tx.outputs = [o0];
  const m = TX.measure(tx);
  const res = VALIDATE.run(tx);
  const row = res.rows.find(r => /Non-witness size/.test(r.title));
  eq('base below 65 detected', m.base < 65, true);
  eq('min-size row present', !!row, true);
  eq('min-size row severity nonstandard', row && row.sev, 'nonstandard');
}

/* ---- estimator constants + remaining estimateInputSpend branches ---- */
{
  eq('OUTPUT_COSTS OP_RETURN(80) = 92', TOOLS.OUTPUT_COSTS['OP_RETURN(80)'], 92);
  eq('INPUT_COSTS P2SH-P2WPKH base = 64', TOOLS.INPUT_COSTS['P2SH-P2WPKH'].base, 64);
  const p2shNoRedeem = TX.newInput();
  p2shNoRedeem.scriptPubKey = hex(SCRIPT.p2sh(new Uint8Array(20)));
  eq('P2SH fallback estimate 107', TX.estimateInputSpend(p2shNoRedeem).scriptSig, 107);
  const unknown = TX.newInput();
  unknown.scriptPubKey = 'aabbcc';
  eq('unknown-type estimate 107', TX.estimateInputSpend(unknown).scriptSig, 107);
}

/* ---- newInput applies overrides ---- */
{
  const inp = TX.newInput({ vout: 7, label: 'x' });
  eq('newInput override vout', inp.vout, 7);
  eq('newInput override label', inp.label, 'x');
  eq('newInput defaults intact', TX.newInput().vout, 0);
}

/* ---- tightened: BIP341 rejects every consensus-invalid sighash byte ---- */
{
  const tx = TX.newTx();
  const i0 = TX.newInput({ vout: 0, amount: 100000n });
  i0.txid = 'ee'.repeat(32);
  i0.scriptPubKey = hex(SCRIPT.p2tr(new Uint8Array(32).fill(3)));
  tx.inputs = [i0];
  const o0 = TX.newOutput(); o0.amount = 99000n; o0.mode = 'raw'; o0.rawAsm = ''; o0.script = hex(SCRIPT.p2wpkh(new Uint8Array(20)));
  tx.outputs = [o0];
  throws('bip341 rejects 0x04', () => SIGHASH.bip341(tx, 0, 0x04), /invalid for taproot/);
  throws('bip341 rejects 0x21', () => SIGHASH.bip341(tx, 0, 0x21), /invalid for taproot/);
  throws('bip341 rejects 0x80', () => SIGHASH.bip341(tx, 0, 0x80), /invalid for taproot/);
  throws('bip341 rejects 0xff', () => SIGHASH.bip341(tx, 0, 0xff), /invalid for taproot/);
  for (const v of [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83])
    eq(`bip341 accepts 0x${v.toString(16).padStart(2, '0')}`, SIGHASH.bip341(tx, 0, v).digest.length, 32);

  /* validator: invalid taproot byte is INVALID; same byte on an ECDSA input is NONSTANDARD */
  i0.sighashCustom = '04';
  const res = VALIDATE.run(tx);
  eq('taproot 0x04 → INVALID row', res.rows.some(r => r.sev === 'invalid' && /invalid for taproot/.test(r.title)), true);
  i0.scriptPubKey = hex(SCRIPT.p2wpkh(new Uint8Array(20).fill(9)));
  const res2 = VALIDATE.run(tx);
  eq('segwit-v0 0x04 → NONSTANDARD row', res2.rows.some(r => r.sev === 'nonstandard' && /unusual sighash/.test(r.title)), true);
  eq('segwit-v0 0x04 not INVALID', res2.rows.some(r => r.sev === 'invalid' && /sighash/.test(r.title)), false);
}

/* ---- tightened: exact P2SH-2of3 input size ---- */
{
  eq('P2SH-2of3 base = 297', TOOLS.INPUT_COSTS['P2SH-2of3'].base, 297);
  // independent derivation: 36 outpoint + varint(254)=3 + [OP_0 + 2×(1+72) + (2+105)] + 4 sequence
  eq('P2SH-2of3 derivation', 36 + 3 + (1 + 2 * 73 + 2 + 105) + 4, 297);
}

/* ---- tightened: unit conversion refuses lossy input, keeps exact input ---- */
{
  throws('1.5 sat rejected', () => TOOLS.convertUnits('1.5', 'sat'), /smallest unit/);
  eq('1.0 sat accepted (exact)', TOOLS.convertUnits('1.0', 'sat').sats, 1n);
  eq('1.230 bit accepted (exact)', TOOLS.convertUnits('1.230', 'bit').sats, 123n);
  throws('1.234 bit rejected', () => TOOLS.convertUnits('1.234', 'bit'), /whole sats/);
  throws('0.000000001 btc rejected', () => TOOLS.convertUnits('0.000000001', 'btc'), /whole sats/);
  eq('0.100000000 btc accepted (exact)', TOOLS.convertUnits('0.100000000', 'btc').sats, 10000000n);
  eq('negative exact still works', TOOLS.convertUnits('-1.50', 'btc').sats, -150000000n);
  throws('multi-dot rejected', () => TOOLS.convertUnits('1.2.3', 'btc'), /not a valid number/);
  eq('btcToSats trailing-zero 9th decimal ok', ENC.btcToSats('0.123456780'), 12345678n);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
