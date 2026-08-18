/* verify.js — regression harness for the TXCRAFT variant modules.
   Run with:  node verify.js       (no dependencies, Node 16+) */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = __dirname;
for (const f of ['btc-core.js', 'btc-tx.js', 'btc-psbt.js', 'btc-fulcrum.js']) {
  vm.runInThisContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), { filename: f });
}
const B = globalThis.BTC;

let pass = 0, fail = 0;
const eq = (name, got, want) => {
  const g = typeof got === 'bigint' ? got.toString() : JSON.stringify(got);
  const w = typeof want === 'bigint' ? want.toString() : JSON.stringify(want);
  if (g === w) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log('FAIL  ' + name + '\n      got  ' + g + '\n      want ' + w); }
};
const throws = (name, fn, re) => {
  try { fn(); fail++; console.log('FAIL  ' + name + ' — did not throw'); }
  catch (e) { if (!re || re.test(e.message)) { pass++; console.log('  ok  ' + name); } else { fail++; console.log('FAIL  ' + name + ' — wrong error: ' + e.message); } }
};

/* ---- regression anchors ---- */
{
  // BIP143 official P2WPKH example
  const tx = {
    version: 1, locktime: 0x11,
    ins: [
      { txid: '9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff', vout: 0, sequence: 0xffffffee, scriptSig: new Uint8Array(0), witness: [] },
      { txid: '8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef', vout: 1, sequence: 0xffffffff, scriptSig: new Uint8Array(0), witness: [] }
    ],
    outs: [
      { value: 112340000, script: B.fromHex('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac') },
      { value: 223450000, script: B.fromHex('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac') }
    ]
  };
  const scriptCode = B.p2pkh(B.fromHex('1d0f172a0ecb48aee1be1f2687d2963ae33f71a1'));
  const r = B.sighashV0(tx, 1, scriptCode, 600000000, 0x01);
  eq('BIP143 sighash', r.z, 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670');
  eq('BIP143 hashPrevouts', r.hashPrevouts, '96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37');

  // BIP86 taproot: internal key -> output key and mainnet address
  const internal = B.fromHex('cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  const tw = B.tapTweak(internal, null);
  eq('BIP86 output key', B.toHex(tw.outputKey), 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');
  eq('BIP86 address', B.addressFromScript(B.p2tr(tw.outputKey), 'mainnet'), 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
}

/* ---- tapLeafHash parity-bit masking ---- */
{
  const s = B.fromHex('20cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115ac');
  eq('leaf version parity bit masked', B.toHex(B.tapLeafHash(s, 0xc1)), B.toHex(B.tapLeafHash(s, 0xc0)));
  eq('default version unchanged', B.toHex(B.tapLeafHash(s)), B.toHex(B.tapLeafHash(s, 0xc0)));
}

/* ---- multisig 17–20 keys ---- */
{
  const keys = [];
  for (let i = 1; i <= 20; i++) keys.push(B.pointToCompressed(B.ptMul(BigInt(i * 3 + 5), B.G)));
  const ms = B.multisig(17, keys);
  eq('17-of-20 m as CScriptNum push', B.toHex(ms.slice(0, 2)), '0111');
  eq('17-of-20 n as CScriptNum push + CHECKMULTISIG', B.toHex(ms.slice(-3)), '0114ae');
  eq('17-of-20 length', ms.length, 2 + 20 * 34 + 2 + 1);
  const ms23 = B.multisig(2, keys.slice(0, 3));
  eq('2-of-3 still OP_n encoded', B.toHex(ms23.slice(0, 1)) + '/' + B.toHex(ms23.slice(-2)), '52/53ae');
  throws('m > n rejected', () => B.multisig(5, keys.slice(0, 3)), /1 ≤ m ≤ n ≤ 20/);
  throws('n > 20 rejected', () => B.multisig(2, keys.concat([keys[0]])), /1 ≤ m ≤ n ≤ 20/);
}

/* ---- ASM number parsing ---- */
{
  eq('odd-length decimal is a number (144)', B.toHex(B.asmToScript('144')), '029000');
  eq('single digit still OP_n (5)', B.toHex(B.asmToScript('5')), '55');
  eq('zero is OP_0', B.toHex(B.asmToScript('0')), '00');
  eq('negative number works (-5)', B.toHex(B.asmToScript('-5')), '0185');
  eq('even-length digits stay hex (20)', B.toHex(B.asmToScript('20')), '0120');
  const rt = '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac';
  eq('hex round-trip preserved', B.toHex(B.asmToScript(B.scriptToAsm(B.fromHex(rt)))), rt);
  eq('CSV 144 compiles', B.toHex(B.asmToScript('144 OP_CHECKSEQUENCEVERIFY OP_DROP')), '029000b275');
}

/* ---- taproot sighash byte validity ---- */
{
  const tx = {
    version: 2, locktime: 0,
    ins: [{ txid: 'aa'.repeat(32), vout: 0, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [] }],
    outs: [{ value: 90000, script: B.fromHex('001479091972186c449eb1ded22b78e40d009bdf0089') }]
  };
  const prev = [{ value: 100000, script: B.fromHex('5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c') }];
  for (const v of [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83])
    eq('taproot accepts 0x' + v.toString(16).padStart(2, '0'), B.sighashTaproot(tx, 0, prev, v, {}).digest.length, 32);
  for (const v of [0x80, 0x04, 0x21, 0x41, 0xff])
    throws('taproot rejects 0x' + v.toString(16).padStart(2, '0'), () => B.sighashTaproot(tx, 0, prev, v, {}), /BIP 341 allows/);
}

/* ---- witness version bounds in addresses ---- */
{
  const prog = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
  const bad = B.bechEncode('tb', [17].concat(B.convertBits(prog, 8, 5, true)), 'bech32m');
  throws('witness v17 address rejected', () => B.addressToScript(bad, 'testnet3'), /0–16/);
  const ok = B.bechEncode('tb', [2].concat(B.convertBits(prog, 8, 5, true)), 'bech32m');
  eq('witness v2 accepted', B.addressToScript(ok, 'testnet3').type, 'witness_unknown');
}

/* ---- pointFromPubkey on-curve validation ---- */
{
  const g = B.pointToUncompressed(B.G);
  eq('valid uncompressed accepted', B.toHex(B.pointToCompressed(B.pointFromPubkey(g))), B.toHex(B.pointToCompressed(B.G)));
  const badPt = new Uint8Array(g); badPt[40] ^= 1;   // corrupt a byte inside the y coordinate
  throws('off-curve uncompressed rejected', () => B.pointFromPubkey(badPt), /not a point on the secp256k1 curve/);
}

/* ---- scriptNum guards ---- */
{
  eq('scriptNum 2^40 exact', B.toHex(B.scriptNum(Math.pow(2, 40))), '000000000001');
  throws('scriptNum NaN rejected', () => B.scriptNum(NaN), /integer/);
  eq('scriptNum -255', B.toHex(B.scriptNum(-255)), 'ff80');
}

/* ---- legacy SIGHASH_SINGLE bug still reported (regression) ---- */
{
  const tx = {
    version: 1, locktime: 0,
    ins: [
      { txid: 'aa'.repeat(32), vout: 0, sequence: 0xffffffff, scriptSig: new Uint8Array(0), witness: [] },
      { txid: 'bb'.repeat(32), vout: 1, sequence: 0xffffffff, scriptSig: new Uint8Array(0), witness: [] }
    ],
    outs: [{ value: 1000, script: B.p2pkh(new Uint8Array(20)) }]
  };
  const r = B.sighashLegacy(tx, 1, B.p2pkh(new Uint8Array(20)), 0x03);
  eq('legacy SINGLE bug digest is constant 1', B.toHex(r.digest), '01' + '00'.repeat(31));
  eq('legacy SINGLE bug warned', /SIGHASH_SINGLE bug/.test(r.warning), true);
}

/* ---- serialize/parse round trip with witness ---- */
{
  const tx = {
    version: 2, locktime: 500,
    ins: [{ txid: 'cc'.repeat(32), vout: 3, sequence: 0xfffffffd, scriptSig: new Uint8Array(0), witness: [new Uint8Array(0), B.fromHex('aa'.repeat(71)), B.fromHex('5221ae')] }],
    outs: [{ value: 12345, script: B.p2wpkh(new Uint8Array(20).fill(7)) }]
  };
  const ser = B.serializeTx(tx);
  const back = B.parseTx(ser.bytes);
  eq('witness round trip (3 items, first empty)', back.ins[0].witness.map((w) => w.length).join(','), '0,71,3');
  eq('segwit flag detected', back.segwit, true);
  eq('txid excludes witness', B.txid(tx), B.toHex(B.rev(B.hash256(B.serializeTx(tx, { witness: false }).bytes))));
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
