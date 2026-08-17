# ⚒️ idleAnvil

**An offline, single-page Bitcoin transaction forge** — crafter, PSBT workbench, sighash
debugger, script laboratory and forensic transaction analyser.

**It constructs, inspects and exports. It never signs.** There is no private-key field
and no signing code anywhere in the source — that separation is the whole point of the
design.

```
construct → inspect → compute signing data → export → sign elsewhere → import signatures → finalize
```

![idleAnvil — the Transaction workspace](docs/screenshots/01-transaction.png)

## Running it

Open `index.html` in Chrome, Edge or Firefox. That is the entire setup. No server, no
build step, no CDN, no dependencies — everything is plain classic scripts, so it works
straight off `file://`.

It makes **no network requests at all** unless you explicitly connect it to a node in
the **Node** workspace. The header pill always tells you which state you are in.

Workspaces deep-link: `index.html#multisig`, `#signing`, `#inspector`, `#script` … open
straight into that workspace.

## Workspaces

| Workspace | What it does |
| --- | --- |
| **Transaction** | nVersion, nLockTime (+ height/time interpretation), network, serialization, PSBT version, forensic switches, value-flow diagram, weight-budget meters |
| **Inputs** | Outpoints, prevout amount and script, redeem/witness scripts, full taproot block, per-input sighash and algorithm, manual scriptSig/witness, BIP32 derivations |
| **Outputs** | Address mode, 30 script templates, raw ASM↔hex, and a dedicated OP_RETURN builder |
| **Script Lab** | Opcode palette by category, drag-reorderable canvas, ASM ↔ hex, and derived P2SH / P2WSH / tapleaf values |
| **Signing Data** | Preimage, intermediate hashes, digest and `z` per input, plus the commitment breakdown |
| **PSBT Lab** | Build and decode BIP174 v0 / BIP370 v2, key-by-key structure view, Bitcoin Core command helpers |
| **Finalize** | Import signed PSBT / DER / Schnorr / r,s / signing JSON / raw tx; assemble scriptSig and witness |
| **Inspector** | Byte-level colour-coded decode; hover any byte to see its field |
| **Validation** | Consensus, structural and relay-policy findings, plus the sighash commitment matrix |
| **Raw Lab** | Hash calculator, DER surgery, address ↔ script, byte utilities, taproot bench, signature verification |
| **Toolkit** | Output descriptors, extended-key decoding, taproot tree builder, unit/base/time conversion, size estimator, pubkey tools, merkle root, script analyser |
| **Multisig** | m-of-n wallet crafter from public keys, with every script variant and a live address diff |
| **Node** | Optional live chain data over an Electrum WebSocket — fees, UTXOs, prevout fetch, guarded broadcast |

A fixed bottom console always shows size, vSize, weight, input/output totals, fee,
sat/vB, the live unsigned TX hex, the live PSBT base64, and validation status.

## Screenshots

| | |
| --- | --- |
| ![Signing Data](docs/screenshots/02-signing.png) **Signing Data** — preimage, digest and `z` per input, with the exact commitment breakdown | ![Script Lab](docs/screenshots/03-script-lab.png) **Script Lab** — opcode palette, syntax-highlighted ASM, derived P2SH/P2WSH/tapleaf forms |
| ![Inspector](docs/screenshots/04-inspector.png) **Inspector** — byte-level colour-coded decode of any transaction | ![Multisig](docs/screenshots/05-multisig.png) **Multisig crafter** — every m-of-n script variant at once, with a live address avalanche diff |
| ![Validation](docs/screenshots/06-validation.png) **Validation** — consensus and relay-policy findings plus the sighash commitment matrix | |

## Networks

**Mainnet** · Testnet3 · Testnet4 (BIP94) · Signet · Regtest — all five fully enabled,
with mainnet as the default. The network controls address encoding and validation;
change it at any time and addresses re-encode against the new network, with mismatches
flagged rather than silently accepted. Mainnet gets an amber ribbon reminding you the
values are live.

## Normal vs Forensic mode

Forensic mode unlocks the fields wallet software deliberately hides: manual scriptSig
and witness, arbitrary nVersion, non-minimal pushes, custom sighash bytes, duplicate
inputs, zero-value and dust outputs, malformed DER, high-S signatures, arbitrary opcodes
and raw script bytes.

Nothing is ever blocked. Every unusual construction is *labelled* instead:

- **VALID** — standard, will relay
- **NON-STANDARD** — consensus-valid but poorly relayed
- **INVALID** — consensus failure
- **UNKNOWN** — not enough information to judge

Use regtest or a testnet for experiments.

## Getting a signature back in

Five routes, all handled in **Finalize**:

1. **PSBT** — export, sign in Bitcoin Core / a hardware signer / any PSBT wallet, paste
   the result back. idleAnvil diffs it against the current transaction and reports which
   inputs gained a signature.
2. **DER signature** + public key — verified against `z` before being accepted.
3. **Schnorr signature** — 64 or 65 bytes, key path or script path.
4. **r / s** — DER-encoded for you, with optional low-S normalisation.
5. **Signing JSON** — the interchange format below.

### Signing JSON

Export from **Signing Data** (or Export → signing package):

```json
{
  "network": "testnet3",
  "input": 0,
  "txid": "…", "vout": 1, "amount": 10000,
  "scriptPubKey": "…", "scriptCode": "…",
  "sighash": "ALL", "sighashByte": "0x01",
  "algorithm": "ecdsa", "hashAlgorithm": "bip143",
  "preimage": "…", "digest": "…", "z": "…"
}
```

Return this shape and paste it into Finalize → Signing JSON:

```json
{ "input": 0, "r": "…", "s": "…", "der": "…", "pubkey": "…" }
```

or, for taproot:

```json
{ "input": 0, "schnorr": "…", "pubkey": "…", "leafHash": "…" }
```

The Signing workspace also generates ready-to-run signer snippets in six flavours —
Python/coincurve, Python/ecdsa, Python/python-bitcoinlib (which recomputes the sighash
independently and asserts it matches), JavaScript/@noble/curves, Bitcoin Core CLI, and
a verify-only variant. Each prints JSON in exactly the shape Finalize imports.

## Connecting a node (optional)

The Node workspace speaks the **Electrum protocol over WebSocket** (Fulcrum's
`ws = <port>` listener; a browser cannot open plain TCP or SSL Electrum ports).
Verified against Fulcrum 2.1.1.

What connecting adds: chain height and live block notifications · `estimatefee` across
1/2/3/6/12/25 blocks with one-click "use this rate" · UTXO lookup for any address or
script with one-click "add as input" · a **fetch prevout** button on every input that
fills in the amount, scriptPubKey and full parent transaction · raw transaction fetch
and decode · broadcast behind a mandatory confirmation (mainnet additionally requires
typing `BROADCAST`).

Off by default, genesis hash checked on connect, every request visible in the traffic
log, and still no private keys — the page holds none.

## What is implemented from scratch

SHA-256 · RIPEMD-160 · SHA-1 · BIP340 tagged hashes · secp256k1 point arithmetic ·
ECDSA verification · BIP340 Schnorr verification · Base58Check · Bech32 (BIP173) ·
Bech32m (BIP350) · transaction serialization (BIP144) · script assembler and
disassembler · CScriptNum · legacy signature hashing (including the SIGHASH_SINGLE
bug) · BIP143 · BIP341 SigMsg · BIP341 taproot tweaking, tapleaf and tapbranch
hashing · BIP174 · BIP370 · DER encode/decode with strictness and low-S analysis.

## Verification

```
node verify.js
```

No dependencies, Node 16+. The in-repo harness loads the exact browser modules and runs
**90 checks**: the BIP143 official P2WPKH worked example byte-for-byte, Bitcoin Core's
dust thresholds (546 / 540 / 294 / 330), OP_RETURN datacarrier policy at the exact
83-byte boundary, BIP341 sighash-byte validity (all seven legal types accepted,
everything else rejected), the sighash commitment matrix across algorithms,
multisig finalization (BIP147 empty dummy, key-ordered signatures, positional
CHECKSIGADD slots), BIP125 sequence semantics, size-estimator figures derived
byte-by-byte, BigInt-exact varints, and lossless-only unit conversion.

Run it after any change to `js/`.

## Files

```
index.html            markup, icon sprite, script tags
css/idleanvil.css     design system, light + dark themes
js/crypto.js          SHA-256, RIPEMD-160, SHA-1, secp256k1, taproot tweaks, DER, verification
js/encoding.js        hex, varint, base58check, bech32, bech32m, base64, byte reader/writer
js/script.js          opcodes, ASM assembler/disassembler, templates, address ↔ script, networks
js/tx.js              transaction model, serialization, weight accounting, raw decoding
js/sighash.js         legacy, BIP143 and BIP341 signature hashes + commitment model
js/psbt.js            BIP174 v0 and BIP370 v2 build / parse / describe / merge
js/validate.js        consensus + policy checks, and input finalization
js/tools.js           descriptors, extended keys, taproot trees, conversions, estimator, code generation
js/multisig.js        m-of-n construction from public keys
js/node.js            optional Electrum-over-WebSocket client
js/ui.js              state, rendering and wiring
verify.js             regression harness — `node verify.js`
```

## Caveats

- Size and fee figures for an unsigned transaction are **estimates** based on standard
  spend templates. Once real signatures are attached, the Finalize panel reports actual
  figures.
- Validation reports relay-policy defaults. Individual nodes and miners may differ.
- Verify anything independently before broadcasting on mainnet. This is a bench, not an
  authority.

## License

[MIT](LICENSE)
