# TXCRAFT — the Claude Design variant

An **independent sibling implementation of idleAnvil**: the same brief — *construct,
inspect and export Bitcoin transactions; never sign* — forged as a single
self-contained page by **Claude Fable through Claude Design**, then audited and
polished against the same verification bar as the main forge.

**Live demo: [idlebg.com/idleanvil/txcraft](https://idlebg.com/idleanvil/txcraft/)** ·
main forge: [idlebg.com/idleanvil](https://idlebg.com/idleanvil/) ·
[repo root](../../)

![TXCRAFT](../../docs/screenshots/07-txcraft.png)

## Running it

Open **`txcraft-standalone.html`** — one file, every dependency inlined (React, the
Claude Design runtime, all Bitcoin modules, the fonts). Works from `file://`, makes no
network requests unless you point the Chain tab at your own Fulcrum.

Two builds live here:

| File | What it is |
| --- | --- |
| `txcraft-standalone.html` | **the shippable artifact** — single file, fully offline |
| `Transaction Workbench.dc.html` | the Claude Design source document — runs only inside the Claude Design environment (it expects the host to provide React) |

## How it relates to idleAnvil

Same domain, same never-signs boundary, independently written code:

- **Own engine** — `btc-core.js` (hashing, encodings, secp256k1 point math),
  `btc-tx.js` (script, taproot trees, serialisation, legacy/BIP143/BIP341 sighash),
  `btc-psbt.js` (BIP174/BIP370/BIP371), `btc-fulcrum.js` (Electrum over WebSocket).
  Nothing is shared with `../../js/` — two implementations of the same BIPs that can
  be checked against each other.
- **Own architecture** — a declarative Claude Design template rendered by the
  generated `support.js` runtime (React underneath), versus idleAnvil's plain
  classic-script DOM. `support.js` is generated — do not edit it.
- **Own ideas worth stealing** — the byte-map Inspector driven by serializer marks,
  the depth-notation taproot tree input (`depth:leafversion:scripthex` per line), and
  *load-from-chain keeps the original scriptSig/witness under Finalize*, so a fetched
  transaction re-serialises byte-for-byte until you deliberately change something.

Cross-links run both ways: the TXCRAFT header carries an *idleAnvil variant* chip, and
idleAnvil's About dialog points back here.

## Fulcrum

The Chain tab speaks the Electrum protocol over WebSocket. In `fulcrum.conf`:

```conf
ws_port  = 50003      # plain — fine for localhost
wss_port = 50004      # TLS — needed if the page itself is served over https
```

A page served over `https:` cannot open `ws://` to a remote host (mixed content), but
browsers exempt `127.0.0.1` — so the hosted demo can still reach a local Fulcrum.
Fetch prevouts per input (or *hydrate every input*), pull any txid into the crafter,
list UTXOs by address, apply fee estimates, and broadcast — the only call that writes.

## Signing round trip

`Signing data` exports per-input JSON (`tool: "txcraft/1"`) with the preimage, digest
and `z`; `Finalize` accepts a signed PSBT, DER, r/s, a 64/65-byte Schnorr signature,
or signing JSON (single record or an array).

## Verification

```
node verify.js
```

**43 checks**, no dependencies: the BIP143 official P2WPKH vector, the BIP86 taproot
key/address vector, tapleaf-version masking, 17-of-20 CHECKMULTISIG encoding, ASM
number parsing, the strict BIP341 sighash-type set, witness-version bounds, on-curve
pubkey validation, the legacy SIGHASH_SINGLE bug contract, and serialisation round
trips.

### Corrected by the 2026-08 audit

The build arrived with a solid core (the BIP vectors passed untouched) and these
fixes applied on top: strict BIP341 sighash bytes (0x80 and friends now rejected and
flagged INVALID), CScriptNum encoding for 17–20-key multisig, the BIP147 empty dummy
in every multisig spend path, tapleaf version parity masking, witness versions capped
at 16 in address parsing, on-curve checks for uncompressed keys, P2TR dust corrected
to 330 sat (P2SH 540), **fee maths moved from the unsigned skeleton to an estimated
signed size** (the status bar now shows both), the sighash visualiser's taproot
sequences row, SIGHASH_SINGLE-without-output findings, a txid check on fetched
prevouts, and number handling in the ASM compiler.

State persists in `localStorage` under `txcraft.state.v1`; **Reset** clears it.
MIT, same as the repo.
