/* ============================================================================
   ui.js — the workbench itself: state, rendering, wiring.
   Classic script (no modules) so the page works straight off file://
   ========================================================================== */
(function () {
  'use strict';
  const { bytesToHex, hexToBytes, satsToBtc, btcToSats, groupNum, bytesToBase64 } = ENC;
  const S = SCRIPT;

  /* =========================== tiny helpers ============================== */

  const $  = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const ico = (name, w = 14) =>
    `<svg viewBox="0 0 24 24" width="${w}" height="${w}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><use href="#i-${name}"/></svg>`;
  /** With an id, copies that element. With no id, copies the field it sits next to. */
  const copyIcon = (target) =>
    `<button class="iconbtn"${target ? ` data-copy-el="${target}"` : ''} title="Copy">${ico('copy')}</button>`;
  const copyVal = (value, title = 'Copy') =>
    `<button class="iconbtn" data-copy-val="${esc(value)}" title="${title}">${ico('copy')}</button>`;

  function toast(msg, kind = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + kind;
    t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(14px)'; }, 2600);
    setTimeout(() => t.remove(), 3000);
  }

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (_) { toast('Copy failed — select the text manually.', 'err'); }
      ta.remove();
    }
    if (btn) { btn.classList.add('copied'); setTimeout(() => btn.classList.remove('copied'), 900); }
    toast(text.length > 60 ? `Copied ${text.length} characters.` : `Copied: ${text}`);
  }

  function download(filename, data, mime = 'application/octet-stream') {
    const blob = data instanceof Uint8Array ? new Blob([data], { type: mime }) : new Blob([data], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Saved ${filename}`);
  }

  const safe = (fn, fallback = null) => { try { return fn(); } catch (e) { return fallback; } };
  const shortHex = (h, n = 10) => !h ? '—' : (h.length > n * 2 ? h.slice(0, n) + '…' + h.slice(-n) : h);
  const netOf = () => NETWORKS[state.tx.network] || NETWORKS.mainnet;

  /* ======================= semantic rendering helpers ==================== */

  /**
   * Render Bitcoin Script as coloured ASM. Opcodes are tinted by category,
   * data pushes are boxed, and every opcode carries its description on hover.
   */
  function hlAsm(scriptOrHex, opts = {}) {
    let script;
    try {
      script = scriptOrHex instanceof Uint8Array ? scriptOrHex : hexToBytes(scriptOrHex || '');
    } catch (e) { return `<span class="asm"><span class="err">${esc(e.message)}</span></span>`; }
    if (!script.length) return `<span class="asm mutedc">${esc(opts.empty || '(empty)')}</span>`;

    const { ops, error } = S.parseScript(script);
    const parts = ops.map(o => {
      if (o.data !== null && o.data !== undefined) {
        const hex = bytesToHex(o.data);
        const pre = o.op === 0x4c ? 'OP_PUSHDATA1 ' : o.op === 0x4d ? 'OP_PUSHDATA2 ' : o.op === 0x4e ? 'OP_PUSHDATA4 ' : '';
        if (!o.data.length) return `<span class="t op-push" title="empty push">OP_0</span>`;
        const label = (opts.trim && hex.length > opts.trim * 2)
          ? hex.slice(0, opts.trim) + '…' + hex.slice(-6) : hex;
        const ascii = printable(o.data);
        const title = `${o.data.length}-byte push${ascii ? ` — "${ascii}"` : ''}${o.minimal ? '' : ' — NON-MINIMAL encoding'}`;
        return (pre ? `<span class="t pushop">${pre.trim()}</span> ` : '') +
          `<span class="t data${o.data.length <= 8 ? ' small' : ''}${o.minimal ? '' : ' err'}" title="${esc(title)}">${label}</span>`;
      }
      if (o.op >= 0x51 && o.op <= 0x60)
        return `<span class="t num" title="pushes the number ${o.op - 0x50}">${o.name}</span>`;
      const cat = S.OP_CAT_OF[o.name] || 'unknown';
      const doc = S.OP_DOC[o.name] || `opcode 0x${o.op.toString(16).padStart(2, '0')}`;
      return `<span class="t op-${cat}" title="${esc(doc)}">${o.name}</span>`;
    });
    if (error) parts.push(`<span class="t err" title="parse failure">[${esc(error)}]</span>`);
    return `<span class="asm${opts.lg ? ' lg' : ''}">${parts.join(' ')}</span>`;
  }

  function printable(bytes) {
    if (!bytes.length || bytes.length > 64) return '';
    let s = '', printableCount = 0;
    for (const b of bytes) {
      if (b >= 0x20 && b < 0x7f) { s += String.fromCharCode(b); printableCount++; }
      else s += '·';
    }
    return printableCount / bytes.length > 0.8 ? s : '';
  }

  /** Colour a hex string by script structure: length prefixes, opcodes, data. */
  function hlHex(scriptOrHex) {
    let script;
    try { script = scriptOrHex instanceof Uint8Array ? scriptOrHex : hexToBytes(scriptOrHex || ''); }
    catch (e) { return `<span class="hexstr err">${esc(String(scriptOrHex))}</span>`; }
    if (!script.length) return '<span class="hexstr mutedc">—</span>';
    const { ops } = S.parseScript(script);
    let out = '', cursor = 0;
    for (const o of ops) {
      const head = script.slice(o.offset, o.data ? o.offset + o.size - o.data.length : o.offset + o.size);
      out += o.data
        ? `<span class="hx-len">${bytesToHex(head)}</span><span class="hx-data">${bytesToHex(o.data)}</span>`
        : `<span class="hx-op">${bytesToHex(head)}</span>`;
      cursor = o.offset + o.size;
    }
    if (cursor < script.length) out += `<span class="hx-data">${bytesToHex(script.slice(cursor))}</span>`;
    return `<span class="hexstr">${out}</span>`;
  }

  /** An amount with the integer and fractional parts styled separately. */
  function fmtAmt(sats, opts = {}) {
    const v = BigInt(sats || 0);
    const btc = satsToBtc(v);
    const [int, frac] = btc.split('.');
    let cls = '';
    if (v < 0n) cls = 'neg';
    else if (v === 0n) cls = 'zero';
    else if (opts.dustLimit && v < opts.dustLimit) cls = 'dust';
    else if (v >= 100000000n) cls = 'big';
    return `<span class="amt ${cls}"><span class="int">${esc(int)}</span><span class="frac">.${esc(frac)}</span>` +
      `<span class="unit">${esc(opts.unit || netOf().coin)}</span></span>`;
  }
  const fmtSat = (sats, opts = {}) => {
    const v = BigInt(sats || 0);
    let cls = '';
    if (v < 0n) cls = 'neg'; else if (v === 0n) cls = 'zero';
    else if (opts.dustLimit && v < opts.dustLimit) cls = 'dust';
    return `<span class="amt ${cls}"><span class="int">${groupNum(v)}</span><span class="unit">sat</span></span>`;
  };

  /** Classify a kv value so it can be tinted by what it is. */
  function valueClass(v) {
    const s = String(v);
    if (/^(bc|tb|bcrt)1[a-z0-9]{20,}$/i.test(s) || /^[13mn2][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(s)) return 'v-addr';
    if (/^[0-9a-f]{64}$/i.test(s)) return 'v-hash';
    if (/^-?[\d,]+(\s|$)/.test(s)) return 'v-num';
    if (/^(⚠|error|invalid|NO —)/i.test(s)) return 'v-warn';
    return '';
  }

  /** A horizontal meter. segments: [[className, fraction], …] */
  function meter(segments) {
    return `<div class="meter">${segments.map(([c, f]) =>
      `<i class="${c}" style="width:${Math.max(0, Math.min(100, f * 100)).toFixed(2)}%"></i>`).join('')}</div>`;
  }

  const tile = (k, v, note, cls = '') =>
    `<div class="tile ${cls}"><div class="tk">${esc(k)}</div><div class="tv">${v}</div>${note ? `<div class="tn">${note}</div>` : ''}</div>`;

  /* =============================== state ================================= */

  const state = {
    tx: TX.newTx(),
    mode: 'normal',
    ws: 'transaction',
    signingIndex: 0,
    matrixIndex: 0,
    canvas: [],
    opCat: 'crypto',
    psbtVersion: 0,
    importTab: 'psbt',
    inspectSrc: 'current',
    lastDecoded: null,
    refreshers: []
  };

  const FORENSIC_FLAGS = [
    ['manualScriptSig',   'Manually specify scriptSig',      'Unlocks a raw scriptSig field on every input.'],
    ['manualWitness',     'Manually specify witness',        'Unlocks a raw witness stack editor on every input.'],
    ['unusualSequence',   'Unusual sequence values',         'Removes the guard rails on nSequence.'],
    ['arbitraryVersion',  'Arbitrary transaction version',   'Allows any int32 nVersion, including negative.'],
    ['nonMinimalPush',    'Non-minimal pushes',              'Lets the OP_RETURN builder and Script Lab emit oversized push encodings.'],
    ['customSighash',     'Custom sighash byte',             'Type an arbitrary sighash byte per input.'],
    ['uncompressedPubkey','Uncompressed public keys',        'Accept 65-byte keys in templates without warning.'],
    ['arbitraryOpcode',   'Arbitrary opcodes',               'Adds reserved and disabled opcodes to the palette.'],
    ['arbitraryBytes',    'Arbitrary script bytes',          'Allows 0x-prefixed raw byte injection in ASM.'],
    ['zeroValue',         'Zero-value outputs',              'Stops zero amounts being clamped.'],
    ['dustOutput',        'Dust outputs',                    'Stops dust amounts being clamped.'],
    ['duplicateInputs',   'Duplicate inputs',                'Permits the same outpoint twice.'],
    ['emptyScripts',      'Empty scriptSig / witness',       'Permits deliberately empty unlocking data on a final transaction.'],
    ['malformedDER',      'Malformed DER experiment',        'Imports signatures that fail strict DER instead of rejecting them.'],
    ['highS',             'High-S signatures',               'Accepts signatures above N/2 without normalising.'],
    ['unusualWitnessProg','Unusual witness programs',        'Allows witness versions 2–16 and odd program lengths.'],
    ['unusualOrdering',   'Unusual output ordering',         'Enables manual reordering of inputs and outputs.']
  ];

  /** Well-known OP_RETURN payload prefixes, as a starting point for the payload field. */
  const OPRETURN_PREFIXES = [
    { label: 'none',    hex: '',         note: 'plain data, no protocol marker' },
    { label: 'Omni',    hex: '6f6d6e69', note: 'Omni Layer — "omni"' },
    { label: 'Stacks',  hex: '5832',     note: 'Stacks — "X2"' },
    { label: 'RUNE',    hex: '52554e45', note: 'Runestone marker — "RUNE"' },
    { label: 'SPK',     hex: '53504b',   note: 'Simple Proof of Knowledge — "SPK"' },
    { label: 'DOC',     hex: '444f4350', note: 'document timestamp — "DOCP"' },
    { label: 'OA',      hex: '4f41',     note: 'Open Assets — "OA"' }
  ];

  const SPEND_TYPES = [
    ['auto', 'AUTO — detect from scriptPubKey'], ['p2pk', 'P2PK'], ['p2pkh', 'P2PKH'], ['p2sh', 'P2SH'],
    ['p2wpkh', 'P2WPKH'], ['p2wsh', 'P2WSH'], ['p2sh-p2wpkh', 'P2SH-P2WPKH'], ['p2sh-p2wsh', 'P2SH-P2WSH'],
    ['p2tr', 'P2TR'], ['custom', 'CUSTOM']
  ];

  /* ------------------------------------------------------- path binding */

  function setPath(obj, path, value) {
    const parts = path.split('.');
    let o = obj;
    for (let i = 0; i < parts.length - 1; i++) {
      if (o[parts[i]] === undefined || o[parts[i]] === null) o[parts[i]] = {};
      o = o[parts[i]];
    }
    o[parts[parts.length - 1]] = value;
  }
  function getPath(obj, path) {
    return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
  }
  function coerce(raw, type) {
    switch (type) {
      case 'int': { const n = parseInt(raw, 10); return isNaN(n) ? 0 : n; }
      case 'float': { const n = parseFloat(raw); return isNaN(n) ? 0 : n; }
      case 'bigint': { try { return BigInt(String(raw).replace(/[\s,_]/g, '') || '0'); } catch (e) { return 0n; } }
      case 'hexnum': { const n = parseInt(String(raw).replace(/^0x/i, ''), 16); return isNaN(n) ? 0 : n >>> 0; }
      case 'hex': return String(raw).replace(/[\s:,]/g, '').toLowerCase();
      case 'bool': return !!raw;
      default: return raw;
    }
  }

  /* ============================ persistence ============================== */

  const STORE_KEY = 'idleanvil-v1';

  function serializeState() {
    return JSON.stringify({
      tx: state.tx, mode: state.mode, canvas: state.canvas,
      theme: document.documentElement.dataset.theme
    }, (k, v) => typeof v === 'bigint' ? { __big: v.toString() } : v);
  }
  function reviveState(json) {
    return JSON.parse(json, (k, v) => (v && typeof v === 'object' && v.__big !== undefined) ? BigInt(v.__big) : v);
  }
  function persist() { safe(() => localStorage.setItem(STORE_KEY, serializeState())); }
  function restore() {
    const raw = safe(() => localStorage.getItem(STORE_KEY));
    if (!raw) return false;
    const d = safe(() => reviveState(raw));
    if (!d || !d.tx) return false;
    state.tx = normaliseTx(d.tx);
    state.mode = d.mode || 'normal';
    state.canvas = d.canvas || [];
    if (d.theme) document.documentElement.dataset.theme = d.theme;
    return true;
  }
  /** Fill in any fields added since the project was saved. */
  function normaliseTx(tx) {
    const base = TX.newTx();
    const out = Object.assign({}, base, tx);
    out.forensic = Object.assign({}, tx.forensic || {});
    out.inputs = (tx.inputs || []).map(i => {
      const n = Object.assign(TX.newInput(), i);
      n.taproot = Object.assign(TX.newInput().taproot, i.taproot || {});
      n.amount = BigInt(i.amount || 0);
      n.witness = i.witness || [];
      n.partialSigs = i.partialSigs || [];
      n.tapScriptSigs = i.tapScriptSigs || [];
      n.bip32 = i.bip32 || [];
      return n;
    });
    if (!out.inputs.length) out.inputs = [TX.newInput()];
    out.outputs = (tx.outputs || []).map(o => {
      const n = Object.assign(TX.newOutput(), o);
      n.opret = Object.assign(TX.newOutput().opret, o.opret || {});
      n.templateVals = o.templateVals || {};
      n.amount = BigInt(o.amount || 0);
      return n;
    });
    if (!out.outputs.length) out.outputs = [TX.newOutput()];
    return out;
  }

  /* ============================ workspaces =============================== */

  function showWorkspace(name) {
    state.ws = name;
    $$('.workspace').forEach(w => w.classList.toggle('active', w.id === 'ws-' + name));
    $$('.navitem').forEach(n => n.classList.toggle('active', n.dataset.ws === name));
    if (name === 'signing') { renderSigning(); renderCode(); }
    if (name === 'psbt') renderPsbt();
    if (name === 'finalize') renderFinalize();
    if (name === 'validation') renderValidation();
    if (name === 'inspector') runInspector();
    if (name === 'script') renderScriptLab();
    if (name === 'toolkit') renderToolkit();
    if (name === 'multisig') renderMultisig({ reason: 'opened' });
    if (name === 'node') renderNode();
    if (name === 'transaction') { renderFlow(); renderTiles(); renderRibbon(); }
    renderPipeline();
    $('#stage').scrollTop = 0;
  }

  /* ============================== header ================================= */

  function bindHeader() {
    const tx = state.tx;
    $('#f-network').value = tx.network;
    $('#f-version').value = tx.version;
    $('#f-locktime').value = tx.locktime;
    $('#f-locktime-mode').value = tx.locktimeMode;
    $('#f-serialization').value = tx.serialization;
    $('#f-psbt-version').value = String(tx.psbtVersion);
    $('#f-feerate').value = tx.feeRate;

    $('#f-network').onchange = (e) => {
      const prev = state.tx.network;
      state.tx.network = e.target.value;
      renderAll();
      /* a live connection is chain-specific — say so rather than serving wrong data silently */
      if (nc().connected && prev !== state.tx.network) {
        const want = NODE.GENESIS[state.tx.network];
        if (nc().info.genesis && want && nc().info.genesis !== want) {
          nc().info.chainMatch = false;
          nc().info.chainMismatch = `the connected server is not ${state.tx.network}`;
          renderNodeStatus();
          toast(`Still connected to the ${prev} server — reconnect from the Node workspace for ${netOf().label}.`, 'warn');
        }
      }
    };
    $('#f-version').oninput = (e) => {
      let v = parseInt(e.target.value, 10) || 0;
      if (!state.tx.forensic.arbitraryVersion) v = Math.max(1, Math.min(3, v));
      state.tx.version = v;
      if (v !== parseInt(e.target.value, 10)) e.target.value = v;
      update();
    };
    $('#f-locktime').oninput = (e) => {
      let v = parseInt(e.target.value, 10) || 0;
      state.tx.locktime = Math.max(0, Math.min(4294967295, v));
      state.tx.locktimeMode = state.tx.locktime === 0 ? 'disabled'
        : state.tx.locktime < TX.LOCKTIME_THRESHOLD ? 'height' : 'time';
      $('#f-locktime-mode').value = state.tx.locktimeMode;
      update();
    };
    $('#f-locktime-mode').onchange = (e) => {
      state.tx.locktimeMode = e.target.value;
      if (e.target.value === 'disabled') { state.tx.locktime = 0; $('#f-locktime').value = 0; }
      else if (e.target.value === 'time' && state.tx.locktime < TX.LOCKTIME_THRESHOLD) {
        state.tx.locktime = Math.floor(Date.now() / 1000); $('#f-locktime').value = state.tx.locktime;
      } else if (e.target.value === 'height' && state.tx.locktime >= TX.LOCKTIME_THRESHOLD) {
        state.tx.locktime = 800000; $('#f-locktime').value = state.tx.locktime;
      }
      update();
    };
    $('#f-serialization').onchange = (e) => { state.tx.serialization = e.target.value; update(); };
    $('#f-psbt-version').onchange = (e) => {
      state.tx.psbtVersion = parseInt(e.target.value, 10);
      state.psbtVersion = state.tx.psbtVersion;
      $$('#psbt-ver-seg button').forEach(b => b.classList.toggle('on', b.dataset.v === e.target.value));
      update();
    };
    $('#f-feerate').oninput = (e) => { state.tx.feeRate = parseFloat(e.target.value) || 0; update(); };
  }

  function renderForensicControls() {
    $('#forensic-controls').innerHTML = FORENSIC_FLAGS.map(([k, label, help]) => `
      <label class="toggle" title="${esc(help)}">
        <span class="lbl">${esc(label)}</span>
        <input type="checkbox" class="switch" data-forensic="${k}" ${state.tx.forensic[k] ? 'checked' : ''}>
      </label>`).join('');
  }

  /* ============================== INPUTS ================================= */

  function renderInputs() {
    const list = $('#inputs-list');
    if (!state.tx.inputs.length) {
      list.innerHTML = `<div class="empty-note">No inputs yet. Add one to start.</div>`;
      return;
    }
    list.innerHTML = state.tx.inputs.map((inp, i) => inputCard(inp, i)).join('');
  }

  function inputCard(inp, i) {
    const f = state.tx.forensic;
    const spk = safe(() => hexToBytes(inp.scriptPubKey), null);
    const cls = spk ? S.classify(spk) : { type: 'EMPTY' };
    const typeTag = cls.type === 'EMPTY'
      ? `<span class="tag grey">no prevout script</span>`
      : `<span class="tag ${cls.standard ? 'teal' : 'amber'}">${cls.type}</span>`;
    const badges = [];
    if ((inp.sequence >>> 0) < 0xfffffffe) badges.push(`<span class="tag blue">RBF</span>`);
    if ((inp.sequence >>> 0) !== 0xffffffff && (inp.sequence >>> 0) !== 0xfffffffd && (inp.sequence >>> 0) !== 0xfffffffe)
      badges.push(`<span class="tag amber">UNUSUAL SEQUENCE</span>`);
    if (inp.manualScriptSig || inp.manualWitness) badges.push(`<span class="tag pink">MANUAL UNLOCK</span>`);
    const sigCount = (inp.partialSigs || []).length + (inp.tapKeySig ? 1 : 0) + (inp.tapScriptSigs || []).length;
    if (sigCount) badges.push(`<span class="tag green">${sigCount} SIG</span>`);

    const isTr = cls.type === 'P2TR' || inp.spendType === 'p2tr';

    return `
<div class="card ${inp.collapsed ? '' : 'open'}" data-card="in" data-idx="${i}">
  <div class="card-head" data-act="toggle-card">
    <span class="idx">INPUT #${i}</span>
    ${typeTag} ${badges.join(' ')}
    <span class="meta">${inp.txid ? shortHex(inp.txid, 8) + ':' + inp.vout : 'no outpoint set'}</span>
    ${fmtSat(inp.amount)}
    <div class="tools">
      <button class="iconbtn" data-act="dup-input" data-idx="${i}" title="Duplicate">${ico('copy')}</button>
      <button class="iconbtn" data-act="move-input-up" data-idx="${i}" title="Move up" style="transform:rotate(180deg)">${ico('chevron')}</button>
      <button class="iconbtn" data-act="del-input" data-idx="${i}" title="Remove">${ico('trash')}</button>
      <span class="chev">${ico('chevron')}</span>
    </div>
  </div>
  <div class="card-body">
    <div class="row r4">
      <div class="field" style="grid-column:span 2">
        <label>Previous TXID <span class="hint">32 bytes, display order</span></label>
        <div class="with-copy">
          <input type="text" class="mono ${inp.txid && !/^[0-9a-f]{64}$/i.test(inp.txid) ? 'err' : ''}"
                 data-bind="in:${i}:txid" data-type="hex" value="${esc(inp.txid)}" placeholder="64 hex characters">
          ${copyIcon('')}
        </div>
      </div>
      <div class="field"><label>VOUT</label>
        <input type="number" min="0" data-bind="in:${i}:vout" data-type="int" value="${inp.vout}"></div>
      <div class="field"><label>Prevout amount <span class="hint">sat</span></label>
        <input type="text" class="mono" data-bind="in:${i}:amount" data-type="bigint" value="${inp.amount}"></div>
    </div>
    <div class="flexrow mt">
      <button class="btn sm" data-act="fetch-prevout" data-idx="${i}"
        title="Look this outpoint up on the connected node and fill in the amount, script and parent transaction">
        ${ico('plug')} Fetch prevout from node</button>
      <span class="hint-text">${inp.prevTxHex ? 'parent transaction cached — PSBT will carry the non-witness UTXO' : ''}</span>
    </div>

    <div class="row r4 mt">
      <div class="field">
        <label>nSequence <span class="hint">hex</span></label>
        <input type="text" class="mono" data-bind="in:${i}:sequence" data-type="hexnum"
               value="${(inp.sequence >>> 0).toString(16).padStart(8, '0')}">
      </div>
      <div class="field" style="grid-column:span 2">
        <label>Sequence presets</label>
        <div class="seg full">
          <button data-act="seq" data-idx="${i}" data-v="ffffffff" class="${(inp.sequence >>> 0) === 0xffffffff ? 'on' : ''}">Final</button>
          <button data-act="seq" data-idx="${i}" data-v="fffffffd" class="${(inp.sequence >>> 0) === 0xfffffffd ? 'on' : ''}">RBF</button>
          <button data-act="seq" data-idx="${i}" data-v="fffffffe" class="${(inp.sequence >>> 0) === 0xfffffffe ? 'on' : ''}">Locktime only</button>
          <button data-act="seq" data-idx="${i}" data-v="00000090" class="${(inp.sequence >>> 0) === 0x90 ? 'on' : ''}">CSV 144</button>
        </div>
      </div>
      <div class="field"><label>Spending template</label>
        <select data-bind="in:${i}:spendType" data-structural="1">
          ${SPEND_TYPES.map(([v, l]) => `<option value="${v}" ${inp.spendType === v ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="hint-text mt" data-role="seq-note-${i}">${esc(TX.describeSequence(inp.sequence >>> 0))}</div>

    <div class="field mt">
      <label>Prevout scriptPubKey <span class="hint">hex — the script being spent</span></label>
      <div class="with-copy">
        <input type="text" class="mono" data-bind="in:${i}:scriptPubKey" data-type="hex" data-structural="1"
               value="${esc(inp.scriptPubKey)}" placeholder="0014… / 76a914…88ac / 5120…">
        ${copyIcon('')}
      </div>
      <div class="hint-text" data-role="spk-asm-${i}">${spk ? hlAsm(spk, { trim: 24 }) : ''}</div>
    </div>

    <div class="row r2 mt">
      <div class="field">
        <label>redeemScript <span class="hint">P2SH</span></label>
        <input type="text" class="mono" data-bind="in:${i}:redeemScript" data-type="hex" data-structural="1"
               value="${esc(inp.redeemScript)}" placeholder="required for P2SH spends">
      </div>
      <div class="field">
        <label>witnessScript <span class="hint">P2WSH</span></label>
        <input type="text" class="mono" data-bind="in:${i}:witnessScript" data-type="hex" data-structural="1"
               value="${esc(inp.witnessScript)}" placeholder="required for P2WSH spends">
      </div>
    </div>

    ${isTr ? taprootBlock(inp, i) : ''}

    <details class="disclosure" ${inp._openSig ? 'open' : ''}>
      <summary>Signature settings</summary>
      <div class="dbody">
        <div class="row r4">
          <div class="field"><label>Algorithm</label>
            <select data-bind="in:${i}:algorithm" data-structural="1">
              <option value="ecdsa" ${inp.algorithm === 'ecdsa' ? 'selected' : ''}>ECDSA (secp256k1)</option>
              <option value="schnorr" ${inp.algorithm === 'schnorr' ? 'selected' : ''}>Schnorr (BIP340)</option>
            </select>
          </div>
          <div class="field"><label>SIGHASH type</label>
            <select data-bind="in:${i}:sighashType" data-type="int" data-structural="1">
              <option value="0" ${inp.sighashType === 0 ? 'selected' : ''}>DEFAULT (0x00) — taproot</option>
              <option value="1" ${inp.sighashType === 1 ? 'selected' : ''}>ALL (0x01)</option>
              <option value="2" ${inp.sighashType === 2 ? 'selected' : ''}>NONE (0x02)</option>
              <option value="3" ${inp.sighashType === 3 ? 'selected' : ''}>SINGLE (0x03)</option>
            </select>
          </div>
          <div class="field"><label>&nbsp;</label>
            <label class="check"><input type="checkbox" data-bind="in:${i}:sighashAnyoneCanPay" data-type="bool" data-structural="1"
              ${inp.sighashAnyoneCanPay ? 'checked' : ''}> ANYONECANPAY (| 0x80)</label>
          </div>
          <div class="field forensic-only"><label>Custom sighash byte <span class="hint">hex, overrides</span></label>
            <input type="text" class="mono" data-bind="in:${i}:sighashCustom" data-structural="1"
                   value="${esc(inp.sighashCustom)}" placeholder="e.g. 41" ${f.customSighash ? '' : 'disabled'}>
          </div>
        </div>
        <div class="hint-text mt" data-role="sig-note-${i}"></div>
        <div class="field mt forensic-only"><label>scriptCode override <span class="hint">bypasses derivation</span></label>
          <input type="text" class="mono" data-bind="in:${i}:scriptCodeOverride" data-type="hex" data-structural="1" value="${esc(inp.scriptCodeOverride)}">
        </div>
      </div>
    </details>

    <details class="disclosure">
      <summary>Unlocking data — scriptSig &amp; witness</summary>
      <div class="dbody">
        <div class="flexrow mb">
          <label class="check"><input type="checkbox" data-bind="in:${i}:manualScriptSig" data-type="bool" data-structural="1" ${inp.manualScriptSig ? 'checked' : ''}> Manual scriptSig</label>
          <label class="check"><input type="checkbox" data-bind="in:${i}:manualWitness" data-type="bool" data-structural="1" ${inp.manualWitness ? 'checked' : ''}> Manual witness</label>
          <button class="btn sm" data-act="finalize-one" data-idx="${i}">Assemble from signatures</button>
        </div>
        <div class="field">
          <label>scriptSig <span class="hint">hex</span></label>
          <input type="text" class="mono" data-bind="in:${i}:scriptSig" data-type="hex" data-structural="1"
                 value="${esc(inp.scriptSig)}" ${inp.manualScriptSig ? '' : 'readonly'}>
          <div class="hint-text">${inp.scriptSig ? hlAsm(inp.scriptSig, { trim: 20 }) : '<span class="mutedc">empty</span>'}</div>
        </div>
        <div class="mt">
          <div class="subhead">Witness stack (${(inp.witness || []).length} item${(inp.witness || []).length === 1 ? '' : 's'})</div>
          ${(inp.witness || []).map((w, wi) => `
            <div class="witness-item">
              <span class="n">${wi}</span>
              <input type="text" class="mono" data-bind="in:${i}:witness.${wi}" data-type="hex" value="${esc(w)}" ${inp.manualWitness ? '' : 'readonly'}>
              <button class="iconbtn" data-act="del-witness" data-idx="${i}" data-wi="${wi}">${ico('x')}</button>
            </div>`).join('') || '<div class="hint-text">No witness items.</div>'}
          ${inp.manualWitness ? `<button class="btn sm mt" data-act="add-witness" data-idx="${i}">${ico('plus')} Add witness item</button>` : ''}
        </div>
      </div>
    </details>

    <details class="disclosure">
      <summary>Signatures &amp; key derivation (for PSBT)</summary>
      <div class="dbody">
        <div class="subhead">Partial signatures</div>
        ${(inp.partialSigs || []).map((ps, si) => `
          <div class="row r2 mb">
            <div class="field"><label>Public key ${si}</label><input type="text" class="mono" data-bind="in:${i}:partialSigs.${si}.pubkey" data-type="hex" value="${esc(ps.pubkey)}"></div>
            <div class="field"><label>Signature (DER + sighash byte)
              <button class="iconbtn" data-act="del-sig" data-idx="${i}" data-si="${si}">${ico('x')}</button></label>
              <input type="text" class="mono" data-bind="in:${i}:partialSigs.${si}.signature" data-type="hex" value="${esc(ps.signature)}"></div>
          </div>`).join('') || '<div class="hint-text mb">None yet — import them in Finalize.</div>'}
        <button class="btn sm" data-act="add-sig" data-idx="${i}">${ico('plus')} Add signature slot</button>

        ${isTr ? `
        <div class="subhead mt-lg">Taproot signatures</div>
        <div class="field"><label>Key-path Schnorr signature (64 or 65 bytes)</label>
          <input type="text" class="mono" data-bind="in:${i}:tapKeySig" data-type="hex" value="${esc(inp.tapKeySig)}"></div>` : ''}

        <div class="subhead mt-lg">BIP32 derivation</div>
        ${(inp.bip32 || []).map((d, di) => `
          <div class="row r3 mb">
            <div class="field"><label>Pubkey</label><input type="text" class="mono" data-bind="in:${i}:bip32.${di}.pubkey" data-type="hex" value="${esc(d.pubkey)}"></div>
            <div class="field"><label>Master fingerprint</label><input type="text" class="mono" data-bind="in:${i}:bip32.${di}.fingerprint" data-type="hex" value="${esc(d.fingerprint)}" placeholder="8 hex"></div>
            <div class="field"><label>Path <button class="iconbtn" data-act="del-bip32" data-idx="${i}" data-di="${di}">${ico('x')}</button></label>
              <input type="text" class="mono" data-bind="in:${i}:bip32.${di}.path" value="${esc(d.path)}" placeholder="m/84'/0'/0'/0/0"></div>
          </div>`).join('') || '<div class="hint-text mb">None.</div>'}
        <button class="btn sm" data-act="add-bip32" data-idx="${i}">${ico('plus')} Add derivation</button>

        <div class="field mt-lg"><label>Full previous transaction <span class="hint">hex — PSBT non-witness UTXO, required by some signers for legacy inputs</span></label>
          <textarea class="mono" rows="2" data-bind="in:${i}:prevTxHex" data-type="hex">${esc(inp.prevTxHex)}</textarea></div>
      </div>
    </details>

    <details class="disclosure">
      <summary>Derived signing context</summary>
      <div class="dbody"><dl class="kv" data-role="in-derived-${i}"></dl></div>
    </details>
  </div>
</div>`;
  }

  function taprootBlock(inp, i) {
    const tr = inp.taproot || {};
    return `
    <div class="disclosure" style="border-top-color:var(--violet)">
      <div class="subhead" style="color:var(--violet)">Taproot (BIP341)</div>
      <div class="row r4">
        <div class="field"><label>Spend path</label>
          <select data-bind="in:${i}:taproot.path" data-structural="1">
            <option value="key" ${tr.path === 'key' ? 'selected' : ''}>Key path</option>
            <option value="script" ${tr.path === 'script' ? 'selected' : ''}>Script path</option>
          </select>
        </div>
        <div class="field" style="grid-column:span 2"><label>Internal key <span class="hint">32-byte x-only</span></label>
          <input type="text" class="mono" data-bind="in:${i}:taproot.internalKey" data-type="hex" data-structural="1" value="${esc(tr.internalKey)}"></div>
        <div class="field"><label>Leaf version</label>
          <input type="text" class="mono" data-bind="in:${i}:taproot.leafVersion" data-type="hexnum" value="${(Number(tr.leafVersion) || 0xc0).toString(16)}"></div>
      </div>
      <div class="row r2 mt">
        <div class="field"><label>Merkle root <span class="hint">empty = key-path only</span></label>
          <input type="text" class="mono" data-bind="in:${i}:taproot.merkleRoot" data-type="hex" data-structural="1" value="${esc(tr.merkleRoot)}"></div>
        <div class="field"><label>Tapleaf script <span class="hint">hex, script path</span></label>
          <input type="text" class="mono" data-bind="in:${i}:taproot.leafScript" data-type="hex" data-structural="1" value="${esc(tr.leafScript)}"></div>
      </div>
      <div class="row r2 mt">
        <div class="field"><label>Control block</label>
          <input type="text" class="mono" data-bind="in:${i}:taproot.controlBlock" data-type="hex" value="${esc(tr.controlBlock)}"></div>
        <div class="field"><label>Annex <span class="hint">0x50-prefixed, rarely used</span></label>
          <input type="text" class="mono" data-bind="in:${i}:taproot.annex" data-type="hex" value="${esc(tr.annex)}"></div>
      </div>
      <dl class="kv mt" data-role="tr-derived-${i}"></dl>
    </div>`;
  }

  /** Update the read-only bits inside input cards without touching focus. */
  function refreshInputCards() {
    state.tx.inputs.forEach((inp, i) => {
      const seqNote = $(`[data-role="seq-note-${i}"]`);
      if (seqNote) seqNote.textContent = TX.describeSequence(inp.sequence >>> 0);

      const asm = $(`[data-role="spk-asm-${i}"]`);
      if (asm) asm.innerHTML = inp.scriptPubKey ? hlAsm(inp.scriptPubKey, { trim: 24 }) : '';

      const sigNote = $(`[data-role="sig-note-${i}"]`);
      if (sigNote) {
        const t = SIGHASH.effectiveType(inp);
        sigNote.innerHTML = `Effective sighash byte <span class="accent mono">0x${t.toString(16).padStart(2, '0')}</span> — ${esc(SIGHASH.nameOf(t))}`;
      }

      const trBox = $(`[data-role="tr-derived-${i}"]`);
      if (trBox) {
        const tr = inp.taproot || {};
        const rows = [];
        if (tr.internalKey) {
          try {
            const t = BC.taprootTweak(hexToBytes(tr.internalKey), tr.merkleRoot ? hexToBytes(tr.merkleRoot) : null);
            rows.push(['Output key', bytesToHex(t.outputKey)]);
            rows.push(['Parity', String(t.parity)]);
            rows.push(['TapTweak', bytesToHex(t.tweak)]);
            rows.push(['scriptPubKey', bytesToHex(S.p2tr(t.outputKey))]);
            const addr = S.scriptToAddress(S.p2tr(t.outputKey), state.tx.network);
            if (addr) rows.push(['Address', addr]);
          } catch (e) { rows.push(['Tweak error', e.message]); }
        }
        if (tr.leafScript) {
          try {
            const lh = BC.tapLeafHash(hexToBytes(tr.leafScript), Number(tr.leafVersion) || 0xc0);
            rows.push(['TapLeaf hash', bytesToHex(lh)]);
            rows.push(['Leaf ASM', S.toAsm(hexToBytes(tr.leafScript))]);
          } catch (e) { rows.push(['Leaf error', e.message]); }
        }
        trBox.innerHTML = rows.length ? kvRows(rows) : '<dt class="mutedc">—</dt><dd>fill in the internal key</dd>';
      }

      const der = $(`[data-role="in-derived-${i}"]`);
      if (der) {
        const rows = [];
        const sc = S.deriveScriptCode(inp);
        rows.push(['scriptCode', sc.scriptCode ? bytesToHex(sc.scriptCode) : '— ' + sc.note]);
        if (sc.scriptCode) rows.push(['scriptCode ASM', S.toAsm(sc.scriptCode)]);
        rows.push(['Algorithm', sc.kind === 'bip341' ? 'BIP341 tapsighash' : sc.kind === 'bip143' ? 'BIP143 (segwit v0)' : 'legacy']);
        const est = TX.estimateInputSpend(inp);
        rows.push(['Estimated unlock', `${est.scriptSig} B scriptSig · ${est.witness} B witness`]);
        if (inp.scriptPubKey) {
          const addr = safe(() => S.scriptToAddress(hexToBytes(inp.scriptPubKey), state.tx.network));
          if (addr) rows.push(['Prevout address', addr]);
        }
        der.innerHTML = kvRows(rows);
      }
    });
  }

  const kvRows = (rows) => rows.map(([k, v, forceClass]) =>
    `<dt>${esc(k)}</dt><dd class="brk ${forceClass || valueClass(v)}">${esc(v)}` +
    `${String(v).length > 16 ? ' ' + copyVal(String(v)) : ''}</dd>`).join('');

  /* ============================== OUTPUTS ================================ */

  function renderOutputs() {
    const list = $('#outputs-list');
    if (!state.tx.outputs.length) { list.innerHTML = `<div class="empty-note">No outputs yet.</div>`; return; }
    list.innerHTML = state.tx.outputs.map((o, i) => outputCard(o, i)).join('');
  }

  function outputCard(out, i) {
    const r = TX.resolveOutput(out, state.tx.network);
    const cls = r.script && r.script.length ? S.classify(r.script) : { type: 'EMPTY', standard: false };
    const amt = BigInt(out.amount || 0);
    let badge = `<span class="tag ${cls.standard ? 'teal' : 'amber'}">${cls.type}</span>`;
    if (r.error) badge = `<span class="tag red">ERROR</span>`;
    const extra = [];
    if (!r.error && cls.type !== 'OP_RETURN' && amt > 0n && amt < VALIDATE.dustThreshold(r.script)) extra.push(`<span class="tag amber">DUST</span>`);
    if (!r.error && cls.type !== 'OP_RETURN' && amt === 0n) extra.push(`<span class="tag amber">ZERO VALUE</span>`);

    return `
<div class="card ${out.collapsed ? '' : 'open'}" data-card="out" data-idx="${i}">
  <div class="card-head" data-act="toggle-card">
    <span class="idx">OUTPUT #${i}</span>
    ${badge} ${extra.join(' ')}
    ${fmtSat(amt, { dustLimit: r.script && r.script.length ? VALIDATE.dustThreshold(r.script) : 0n })}
    <span class="meta">${satsToBtc(amt)} ${netOf().coin}</span>
    <div class="tools">
      <button class="iconbtn" data-act="dup-output" data-idx="${i}" title="Duplicate">${ico('copy')}</button>
      <button class="iconbtn" data-act="move-output-up" data-idx="${i}" title="Move up" style="transform:rotate(180deg)">${ico('chevron')}</button>
      <button class="iconbtn" data-act="del-output" data-idx="${i}" title="Remove">${ico('trash')}</button>
      <span class="chev">${ico('chevron')}</span>
    </div>
  </div>
  <div class="card-body">
    <div class="row r3">
      <div class="field"><label>Amount <span class="hint">sat</span></label>
        <input type="text" class="mono" data-bind="out:${i}:amount" data-type="bigint" value="${amt}"></div>
      <div class="field"><label>Amount <span class="hint">${netOf().coin}</span></label>
        <input type="text" class="mono" data-act="btc-amount" data-idx="${i}" value="${satsToBtc(amt)}"></div>
      <div class="field"><label>&nbsp;</label>
        <div class="flexrow">
          <button class="btn sm" data-act="max-amount" data-idx="${i}">Send remaining</button>
          <label class="check"><input type="checkbox" data-bind="out:${i}:subtractFee" data-type="bool" ${out.subtractFee ? 'checked' : ''}> subtract fee</label>
        </div>
      </div>
    </div>

    <div class="subhead mt">Creation mode</div>
    <div class="seg full" data-role="outmode-${i}">
      <button data-act="out-mode" data-idx="${i}" data-v="address"  class="${out.mode === 'address' ? 'on' : ''}">Address</button>
      <button data-act="out-mode" data-idx="${i}" data-v="template" class="${out.mode === 'template' ? 'on' : ''}">Script template</button>
      <button data-act="out-mode" data-idx="${i}" data-v="raw"      class="${out.mode === 'raw' ? 'on' : ''}">Raw script</button>
      <button data-act="out-mode" data-idx="${i}" data-v="opreturn" class="${out.mode === 'opreturn' ? 'on' : ''}">OP_RETURN</button>
    </div>

    <div class="mt">${outputModeBody(out, i)}</div>

    <div class="field mt">
      <label>Resolved scriptPubKey <span class="hint">${r.script ? r.script.length + ' bytes' : ''}</span></label>
      <div class="with-copy">
        <input type="text" class="mono" readonly value="${esc(r.error ? '' : bytesToHex(r.script))}" data-role="out-spk-${i}">
        ${copyVal(r.error ? '' : bytesToHex(r.script))}
      </div>
      <div class="hint-text" data-role="out-asm-${i}">${r.error ? '' : hlAsm(r.script, { trim: 32 })}</div>
      <div class="err-text" data-role="out-err-${i}">${r.error ? esc(r.error) : ''}</div>
    </div>
  </div>
</div>`;
  }

  function outputModeBody(out, i) {
    if (out.mode === 'address') {
      const v = out.address ? S.validateAddress(out.address, state.tx.network) : null;
      return `
      <div class="field">
        <label>Address <span class="hint">${netOf().label} · ${netOf().hrp}1… / ${netOf().p2pkh === 0 ? '1…' : 'm|n…'}</span></label>
        <input type="text" class="mono ${v && !v.ok ? 'err' : v ? 'good' : ''}" data-bind="out:${i}:address" data-structural="1"
               value="${esc(out.address)}" placeholder="paste a destination address">
        <div class="${v && !v.ok ? 'err-text' : 'hint-text'}" data-role="out-addr-note-${i}">${v ? (v.ok ? 'valid ' + v.type : esc(v.error)) : ''}</div>
      </div>`;
    }
    if (out.mode === 'template') {
      const tpl = S.TEMPLATES.find(t => t.id === out.template) || S.TEMPLATES[0];
      return `
      <div class="field">
        <label>Template</label>
        <select data-bind="out:${i}:template" data-structural="1">
          ${S.TEMPLATES.map(t => `<option value="${t.id}" ${out.template === t.id ? 'selected' : ''}>${esc(t.label)}</option>`).join('')}
        </select>
      </div>
      <div class="row auto mt">
        ${tpl.fields.map(fd => `
          <div class="field" ${fd.area ? 'style="grid-column:1/-1"' : ''}>
            <label>${esc(fd.l)}</label>
            ${fd.area
              ? `<textarea class="mono" rows="2" data-bind="out:${i}:templateVals.${fd.k}" data-structural="1" placeholder="${esc(fd.ph || '')}">${esc((out.templateVals || {})[fd.k] || '')}</textarea>`
              : `<input type="text" class="mono" data-bind="out:${i}:templateVals.${fd.k}" data-structural="1" value="${esc((out.templateVals || {})[fd.k] || '')}" placeholder="${esc(fd.ph || '')}">`}
          </div>`).join('') || '<div class="hint-text">This template takes no parameters.</div>'}
      </div>`;
    }
    if (out.mode === 'raw') {
      return `
      <div class="field">
        <label>Script ASM <span class="hint">opcode names, &lt;hex&gt; pushes, 'text', numbers${state.tx.forensic.arbitraryBytes ? ", 0xRAW for literal bytes" : ''}</span></label>
        <textarea class="mono" rows="3" data-bind="out:${i}:rawAsm" data-structural="1" placeholder="OP_DUP OP_HASH160 &lt;hash160&gt; OP_EQUALVERIFY OP_CHECKSIG">${esc(out.rawAsm)}</textarea>
      </div>
      <div class="flexrow mt">
        <button class="btn sm" data-act="raw-from-hex" data-idx="${i}">Load from hex…</button>
        <button class="btn sm" data-act="raw-to-lab" data-idx="${i}">Open in Script Lab</button>
      </div>`;
    }
    /* OP_RETURN */
    const o = out.opret;
    const preview = safe(() => TX.buildOpReturn(o), null);
    const payloadBytes = safe(() => TX.encodePayload(o.payload || '', o.encoding), new Uint8Array(0));
    return `
    <div class="row r3">
      <div class="field"><label>Payload encoding</label>
        <select data-bind="out:${i}:opret.encoding" data-structural="1">
          <option value="utf8"   ${o.encoding === 'utf8' ? 'selected' : ''}>UTF-8 text</option>
          <option value="ascii"  ${o.encoding === 'ascii' ? 'selected' : ''}>ASCII / latin-1</option>
          <option value="hex"    ${o.encoding === 'hex' ? 'selected' : ''}>Hex bytes</option>
          <option value="base64" ${o.encoding === 'base64' ? 'selected' : ''}>Base64</option>
          <option value="int"    ${o.encoding === 'int' ? 'selected' : ''}>Integer (CScriptNum)</option>
          <option value="int-le8"${o.encoding === 'int-le8' ? 'selected' : ''}>Integer (8-byte LE)</option>
        </select>
      </div>
      <div class="field"><label>Push encoding</label>
        <select data-bind="out:${i}:opret.pushdata" data-structural="1">
          <option value="auto"   ${o.pushdata === 'auto' ? 'selected' : ''}>Automatic / minimal</option>
          <option value="direct" ${o.pushdata === 'direct' ? 'selected' : ''}>Direct push (≤ 75 B)</option>
          <option value="1"      ${o.pushdata === '1' ? 'selected' : ''}>OP_PUSHDATA1</option>
          <option value="2"      ${o.pushdata === '2' ? 'selected' : ''}>OP_PUSHDATA2</option>
          <option value="4"      ${o.pushdata === '4' ? 'selected' : ''}>OP_PUSHDATA4</option>
        </select>
      </div>
      <div class="field"><label>Payload size</label>
        <input type="text" class="mono" readonly value="${payloadBytes.length} bytes" data-role="opret-size-${i}">
      </div>
    </div>
    <div class="field mt">
      <label>Payload</label>
      <textarea class="mono" rows="3" data-bind="out:${i}:opret.payload" data-structural="1" placeholder="your data">${esc(o.payload)}</textarea>
    </div>
    <div class="flexrow mt">
      <span class="hint-text">Known prefixes:</span>
      ${OPRETURN_PREFIXES.map(p =>
        `<button class="opchip" data-act="opret-prefix" data-idx="${i}" data-v="${esc(p.hex)}" title="${esc(p.note)}">${esc(p.label)}</button>`).join('')}
    </div>
    <div class="flexrow mt forensic-only">
      <label class="check"><input type="checkbox" data-bind="out:${i}:opret.nonMinimal" data-type="bool" data-structural="1" ${o.nonMinimal ? 'checked' : ''}> force non-minimal push</label>
      <label class="check"><input type="checkbox" data-bind="out:${i}:opret.multiPush" data-type="bool" data-structural="1" ${o.multiPush ? 'checked' : ''}> allow multiple pushes</label>
      <div class="field" style="max-width:170px"><label>Custom prefix opcode <span class="hint">decimal, default 106</span></label>
        <input type="text" class="mono" data-bind="out:${i}:opret.prefixOpcode" data-structural="1" value="${esc(o.prefixOpcode)}" placeholder="106">
      </div>
    </div>
    ${o.multiPush ? `
      <div class="subhead mt">Additional pushes</div>
      ${(o.extraPayloads || []).map((e, ei) => `
        <div class="row r3 mb">
          <div class="field"><label>Encoding</label>
            <select data-bind="out:${i}:opret.extraPayloads.${ei}.encoding" data-structural="1">
              ${['utf8', 'hex', 'ascii', 'int'].map(v => `<option value="${v}" ${e.encoding === v ? 'selected' : ''}>${v}</option>`).join('')}
            </select></div>
          <div class="field" style="grid-column:span 2"><label>Value
            <button class="iconbtn" data-act="del-extra" data-idx="${i}" data-ei="${ei}">${ico('x')}</button></label>
            <input type="text" class="mono" data-bind="out:${i}:opret.extraPayloads.${ei}.value" data-structural="1" value="${esc(e.value)}"></div>
        </div>`).join('')}
      <button class="btn sm" data-act="add-extra" data-idx="${i}">${ico('plus')} Add push</button>` : ''}
    <div class="field mt">
      <label>Payload hex</label>
      <div class="with-copy"><input type="text" class="mono" readonly value="${bytesToHex(payloadBytes)}" data-role="opret-hex-${i}">${copyVal(bytesToHex(payloadBytes))}</div>
    </div>
    ${preview && preview.length > 83 ? `<div class="warn-text mt">Script is ${preview.length} bytes — over the 83-byte data-carrier relay limit (80 bytes of payload). Consensus-valid, but most nodes will not forward it.</div>` : ''}`;
  }

  function refreshOutputCards() {
    state.tx.outputs.forEach((out, i) => {
      const r = TX.resolveOutput(out, state.tx.network);
      const spk = $(`[data-role="out-spk-${i}"]`);
      if (spk) spk.value = r.error ? '' : bytesToHex(r.script);
      const asm = $(`[data-role="out-asm-${i}"]`);
      if (asm) asm.innerHTML = r.error ? '' : hlAsm(r.script, { trim: 32 });
      const err = $(`[data-role="out-err-${i}"]`);
      if (err) err.textContent = r.error || '';
      const note = $(`[data-role="out-addr-note-${i}"]`);
      if (note && out.mode === 'address') {
        const v = out.address ? S.validateAddress(out.address, state.tx.network) : null;
        note.textContent = v ? (v.ok ? 'valid ' + v.type : v.error) : '';
        note.className = v && !v.ok ? 'err-text' : 'hint-text';
      }
      if (out.mode === 'opreturn') {
        const pb = safe(() => TX.encodePayload(out.opret.payload || '', out.opret.encoding), new Uint8Array(0));
        const sz = $(`[data-role="opret-size-${i}"]`); if (sz) sz.value = pb.length + ' bytes';
        const hx = $(`[data-role="opret-hex-${i}"]`); if (hx) hx.value = bytesToHex(pb);
      }
    });
  }

  /* ============================= SCRIPT LAB ============================== */

  function renderScriptLab() {
    const cats = Object.keys(S.OP_CATEGORIES).filter(c =>
      state.tx.forensic.arbitraryOpcode || (c !== 'reserved' && c !== 'disabled'));
    $('#op-cats').innerHTML = cats.map(c =>
      `<button class="opchip ${state.opCat === c ? 'on' : ''}" data-act="op-cat" data-v="${c}"
        style="${state.opCat === c ? 'border-color:var(--accent);color:var(--accent)' : ''}">${c.toUpperCase()}</button>`).join('');
    const list = S.OP_CATEGORIES[state.opCat] || [];
    $('#op-grid').innerHTML = list.map(n =>
      `<button class="opchip" data-act="op-add" data-v="${n}" title="${esc(S.OP_DOC[n] || '')}">${n.replace('OP_', '')}<span class="hexcode">${S.OPS[n].toString(16).padStart(2, '0')}</span></button>`).join('');
    renderCanvas();
  }

  function renderCanvas() {
    const c = $('#script-canvas');
    if (!state.canvas.length) {
      c.innerHTML = `<div class="empty-note">Empty. Click opcodes on the left, or type ASM below.</div>`;
    } else {
      c.innerHTML = state.canvas.map((item, i) => {
        const cat = item.kind === 'push' ? 'push' : (S.OP_CAT_OF[item.op] || 'control');
        return `
        <div class="canvas-item c-${cat}" draggable="true" data-ci="${i}">
          <span class="op">${item.kind === 'push' ? 'PUSH' : esc(item.op.replace('OP_', 'OP_'))}</span>
          ${item.kind === 'push'
            ? `<input type="text" class="mono" data-act="canvas-edit" data-ci="${i}" value="${esc(item.value)}" placeholder="hex / 'text' / number">`
            : `<span class="mutedc small">0x${S.OPS[item.op].toString(16).padStart(2, '0')}</span>`}
          <div class="tools">
            <button class="iconbtn" data-act="canvas-up" data-ci="${i}" style="transform:rotate(180deg)">${ico('chevron', 12)}</button>
            <button class="iconbtn" data-act="canvas-down" data-ci="${i}">${ico('chevron', 12)}</button>
            <button class="iconbtn" data-act="canvas-del" data-ci="${i}">${ico('x', 12)}</button>
          </div>
        </div>`;
      }).join('');
    }
    syncScriptFromCanvas();
  }

  function canvasToAsm() {
    return state.canvas.map(it => it.kind === 'push' ? (it.value || '') : it.op).filter(Boolean).join(' ');
  }

  /**
   * Hand a script to the Script Lab. Switching workspace re-renders the canvas,
   * which would clear the fields, so the switch has to happen first.
   */
  function loadIntoScriptLab(script) {
    const hex = script instanceof Uint8Array ? bytesToHex(script) : String(script || '');
    state.canvas = [];
    showWorkspace('script');
    $('#script-hex').value = hex;
    compileScript(hex, 'hex');
  }

  function syncScriptFromCanvas() {
    const asm = canvasToAsm();
    $('#script-asm').value = asm;
    compileScript(asm, 'asm');
  }

  function compileScript(text, from) {
    const errEl = $('#script-error');
    try {
      let bytes;
      if (from === 'asm') {
        bytes = text.trim() ? S.fromAsm(text, { nonMinimal: state.tx.forensic.nonMinimalPush }) : new Uint8Array(0);
        $('#script-hex').value = bytesToHex(bytes);
      } else {
        bytes = text.trim() ? hexToBytes(text) : new Uint8Array(0);
        $('#script-asm').value = S.toAsm(bytes);
      }
      errEl.textContent = '';
      $('#script-size').textContent = `${bytes.length} bytes`;
      renderScriptDerived(bytes);
    } catch (e) {
      errEl.textContent = e.message;
      $('#script-derived').innerHTML = '';
    }
  }

  function renderScriptDerived(bytes) {
    const pretty = $('#script-pretty');
    if (pretty) pretty.innerHTML = bytes.length ? hlAsm(bytes, { lg: true }) : '<span class="mutedc">empty</span>';
    if (!bytes.length) { $('#script-derived').innerHTML = '<dt class="mutedc">—</dt><dd>empty script</dd>'; return; }
    const cls = S.classify(bytes);
    const rows = [
      ['Detected type', cls.type + (cls.standard ? ' (standard)' : ' (non-standard)')],
      ['Size', bytes.length + ' bytes'],
      ['SHA256', bytesToHex(BC.sha256(bytes))],
      ['HASH160', bytesToHex(BC.hash160(bytes))],
      ['P2SH address', S.scriptToAddress(S.p2sh(BC.hash160(bytes)), state.tx.network) || '—'],
      ['P2WSH address', S.scriptToAddress(S.p2wsh(BC.sha256(bytes)), state.tx.network) || '—'],
      ['P2SH scriptPubKey', bytesToHex(S.p2sh(BC.hash160(bytes)))],
      ['P2WSH scriptPubKey', bytesToHex(S.p2wsh(BC.sha256(bytes)))],
      ['TapLeaf hash (0xc0)', bytesToHex(BC.tapLeafHash(bytes, 0xc0))]
    ];
    const parsed = S.parseScript(bytes);
    if (parsed.error) rows.push(['Parse warning', parsed.error]);
    const nonMin = parsed.ops.filter(o => !o.minimal);
    if (nonMin.length) rows.push(['Non-minimal pushes', nonMin.map(o => `byte ${o.offset}`).join(', ')]);
    $('#script-derived').innerHTML = kvRows(rows);
  }

  /* ============================== SIGNING ================================ */

  function renderSigning() {
    const sel = $('#signing-input-sel');
    sel.innerHTML = state.tx.inputs.map((inp, i) =>
      `<option value="${i}" ${state.signingIndex === i ? 'selected' : ''}>Input #${i} — ${inp.txid ? shortHex(inp.txid, 6) : 'no outpoint'}:${inp.vout}</option>`).join('');

    const i = Math.min(state.signingIndex, state.tx.inputs.length - 1);
    state.signingIndex = Math.max(0, i);
    const inp = state.tx.inputs[state.signingIndex];
    const body = $('#signing-body');
    if (!inp) { body.innerHTML = '<div class="empty-note">Add an input first.</div>'; return; }

    let pkg;
    try { pkg = SIGHASH.forInput(state.tx, state.signingIndex); }
    catch (e) { pkg = { error: e.message, warnings: [] }; }

    const hex = (b) => b ? bytesToHex(b) : '';
    const z = pkg.digest ? bytesToHex(pkg.digest) : '';
    const spk = safe(() => hexToBytes(inp.scriptPubKey), new Uint8Array(0));

    const ctxRows = [
      ['Previous TXID', inp.txid || '—'],
      ['VOUT', String(inp.vout)],
      ['Amount', `${groupNum(inp.amount || 0)} sat (${satsToBtc(inp.amount || 0)} ${netOf().coin})`],
      ['nSequence', '0x' + (inp.sequence >>> 0).toString(16).padStart(8, '0')],
      ['scriptPubKey', inp.scriptPubKey || '—'],
      ['Detected type', spk.length ? S.classify(spk).type : '—'],
      ['redeemScript', inp.redeemScript || '(not used)'],
      ['witnessScript', inp.witnessScript || '(not used)'],
      ['scriptCode', pkg.scriptCode ? bytesToHex(pkg.scriptCode) : '(not used — taproot)'],
      ['Sighash byte', pkg.hashType !== undefined ? `0x${pkg.hashType.toString(16).padStart(2, '0')} — ${pkg.hashTypeName}` : '—'],
      ['Algorithm', pkg.algorithmUsed || '—']
    ];

    const tr = inp.taproot || {};
    const trRows = [];
    if (tr.internalKey) {
      trRows.push(['Internal key (x-only)', tr.internalKey]);
      try {
        const t = BC.taprootTweak(hexToBytes(tr.internalKey), tr.merkleRoot ? hexToBytes(tr.merkleRoot) : null);
        trRows.push(['TapTweak scalar', bytesToHex(t.tweak)]);
        trRows.push(['Output key', bytesToHex(t.outputKey)]);
        trRows.push(['Output parity', String(t.parity)]);
      } catch (e) { trRows.push(['Tweak error', e.message]); }
    }
    if (tr.merkleRoot) trRows.push(['Merkle root', tr.merkleRoot]);
    if (pkg.leafHash) trRows.push(['TapLeaf hash', bytesToHex(pkg.leafHash)]);
    if (tr.leafScript) trRows.push(['Leaf script', tr.leafScript]);
    if (tr.controlBlock) trRows.push(['Control block', tr.controlBlock]);

    const partsRows = [];
    if (pkg.parts) for (const [k, v] of Object.entries(pkg.parts)) partsRows.push([k, bytesToHex(v)]);

    body.innerHTML = `
    <div class="grid c2-1">
      <div>
        <div class="panel">
          <div class="panel-head">${ico('key', 15)}<h3>Input #${state.signingIndex} — signing package</h3>
            <div class="tools">
              ${pkg.algo ? `<span class="tag ${pkg.algo === 'bip341' ? 'violet' : pkg.algo === 'bip143' ? 'blue' : 'grey'}">${pkg.algo.toUpperCase()}</span>` : ''}
            </div>
          </div>
          <div class="panel-body">
            ${pkg.error ? `<div class="banner red">${ico('alert', 18)}<div>${esc(pkg.error)}</div></div>` : ''}
            ${(pkg.warnings || []).map(w => `<div class="banner">${ico('alert', 18)}<div>${esc(w)}</div></div>`).join('')}

            <div class="field">
              <label>Signing serialization / preimage <span class="hint">${pkg.preimage ? pkg.preimage.length + ' bytes' : ''}</span></label>
              <div class="code tall" id="sig-preimage">${pkg.preimage ? bytesToHex(pkg.preimage) : '<span class="mutedc">not available</span>'}</div>
              <div class="flexrow mt">
                <button class="btn sm" data-copy-val="${hex(pkg.preimage)}">Copy preimage</button>
                ${pkg.sigMsg ? `<button class="btn sm" data-copy-val="${hex(pkg.sigMsg)}">Copy SigMsg (no epoch)</button>` : ''}
              </div>
            </div>

            <div class="row r2 mt">
              ${pkg.sha256 ? `<div class="field"><label>SHA256 (single)</label>
                <div class="with-copy"><input class="mono" readonly value="${hex(pkg.sha256)}">${copyVal(hex(pkg.sha256))}</div></div>` : ''}
              <div class="field"><label>${pkg.algo === 'bip341' ? 'TapSighash (tagged)' : 'SHA256d — the digest'}</label>
                <div class="with-copy"><input class="mono" readonly value="${z}">${copyVal(z)}</div></div>
            </div>

            <div class="field mt">
              <label class="accent">z — the value your signer signs</label>
              <div class="with-copy"><input class="mono" readonly value="${z}" style="border-color:var(--accent)">${copyVal(z)}</div>
              <div class="hint-text">Big-endian 32-byte integer. Feed this straight into your ECDSA/Schnorr routine.</div>
            </div>

            <div class="flexrow mt">
              <button class="btn" data-copy-val="${z}">Copy z</button>
              <button class="btn" id="btn-sig-json-one">Copy signing JSON (this input)</button>
              <button class="btn" id="btn-sig-json-all">Copy signing JSON (all inputs)</button>
              <button class="btn primary" id="btn-sig-export-one">Export .json</button>
            </div>
          </div>
        </div>

        ${partsRows.length ? `
        <div class="panel">
          <div class="panel-head"><h3>Intermediate hashes</h3></div>
          <div class="panel-body"><dl class="kv">${kvRows(partsRows)}</dl></div>
        </div>` : ''}

        <div class="panel">
          <div class="panel-head"><h3>Commitment — what this signature covers</h3></div>
          <div class="panel-body">${commitmentTable(pkg)}</div>
        </div>
      </div>

      <div>
        <div class="panel">
          <div class="panel-head"><h3>Transaction context</h3></div>
          <div class="panel-body"><dl class="kv">${kvRows(ctxRows)}</dl></div>
        </div>

        ${trRows.length ? `
        <div class="panel">
          <div class="panel-head" style="border-bottom-color:var(--violet)"><h3 style="color:var(--violet)">Taproot data</h3></div>
          <div class="panel-body"><dl class="kv">${kvRows(trRows)}</dl></div>
        </div>` : ''}

        <div class="panel">
          <div class="panel-head"><h3>Hand-off routes</h3></div>
          <div class="panel-body stack sm">
            <div class="helpcmd"><code>walletprocesspsbt "&lt;psbt&gt;"</code>${copyVal('walletprocesspsbt "<psbt>"')}</div>
            <div class="helpcmd"><code>signrawtransactionwithkey "&lt;hex&gt;" '["&lt;key&gt;"]' '[&lt;prevtxs&gt;]'</code>${copyVal('signrawtransactionwithkey "<hex>" \'["<key>"]\' \'[<prevtxs>]\'')}</div>
            <div class="hint-text">Or take <strong>z</strong> to any library: <span class="mono">sign(z, privkey) → (r, s)</span>, then paste r/s back in Finalize.</div>
          </div>
        </div>
      </div>
    </div>`;

    $('#btn-sig-json-one').onclick = () => copyText(JSON.stringify(signingPackage(state.signingIndex), null, 2));
    $('#btn-sig-json-all').onclick = () => copyText(JSON.stringify(signingPackageAll(), null, 2));
    $('#btn-sig-export-one').onclick = () =>
      download(`signing-input-${state.signingIndex}.json`, JSON.stringify(signingPackage(state.signingIndex), null, 2), 'application/json');
  }

  function commitmentTable(pkg) {
    if (pkg.hashType === undefined) return '<div class="hint-text">Not available.</div>';
    const c = SIGHASH.commitment(pkg.hashType, pkg.algo || 'legacy');
    const labels = {
      version: 'nVersion', locktime: 'nLockTime', thisInput: 'This input’s outpoint',
      otherInputs: 'Other inputs', inputAmounts: 'Input amounts', inputScriptPubKeys: 'Input scriptPubKeys',
      sequences: 'Other sequences', outputs: 'Outputs', scriptCode: 'scriptCode / tapleaf', sighashByte: 'Sighash byte'
    };
    return `<table class="matrix">
      <tr><th>Committed field</th><th>Included</th><th style="text-align:left">Note</th></tr>
      ${Object.entries(c).map(([k, v]) => `
        <tr><td>${labels[k] || k}</td>
          <td class="${v.on ? 'yes' : 'no'}">${v.partial ? '<span class="part">PARTIAL</span>' : v.on ? '✓' : '—'}</td>
          <td style="text-align:left" class="mutedc">${esc(v.note || '')}</td></tr>`).join('')}
    </table>`;
  }

  function signingPackage(i) {
    const inp = state.tx.inputs[i];
    let pkg;
    try { pkg = SIGHASH.forInput(state.tx, i); } catch (e) { pkg = { error: e.message }; }
    const tr = inp.taproot || {};
    return {
      workbench: 'idleanvil/1.0',
      network: state.tx.network,
      input: i,
      txid: inp.txid, vout: inp.vout,
      amount: Number(inp.amount || 0),
      sequence: inp.sequence >>> 0,
      scriptPubKey: inp.scriptPubKey || null,
      redeemScript: inp.redeemScript || null,
      witnessScript: inp.witnessScript || null,
      scriptCode: pkg.scriptCode ? bytesToHex(pkg.scriptCode) : null,
      sighash: pkg.hashTypeName || null,
      sighashByte: pkg.hashType !== undefined ? '0x' + pkg.hashType.toString(16).padStart(2, '0') : null,
      algorithm: inp.algorithm === 'schnorr' ? 'schnorr' : 'ecdsa',
      hashAlgorithm: pkg.algo || null,
      taproot: tr.internalKey ? {
        internalKey: tr.internalKey || null,
        merkleRoot: tr.merkleRoot || null,
        leafScript: tr.leafScript || null,
        leafVersion: Number(tr.leafVersion) || 192,
        leafHash: pkg.leafHash ? bytesToHex(pkg.leafHash) : null,
        path: tr.path
      } : null,
      preimage: pkg.preimage ? bytesToHex(pkg.preimage) : null,
      digest: pkg.digest ? bytesToHex(pkg.digest) : null,
      z: pkg.digest ? bytesToHex(pkg.digest) : null,
      unsignedTx: bytesToHex(TX.serialize(state.tx, { final: false, forceWitness: false })),
      warnings: pkg.warnings || [],
      error: pkg.error || null,
      expects: {
        format: 'return {"input": n, "r": "...", "s": "...", "der": "...", "pubkey": "..."} ' +
                'or {"input": n, "schnorr": "...", "pubkey": "..."}'
      }
    };
  }
  function signingPackageAll() {
    return {
      workbench: 'idleanvil/1.0',
      network: state.tx.network,
      unsignedTx: bytesToHex(TX.serialize(state.tx, { final: false, forceWitness: false })),
      psbt: safe(() => bytesToBase64(PSBT.build(state.tx, state.tx.psbtVersion)), null),
      inputs: state.tx.inputs.map((_, i) => signingPackage(i))
    };
  }

  /* =============================== PSBT ================================== */

  function renderPsbt() {
    $$('#psbt-ver-seg button').forEach(b => b.classList.toggle('on', Number(b.dataset.v) === state.psbtVersion));
    try {
      const bytes = PSBT.build(state.tx, state.psbtVersion);
      $('#psbt-b64').value = bytesToBase64(bytes);
      $('#psbt-hex').value = bytesToHex(bytes);
      $('#psbt-size').textContent = `${bytes.length} bytes · v${state.psbtVersion}`;
      $('#psbt-error').textContent = '';
    } catch (e) {
      $('#psbt-b64').value = ''; $('#psbt-hex').value = '';
      $('#psbt-error').textContent = e.message;
    }
    const b64 = $('#psbt-b64').value;
    const hexTx = bytesToHex(TX.serialize(state.tx, { final: true }));
    const cmds = [
      ['decodepsbt', `decodepsbt "${b64 || '<psbt>'}"`],
      ['analyzepsbt', `analyzepsbt "${b64 || '<psbt>'}"`],
      ['walletprocesspsbt', `walletprocesspsbt "${b64 || '<psbt>'}"`],
      ['finalizepsbt', `finalizepsbt "${b64 || '<psbt>'}"`],
      ['decoderawtransaction', `decoderawtransaction "${hexTx}"`],
      ['testmempoolaccept', `testmempoolaccept '["${hexTx}"]'`],
      ['sendrawtransaction', `sendrawtransaction "${hexTx}"`],
      ['getrawtransaction (prevout)', `getrawtransaction ${state.tx.inputs[0] ? state.tx.inputs[0].txid || '<txid>' : '<txid>'} true`]
    ];
    $('#core-cmds').innerHTML = cmds.map(([name, c]) =>
      `<div class="helpcmd"><code title="${esc(name)}">${esc(c.length > 200 ? c.slice(0, 200) + '…' : c)}</code>${copyVal(c)}</div>`).join('');
  }

  function decodePsbtInput(loadIntoModel) {
    const raw = $('#psbt-in').value.trim();
    if (!raw) { toast('Paste a PSBT first.', 'warn'); return; }
    let parsed;
    try { parsed = PSBT.parse(raw); }
    catch (e) { $('#psbt-decoded').innerHTML = `<div class="vrow"><span class="tag red">ERROR</span><div class="vtxt"><div class="vt">${esc(e.message)}</div></div></div>`; return; }

    const d = PSBT.describe(parsed);
    const diff = PSBT.diff(state.tx, parsed);

    $('#psbt-decoded').innerHTML = `
      <div class="vrow"><span class="tag teal">v${d.summary.version}</span>
        <div class="vtxt"><div class="vt">${d.summary.inputs} inputs · ${d.summary.outputs} outputs · ${d.summary.signedInputs} signed · ${d.summary.size} bytes</div></div></div>
      ${diff.map(r => `
        <div class="vrow">
          <span class="tag ${r.finalized ? 'violet' : r.total ? 'green' : 'grey'}">INPUT ${r.index}</span>
          <div class="vtxt"><div class="vt">${r.finalized ? 'finalized' : esc(r.status)}${r.added > 0 ? ` — ${r.added} new` : ''}</div></div>
          <span class="vloc">${r.total} sig${r.total === 1 ? '' : 's'}</span>
        </div>`).join('')}
      <div class="vrow"><span class="tag blue">GLOBAL</span><div class="vtxt">
        ${d.global.map(f => `<div class="vt mono small">${esc(f.name)} <span class="mutedc">= ${esc(f.display)}</span></div>`).join('')}
      </div></div>
      ${d.inputs.map(inRow => `
        <div class="vrow"><span class="tag ${inRow.signed ? 'green' : 'grey'}">IN ${inRow.index}</span><div class="vtxt">
          ${inRow.rows.map(f => `<div class="vt mono small">${esc(f.name)}${f.keyData ? `[${shortHex(f.keyData, 6)}]` : ''} <span class="mutedc">= ${esc(f.display)}</span></div>`).join('') || '<span class="mutedc">empty map</span>'}
        </div></div>`).join('')}
      ${d.outputs.map(oRow => `
        <div class="vrow"><span class="tag grey">OUT ${oRow.index}</span><div class="vtxt">
          ${oRow.rows.map(f => `<div class="vt mono small">${esc(f.name)} <span class="mutedc">= ${esc(f.display)}</span></div>`).join('') || '<span class="mutedc">empty map</span>'}
        </div></div>`).join('')}`;

    if (loadIntoModel) {
      const { tx, report } = PSBT.toModel(parsed, state.tx.network);
      state.tx = normaliseTx(tx);
      renderAll();
      const added = report.inputs.filter(r => r.changes.length).length;
      toast(`Loaded PSBT v${parsed.version}: ${report.inputs.length} inputs, ${report.outputs.length} outputs, ${added} populated.`);
    }
  }

  /* ============================== FINALIZE =============================== */

  const IMPORT_PANES = {
    psbt: () => `
      <div class="field"><label>Signed PSBT (base64 or hex)</label>
        <textarea id="imp-psbt" class="mono" rows="6" placeholder="cHNidP8B…"></textarea></div>
      <div class="flexrow mt"><button class="btn primary" data-act="imp-psbt">Merge signatures</button>
        <button class="btn" data-act="imp-psbt-replace">Replace transaction entirely</button></div>`,
    der: () => `
      <div class="row r2">
        <div class="field"><label>Input index</label><input type="number" id="imp-idx" value="0" min="0"></div>
        <div class="field"><label>Public key (33 / 65 bytes)</label><input type="text" id="imp-pk" class="mono"></div>
      </div>
      <div class="field mt"><label>DER signature <span class="hint">with or without the trailing sighash byte</span></label>
        <textarea id="imp-der" class="mono" rows="3" placeholder="3044022…01"></textarea></div>
      <div class="flexrow mt"><button class="btn primary" data-act="imp-der">Attach signature</button>
        <button class="btn" data-act="imp-verify">Verify against z first</button></div>
      <div class="mt" id="imp-der-note"></div>`,
    schnorr: () => `
      <div class="row r2">
        <div class="field"><label>Input index</label><input type="number" id="imp-idx" value="0" min="0"></div>
        <div class="field"><label>x-only public key (32 bytes)</label><input type="text" id="imp-pk" class="mono"></div>
      </div>
      <div class="field mt"><label>Schnorr signature <span class="hint">64 bytes, or 65 with an appended sighash byte</span></label>
        <textarea id="imp-schnorr" class="mono" rows="2"></textarea></div>
      <div class="row r2 mt">
        <div class="field"><label>Destination</label>
          <select id="imp-tap-dest"><option value="key">Key path (tapKeySig)</option><option value="script">Script path (tapScriptSig)</option></select></div>
        <div class="field"><label>Leaf hash <span class="hint">script path only</span></label><input type="text" id="imp-leaf" class="mono"></div>
      </div>
      <div class="flexrow mt"><button class="btn primary" data-act="imp-schnorr">Attach signature</button>
        <button class="btn" data-act="imp-verify-schnorr">Verify against z first</button></div>
      <div class="mt" id="imp-der-note"></div>`,
    rs: () => `
      <div class="row r4">
        <div class="field"><label>Input index</label><input type="number" id="imp-idx" value="0" min="0"></div>
        <div class="field"><label>r</label><input type="text" id="imp-r" class="mono"></div>
        <div class="field"><label>s</label><input type="text" id="imp-s" class="mono"></div>
        <div class="field"><label>Sighash byte</label><input type="text" id="imp-sh" class="mono" value="01"></div>
      </div>
      <div class="field mt"><label>Public key</label><input type="text" id="imp-pk" class="mono"></div>
      <div class="flexrow mt">
        <label class="check"><input type="checkbox" id="imp-lows" checked> normalise to low-S</label>
        <button class="btn primary" data-act="imp-rs">Encode DER and attach</button>
      </div>
      <div class="mt" id="imp-der-note"></div>`,
    json: () => `
      <div class="field"><label>Signing result JSON <span class="hint">an object or an array of objects</span></label>
        <textarea id="imp-json" class="mono" rows="8" placeholder='{"input":0,"r":"…","s":"…","pubkey":"…"}'></textarea></div>
      <div class="flexrow mt"><button class="btn primary" data-act="imp-json">Import</button></div>
      <div class="hint-text mt">Accepted keys per entry: <span class="mono">input</span>, <span class="mono">r</span>+<span class="mono">s</span> or <span class="mono">der</span> or <span class="mono">schnorr</span>, <span class="mono">pubkey</span>, <span class="mono">sighash</span>, <span class="mono">leafHash</span>.</div>
      <div class="mt" id="imp-der-note"></div>`,
    raw: () => `
      <div class="field"><label>Final raw transaction hex</label>
        <textarea id="imp-raw" class="mono" rows="6" placeholder="02000000000101…"></textarea></div>
      <div class="flexrow mt"><button class="btn primary" data-act="imp-raw">Load as the current transaction</button></div>
      <div class="hint-text mt">Useful to re-open something a signer returned fully assembled, then inspect it byte by byte.</div>`
  };

  function renderFinalize() {
    $$('#import-tabs button').forEach(b => b.classList.toggle('on', b.dataset.t === state.importTab));
    $('#import-panes').innerHTML = IMPORT_PANES[state.importTab]();

    const rows = state.tx.inputs.map((inp, i) => {
      const sigs = (inp.partialSigs || []).filter(s => s.signature).length;
      const tapSigs = (inp.tapKeySig ? 1 : 0) + (inp.tapScriptSigs || []).length;
      const r = FINALIZE.finalizeInput(inp);
      const done = (inp.scriptSig || (inp.witness || []).length);
      return `
      <div class="vrow">
        <span class="tag ${done ? 'green' : (sigs + tapSigs) ? 'amber' : 'grey'}">INPUT ${i}</span>
        <div class="vtxt">
          <div class="vt">${sigs + tapSigs} signature${sigs + tapSigs === 1 ? '' : 's'} · ${esc(r.note)}</div>
          <div class="vd">${done ? `scriptSig ${(inp.scriptSig || '').length / 2 | 0} B · witness ${(inp.witness || []).length} item(s)` : 'not assembled'}</div>
        </div>
        <button class="btn sm" data-act="finalize-one" data-idx="${i}">Assemble</button>
      </div>`;
    }).join('');
    $('#finalize-status').innerHTML = rows || '<div class="empty-note">No inputs.</div>';

    const finalHex = bytesToHex(TX.serialize(state.tx, { final: true }));
    $('#final-hex').value = finalHex;
    const m = TX.measure(state.tx, { final: true });
    $('#final-stats').innerHTML = kvRows([
      ['TXID', TX.txid(state.tx)],
      ['WTXID', TX.hasWitness(state.tx) ? TX.wtxid(state.tx) : '(no witness)'],
      ['Size', `${m.total} bytes`],
      ['Base size', `${m.base} bytes`],
      ['vSize', `${m.vsize} vB`],
      ['Weight', `${m.weight} WU`],
      ['Input total', `${groupNum(m.inTotal)} sat`],
      ['Output total', `${groupNum(m.outTotal)} sat`],
      ['Fee', `${groupNum(m.fee)} sat`],
      ['Fee rate', `${m.feeRate.toFixed(2)} sat/vB`]
    ]);
  }

  /* ------------------------------------------------------ import actions */

  function attachSignature(idx, pubkey, sigHex, note) {
    const inp = state.tx.inputs[idx];
    if (!inp) { toast(`There is no input #${idx}.`, 'err'); return false; }
    inp.partialSigs = inp.partialSigs || [];
    const existing = inp.partialSigs.findIndex(p => p.pubkey && pubkey && p.pubkey.toLowerCase() === pubkey.toLowerCase());
    if (existing >= 0) inp.partialSigs[existing] = { pubkey, signature: sigHex };
    else inp.partialSigs.push({ pubkey: pubkey || '', signature: sigHex });
    toast(note || `Attached a ${sigHex.length / 2}-byte signature to input #${idx}.`);
    return true;
  }

  function importDer() {
    const idx = parseInt($('#imp-idx').value, 10) || 0;
    const pk = ($('#imp-pk').value || '').trim().toLowerCase();
    const der = ($('#imp-der').value || '').trim().toLowerCase().replace(/\s/g, '');
    if (!der) { toast('Paste a DER signature.', 'warn'); return; }
    let bytes;
    try { bytes = hexToBytes(der); } catch (e) { toast(e.message, 'err'); return; }
    const d = BC.derDecode(bytes);
    const notes = [];
    if (!d.ok) {
      if (!state.tx.forensic.malformedDER) {
        $('#imp-der-note').innerHTML = `<div class="err-text">${esc(d.error)} — enable "Malformed DER experiment" in Forensic controls to attach it anyway.</div>`;
        return;
      }
      notes.push(`malformed DER accepted: ${d.error}`);
    } else {
      if (!d.strictDER) notes.push('not strict DER: ' + d.issues.join('; '));
      if (!d.lowS) notes.push('high-S signature (BIP146 wants low-S)');
      if (d.sighash === null) notes.push('no trailing sighash byte — most scripts require one');
    }
    attachSignature(idx, pk, der);
    $('#imp-der-note').innerHTML = notes.length
      ? `<div class="warn-text">${notes.map(esc).join('<br>')}</div>`
      : `<div class="ok-text">Strict DER, low-S, sighash 0x${(d.sighash || 0).toString(16).padStart(2, '0')}.</div>`;
    renderAll();
  }

  function importSchnorr() {
    const idx = parseInt($('#imp-idx').value, 10) || 0;
    const pk = ($('#imp-pk').value || '').trim().toLowerCase();
    const sig = ($('#imp-schnorr').value || '').trim().toLowerCase().replace(/\s/g, '');
    const dest = $('#imp-tap-dest').value;
    const leaf = ($('#imp-leaf').value || '').trim().toLowerCase();
    if (!sig) { toast('Paste a Schnorr signature.', 'warn'); return; }
    let bytes;
    try { bytes = hexToBytes(sig); } catch (e) { toast(e.message, 'err'); return; }
    if (bytes.length !== 64 && bytes.length !== 65) {
      $('#imp-der-note').innerHTML = `<div class="err-text">A Schnorr signature is 64 bytes (65 with a sighash byte); this is ${bytes.length}.</div>`;
      return;
    }
    const inp = state.tx.inputs[idx];
    if (!inp) { toast(`There is no input #${idx}.`, 'err'); return; }
    if (dest === 'key') inp.tapKeySig = sig;
    else {
      inp.tapScriptSigs = inp.tapScriptSigs || [];
      inp.tapScriptSigs.push({ pubkey: pk, leafHash: leaf, signature: sig });
    }
    inp.algorithm = 'schnorr';
    $('#imp-der-note').innerHTML = `<div class="ok-text">Attached to input #${idx} (${dest} path).</div>`;
    renderAll();
  }

  function importRs() {
    const idx = parseInt($('#imp-idx').value, 10) || 0;
    const rHex = ($('#imp-r').value || '').trim();
    const sHex = ($('#imp-s').value || '').trim();
    const sh = ($('#imp-sh').value || '').trim();
    const pk = ($('#imp-pk').value || '').trim().toLowerCase();
    if (!rHex || !sHex) { toast('Both r and s are required.', 'warn'); return; }
    try {
      let r = BC.bytesToBig(hexToBytes(rHex.padStart(64, '0')));
      let s = BC.bytesToBig(hexToBytes(sHex.padStart(64, '0')));
      const N = BC.secp.N;
      const notes = [];
      if (s > N / 2n) {
        if ($('#imp-lows').checked) { s = N - s; notes.push(`s was above N/2 — normalised to ${bytesToHex(BC.bigToBytes(s, 32))}`); }
        else notes.push('high-S signature kept as-is');
      }
      let der = bytesToHex(BC.derEncode(r, s));
      if (sh) der += sh.replace(/^0x/i, '').padStart(2, '0');
      attachSignature(idx, pk, der);
      $('#imp-der-note').innerHTML = `<div class="ok-text">DER: <span class="mono brk">${esc(der)}</span></div>` +
        (notes.length ? `<div class="warn-text">${notes.map(esc).join('<br>')}</div>` : '');
      renderAll();
    } catch (e) { toast(e.message, 'err'); }
  }

  function importJson() {
    let data;
    try { data = JSON.parse($('#imp-json').value); }
    catch (e) { $('#imp-der-note').innerHTML = `<div class="err-text">Not valid JSON: ${esc(e.message)}</div>`; return; }
    const entries = Array.isArray(data) ? data : (data.signatures || data.inputs || [data]);
    const log = [];
    for (const e of entries) {
      const idx = Number(e.input !== undefined ? e.input : e.index || 0);
      const inp = state.tx.inputs[idx];
      if (!inp) { log.push(`input ${idx}: does not exist`); continue; }
      try {
        if (e.schnorr) {
          if (e.leafHash) { inp.tapScriptSigs = inp.tapScriptSigs || []; inp.tapScriptSigs.push({ pubkey: e.pubkey || '', leafHash: e.leafHash, signature: e.schnorr }); }
          else inp.tapKeySig = e.schnorr;
          inp.algorithm = 'schnorr';
          log.push(`input ${idx}: Schnorr signature attached`);
        } else if (e.der) {
          attachSignature(idx, e.pubkey || '', String(e.der).toLowerCase());
          log.push(`input ${idx}: DER signature attached`);
        } else if (e.r && e.s) {
          let r = BC.bytesToBig(hexToBytes(String(e.r).padStart(64, '0')));
          let s = BC.bytesToBig(hexToBytes(String(e.s).padStart(64, '0')));
          if (s > BC.secp.N / 2n) s = BC.secp.N - s;
          const shByte = e.sighash !== undefined ? Number(e.sighash) : SIGHASH.effectiveType(inp);
          const der = bytesToHex(BC.derEncode(r, s)) + shByte.toString(16).padStart(2, '0');
          attachSignature(idx, (e.pubkey || '').toLowerCase(), der);
          log.push(`input ${idx}: (r, s) encoded to DER and attached`);
        } else log.push(`input ${idx}: no r/s, der or schnorr field found`);
      } catch (err) { log.push(`input ${idx}: ${err.message}`); }
    }
    $('#imp-der-note').innerHTML = `<div class="hint-text">${log.map(esc).join('<br>')}</div>`;
    renderAll();
  }

  function verifyImported(schnorr) {
    const idx = parseInt($('#imp-idx').value, 10) || 0;
    const pk = ($('#imp-pk').value || '').trim();
    const sig = (schnorr ? $('#imp-schnorr').value : $('#imp-der').value || '').trim();
    if (!pk || !sig) { toast('Public key and signature are both required.', 'warn'); return; }
    let pkg;
    try { pkg = SIGHASH.forInput(state.tx, idx); } catch (e) { toast(e.message, 'err'); return; }
    if (!pkg.digest) { toast('No digest available for that input.', 'err'); return; }
    let res;
    if (schnorr) {
      const b = hexToBytes(sig.replace(/\s/g, ''));
      res = BC.verifySchnorr(hexToBytes(pk), pkg.digest, b.slice(0, 64));
    } else {
      res = BC.verifyECDSA(hexToBytes(pk), pkg.digest, hexToBytes(sig.replace(/\s/g, '')));
    }
    $('#imp-der-note').innerHTML = res.ok
      ? `<div class="ok-text">Valid — this signature matches z = ${bytesToHex(pkg.digest)}</div>`
      : `<div class="err-text">Does not verify: ${esc(res.reason)}</div>`;
  }

  /* ============================= INSPECTOR =============================== */

  const FIELD_COLORS = [
    ['version', 'nVersion'], ['marker', 'SegWit marker'], ['count', 'Counts'], ['txid', 'Previous TXID'],
    ['vout', 'VOUT'], ['scriptlen', 'Script length'], ['script', 'Script bytes'], ['sequence', 'nSequence'],
    ['amount', 'Output value'], ['witness', 'Witness'], ['locktime', 'nLockTime']
  ];

  function runInspector() {
    let bytes;
    if (state.inspectSrc === 'paste') {
      const t = $('#inspect-hex').value.trim();
      if (!t) { $('#hexview').innerHTML = '<div class="empty-note">Paste a transaction hex.</div>'; return; }
      try { bytes = hexToBytes(t); } catch (e) { $('#hexview').innerHTML = `<div class="empty-note redc">${esc(e.message)}</div>`; return; }
    } else {
      bytes = TX.serialize(state.tx, { final: true });
    }
    let dec;
    try { dec = TX.decodeRaw(bytes); }
    catch (e) { $('#hexview').innerHTML = `<div class="empty-note redc">${esc(e.message)}</div>`; return; }
    state.lastDecoded = dec;

    /* map byte offset -> field */
    const map = new Array(dec.size).fill(null);
    dec.fields.forEach((f, fi) => { for (let i = f.start; i < f.start + f.len && i < map.length; i++) map[i] = fi; });

    let html = '';
    for (let off = 0; off < dec.size; off += 16) {
      const cells = [];
      for (let i = off; i < Math.min(off + 16, dec.size); i++) {
        const fi = map[i];
        const kind = fi !== null ? dec.fields[fi].kind : '';
        cells.push(`<span class="byte f-${kind}" data-fi="${fi}" data-bo="${i}">${bytes[i].toString(16).padStart(2, '0')}</span>`);
      }
      html += `<div class="hexrow"><span class="off">${off.toString(16).padStart(4, '0')}</span><span class="hexbytes">${cells.join('')}</span></div>`;
    }
    $('#hexview').innerHTML = html;
    $('#inspect-size').textContent = `${dec.size} bytes${dec.trailing ? ` (+${dec.trailing} trailing)` : ''}`;
    $('#hex-legend').innerHTML = FIELD_COLORS.map(([k, l]) =>
      `<span><i class="f-${k}" style="background:currentColor"></i><i class="f-${k}"></i>${l}</span>`).join('');

    $('#inspect-summary').innerHTML = kvRows([
      ['TXID', dec.txid], ['WTXID', dec.wtxid],
      ['Version', String(dec.version)], ['SegWit', dec.segwit ? `yes (flag 0x${dec.flag.toString(16)})` : 'no'],
      ['Inputs', String(dec.inputs.length)], ['Outputs', String(dec.outputs.length)],
      ['Output total', `${groupNum(dec.outTotal)} sat`],
      ['Size', `${dec.size} B`], ['Base', `${dec.baseSize} B`], ['vSize', `${dec.vsize} vB`], ['Weight', `${dec.weight} WU`],
      ['nLockTime', `${dec.locktime} — ${TX.describeLocktime(dec.locktime)}`]
    ]);

    $('#inspect-table').innerHTML = `
      <thead><tr><th>Offset</th><th>Len</th><th>Field</th><th>Value</th></tr></thead>
      <tbody>${dec.fields.map((f, fi) => `
        <tr data-fi="${fi}">
          <td class="m">0x${f.start.toString(16).padStart(4, '0')}</td>
          <td class="m">${f.len}</td>
          <td class="k">${esc(f.label)}</td>
          <td class="m brk">${esc(String(f.value).length > 90 ? String(f.value).slice(0, 90) + '…' : f.value)}</td>
        </tr>`).join('')}</tbody>`;
    $('#byteinfo').innerHTML = 'Hover a byte.';
  }

  function showByteInfo(fi, bo) {
    const dec = state.lastDecoded;
    if (!dec || fi === null || fi === 'null') { $('#byteinfo').innerHTML = 'Hover a byte.'; return; }
    const f = dec.fields[Number(fi)];
    if (!f) return;
    const slice = dec.bytes.slice(f.start, f.start + f.len);
    $('#byteinfo').innerHTML = `
      <div><span class="bk">Offset</span> <span class="bv">0x${f.start.toString(16).padStart(4, '0')} (${f.start})</span></div>
      <div><span class="bk">Length</span> <span class="bv">${f.len} byte${f.len === 1 ? '' : 's'}</span></div>
      <div><span class="bk">Field</span> <span class="bv accent">${esc(f.label)}</span></div>
      <div><span class="bk">Raw</span> <span class="bv brk">${bytesToHex(slice)}</span></div>
      <div><span class="bk">Value</span> <span class="bv brk">${esc(f.value)}</span></div>
      ${bo !== undefined ? `<div><span class="bk">This byte</span> <span class="bv">0x${dec.bytes[bo].toString(16).padStart(2, '0')} at ${bo} (offset ${bo - f.start} within the field)</span></div>` : ''}`;
    $$('.byte').forEach(b => b.classList.toggle('hl', b.dataset.fi === String(fi)));
    $$('#inspect-table tr').forEach(tr => tr.style.background = tr.dataset.fi === String(fi) ? 'var(--accent-bg)' : '');
  }

  /* ============================= VALIDATION ============================== */

  function renderValidation() {
    const res = VALIDATE.run(state.tx);
    const tagFor = { valid: 'green', nonstandard: 'amber', invalid: 'red', unknown: 'grey', info: 'blue' };
    const labelFor = { valid: 'VALID', nonstandard: 'NON-STANDARD', invalid: 'INVALID', unknown: 'UNKNOWN', info: 'INFO' };

    $('#val-chips').innerHTML = `
      <span class="tag red">${res.counts.invalid} invalid</span>
      <span class="tag amber">${res.counts.nonstandard} non-standard</span>
      <span class="tag grey">${res.counts.unknown} unknown</span>
      <span class="tag blue">${res.counts.info} info</span>`;

    $('#validation-list').innerHTML = res.rows.map(r => `
      <div class="vrow">
        <span class="tag ${tagFor[r.sev]}">${labelFor[r.sev]}</span>
        <div class="vtxt"><div class="vt">${esc(r.title)}</div><div class="vd">${esc(r.detail)}</div></div>
        <span class="vloc">${esc(r.loc)}</span>
      </div>`).join('');

    const sel = $('#matrix-input');
    sel.innerHTML = state.tx.inputs.map((inp, i) => `<option value="${i}" ${state.matrixIndex === i ? 'selected' : ''}>Input #${i}</option>`).join('');
    renderMatrix();
    return res;
  }

  function renderMatrix() {
    const i = Math.min(state.matrixIndex, state.tx.inputs.length - 1);
    if (i < 0) { $('#sighash-matrix').innerHTML = '<div class="hint-text">No inputs.</div>'; return; }
    const inp = state.tx.inputs[i];
    const spk = safe(() => hexToBytes(inp.scriptPubKey), new Uint8Array(0));
    const isTr = spk.length && S.classify(spk).type === 'P2TR';
    const algo = isTr ? 'bip341' : (S.deriveScriptCode(inp).kind === 'bip143' ? 'bip143' : 'legacy');
    const current = SIGHASH.effectiveType(inp);

    const cols = ['version', 'otherInputs', 'inputAmounts', 'inputScriptPubKeys', 'sequences', 'outputs', 'scriptCode', 'locktime'];
    const heads = ['nVersion', 'Other inputs', 'Amounts', 'Prevout scripts', 'Sequences', 'Outputs', 'scriptCode', 'nLockTime'];

    $('#sighash-matrix').innerHTML = `
      <div class="hint-text mb">Input #${i} · ${algo === 'bip341' ? 'BIP341 (taproot)' : algo === 'bip143' ? 'BIP143 (segwit v0)' : 'legacy'} algorithm.
        The highlighted row is the type currently selected on this input.</div>
      <table class="matrix">
        <tr><th>SIGHASH type</th>${heads.map(h => `<th>${h}</th>`).join('')}<th>Byte</th></tr>
        ${SIGHASH.TYPES.filter(t => algo === 'bip341' || !t.taprootOnly).map(t => {
          const c = SIGHASH.commitment(t.v, algo);
          return `<tr class="${t.v === current ? 'hl' : ''}">
            <td>${t.name}</td>
            ${cols.map(k => {
              const cell = c[k];
              return `<td class="${cell.on ? 'yes' : 'no'}">${cell.partial ? '<span class="part">matching only</span>' : cell.on ? '✓' : '—'}</td>`;
            }).join('')}
            <td class="m">0x${t.v.toString(16).padStart(2, '0')}</td>
          </tr>`;
        }).join('')}
      </table>`;
  }

  /* =============================== RAW LAB =============================== */

  function wireRawLab() {
    const recalcHash = () => {
      const encv = $('#hash-enc').value;
      const txt = $('#hash-in').value;
      let bytes;
      try {
        bytes = encv === 'hex' ? hexToBytes(txt) : encv === 'utf8' ? ENC.utf8ToBytes(txt)
              : encv === 'ascii' ? ENC.asciiToBytes(txt) : ENC.base64ToBytes(txt);
      } catch (e) { $('#hash-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; return; }
      const tag = $('#hash-tag').value.trim();
      const rows = [
        ['Length', bytes.length + ' bytes'],
        ['SHA256', bytesToHex(BC.sha256(bytes))],
        ['SHA256d', bytesToHex(BC.hash256(bytes))],
        ['SHA256d reversed', bytesToHex(ENC.reverse(BC.hash256(bytes)))],
        ['RIPEMD160', bytesToHex(BC.ripemd160(bytes))],
        ['HASH160', bytesToHex(BC.hash160(bytes))],
        ['SHA1', bytesToHex(BC.sha1(bytes))]
      ];
      if (tag) rows.push([`Tagged "${tag}"`, bytesToHex(BC.taggedHash(tag, bytes))]);
      $('#hash-out').innerHTML = kvRows(rows);
    };
    ['#hash-in', '#hash-enc', '#hash-tag'].forEach(s => { $(s).oninput = recalcHash; $(s).onchange = recalcHash; });

    $('#der-in').oninput = () => {
      const t = $('#der-in').value.trim().replace(/\s/g, '');
      if (!t) { $('#der-out').innerHTML = ''; return; }
      try {
        const d = BC.derDecode(hexToBytes(t));
        if (!d.ok) { $('#der-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(d.error)}</dd>`; return; }
        const rows = [
          ['r', bytesToHex(d.rHex)], ['s', bytesToHex(d.sHex)],
          ['s is low', d.lowS ? 'yes' : 'NO — above N/2'],
          ['N − s', bytesToHex(d.sComplement)],
          ['Sighash byte', d.sighash === null ? '(none)' : `0x${d.sighash.toString(16).padStart(2, '0')} — ${SIGHASH.nameOf(d.sighash)}`],
          ['Strict DER', d.strictDER ? 'yes' : 'no — ' + d.issues.join('; ')]
        ];
        const rc = BC.rCandidates(d.rHex);
        if (rc) { rows.push(['R with even Y', bytesToHex(rc.even)]); rows.push(['R with odd Y', bytesToHex(rc.odd)]); }
        else rows.push(['R point', 'r is not a valid x-coordinate on secp256k1']);
        $('#der-out').innerHTML = kvRows(rows);
      } catch (e) { $('#der-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; }
    };

    $('#btn-rs-build').onclick = () => {
      try {
        const r = BC.bytesToBig(hexToBytes($('#rs-r').value.trim().padStart(64, '0')));
        const s = BC.bytesToBig(hexToBytes($('#rs-s').value.trim().padStart(64, '0')));
        const sh = $('#rs-sh').value.trim().replace(/^0x/i, '');
        $('#rs-out').value = bytesToHex(BC.derEncode(r, s)) + (sh ? sh.padStart(2, '0') : '');
      } catch (e) { toast(e.message, 'err'); }
    };
    $('#btn-rs-low').onclick = () => {
      try {
        let s = BC.bytesToBig(hexToBytes($('#rs-s').value.trim().padStart(64, '0')));
        if (s > BC.secp.N / 2n) { s = BC.secp.N - s; $('#rs-s').value = bytesToHex(BC.bigToBytes(s, 32)); toast('s normalised to the low form.'); }
        else toast('s is already low.');
      } catch (e) { toast(e.message, 'err'); }
    };

    $('#btn-addr-decode').onclick = () => {
      const a = $('#addr-in').value.trim();
      const v = S.validateAddress(a, state.tx.network);
      if (!v.ok) { $('#addr-out').innerHTML = `<dt class="redc">Invalid</dt><dd>${esc(v.error)}</dd>`; return; }
      $('#addr-script').value = bytesToHex(v.script);
      $('#addr-out').innerHTML = kvRows([
        ['Type', v.type], ['scriptPubKey', bytesToHex(v.script)], ['ASM', S.toAsm(v.script)],
        ['Network', netOf().label], ['Size', v.script.length + ' bytes']
      ]);
    };
    $('#btn-script-to-addr').onclick = () => {
      try {
        const b = hexToBytes($('#addr-script').value.trim());
        const a = S.scriptToAddress(b, state.tx.network);
        $('#addr-in').value = a || '';
        $('#addr-out').innerHTML = kvRows([
          ['Type', S.classify(b).type], ['Address', a || 'no address encoding for this script type'], ['ASM', S.toAsm(b)]
        ]);
      } catch (e) { $('#addr-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; }
    };

    $('#btn-tr-compute').onclick = () => {
      const rows = [];
      try {
        const internal = hexToBytes($('#tr-internal').value.trim());
        const leafHexRaw = $('#tr-leaf').value.trim();
        const lv = parseInt($('#tr-leafver').value.trim().replace(/^0x/i, ''), 16) || 0xc0;
        let merkle = $('#tr-merkle').value.trim() ? hexToBytes($('#tr-merkle').value.trim()) : null;
        if (leafHexRaw) {
          const lh = BC.tapLeafHash(hexToBytes(leafHexRaw), lv);
          rows.push(['TapLeaf hash', bytesToHex(lh)]);
          if (!merkle) { merkle = lh; rows.push(['Merkle root', bytesToHex(lh) + '  (single-leaf tree)']); }
        }
        if (internal.length === 32) {
          const t = BC.taprootTweak(internal, merkle);
          rows.push(['TapTweak scalar', bytesToHex(t.tweak)]);
          rows.push(['Output key', bytesToHex(t.outputKey)]);
          rows.push(['Parity', String(t.parity)]);
          rows.push(['scriptPubKey', bytesToHex(S.p2tr(t.outputKey))]);
          rows.push(['Address', S.scriptToAddress(S.p2tr(t.outputKey), state.tx.network) || '—']);
          if (leafHexRaw) rows.push(['Control block', bytesToHex(BC.cat(new Uint8Array([(lv & 0xfe) | t.parity]), internal))]);
        } else if (internal.length) rows.push(['Error', `internal key is ${internal.length} bytes, expected 32`]);
      } catch (e) { rows.push(['Error', e.message]); }
      $('#tr-out').innerHTML = kvRows(rows);
    };

    $('#btn-verify').onclick = () => {
      try {
        const pk = hexToBytes($('#ver-pk').value.trim());
        const z = hexToBytes($('#ver-z').value.trim());
        const sig = hexToBytes($('#ver-sig').value.trim().replace(/\s/g, ''));
        const res = $('#ver-algo').value === 'schnorr'
          ? BC.verifySchnorr(pk, z, sig.slice(0, 64))
          : BC.verifyECDSA(pk, z, sig);
        $('#ver-out').innerHTML = res.ok
          ? `<div class="banner blue" style="border-color:var(--green);background:var(--green-bg)">${ico('check-circle', 18)}<div><strong>Valid signature.</strong></div></div>`
          : `<div class="banner red">${ico('alert', 18)}<div><strong>Does not verify.</strong> ${esc(res.reason)}</div></div>`;
      } catch (e) { $('#ver-out').innerHTML = `<div class="err-text">${esc(e.message)}</div>`; }
    };
    $('#btn-verify-fill').onclick = () => {
      try {
        const pkg = SIGHASH.forInput(state.tx, state.signingIndex);
        if (pkg.digest) { $('#ver-z').value = bytesToHex(pkg.digest); toast(`Filled z from input #${state.signingIndex}.`); }
        else toast('That input has no digest yet.', 'warn');
      } catch (e) { toast(e.message, 'err'); }
    };

    $('#stage').addEventListener('click', (e) => {
      const b = e.target.closest('[data-util]');
      if (!b) return;
      const v = $('#util-in').value.trim();
      const out = $('#util-out');
      try {
        switch (b.dataset.util) {
          case 'reverse':   out.value = bytesToHex(ENC.reverse(hexToBytes(v))); break;
          case 'varint':    out.value = bytesToHex(ENC.encodeVarInt(BigInt(v))); break;
          case 'scriptnum': out.value = bytesToHex(S.scriptNum(BigInt(v))); break;
          case 'u32':       { const w = new ENC.Writer(); w.u32(Number(v)); out.value = w.toHex(); break; }
          case 'u64':       { const w = new ENC.Writer(); w.u64(BigInt(v)); out.value = w.toHex(); break; }
          case 'b64':       out.value = bytesToBase64(hexToBytes(v)); break;
          case 'unb64':     out.value = bytesToHex(ENC.base64ToBytes(v)); break;
          case 'text':      out.value = ENC.bytesToUtf8(hexToBytes(v)) + '\n\nASCII: ' + ENC.bytesToAscii(hexToBytes(v)); break;
          case 'push':      out.value = bytesToHex(S.pushData(hexToBytes(v))); break;
        }
      } catch (err) { out.value = '⚠ ' + err.message; }
    });
  }

  /* ============================== TOOLKIT ================================ */

  const NUMS_POINT = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

  function renderToolkit() {
    /* one-time population of the static selects */
    const tplSel = $('#desc-tpl');
    if (tplSel && !tplSel.options.length) {
      tplSel.innerHTML = '<option value="">— pick a pattern —</option>' +
        TOOLS.DESC_TEMPLATES.map(t => `<option value="${t.id}">${esc(t.label)}</option>`).join('');
    }
    const unitSel = $('#unit-from');
    if (unitSel && !unitSel.options.length) {
      unitSel.innerHTML = TOOLS.UNITS.map(u => `<option value="${u.id}">${esc(u.label)}</option>`).join('');
      unitSel.value = 'sat';
    }
    if (!$('#leaf-list').children.length) { state.leaves = state.leaves || []; renderLeaves(); }
    if (!$('#est-inputs').children.length) renderEstimator();
    recalcUnits();
  }

  /* ---- taproot tree ---- */

  function renderLeaves() {
    state.leaves = state.leaves || [];
    const el = $('#leaf-list');
    if (!el) return;
    el.innerHTML = state.leaves.length ? state.leaves.map((l, i) => `
      <div class="leafrow">
        <span class="ln">${i}</span>
        <input type="text" class="mono" data-leaf="${i}" data-k="script" value="${esc(l.script)}" placeholder="script hex or ASM">
        <input type="text" class="mono" data-leaf="${i}" data-k="version" value="${esc(l.version)}" placeholder="c0">
        <button class="iconbtn" data-act="leaf-del" data-i="${i}">${ico('x')}</button>
      </div>`).join('') : '<div class="hint-text">No leaves — a key-path-only output has no tree.</div>';
  }

  function buildTree() {
    const internal = $('#tree-internal').value.trim();
    const out = $('#tree-out'), layout = $('#tree-layout'), leavesEl = $('#tree-leaves');
    try {
      const leaves = (state.leaves || []).filter(l => l.script.trim()).map(l => {
        const raw = l.script.trim();
        const script = (/^[0-9a-fA-F\s]+$/.test(raw) && raw.replace(/\s/g, '').length % 2 === 0)
          ? hexToBytes(raw) : S.fromAsm(raw);
        return { script, version: parseInt(String(l.version || 'c0').replace(/^0x/i, ''), 16) || 0xc0 };
      });
      if (!internal) throw new Error('an internal key is required');
      const r = TOOLS.taprootOutput(internal, leaves);
      state.lastTree = r;

      layout.innerHTML = leaves.length ? TOOLS.buildTapTree(leaves).layout : '<span class="mutedc">key-path only — no tree</span>';
      out.innerHTML = kvRows([
        ['Merkle root', r.merkleRoot || '(none — key path only)'],
        ['TapTweak', r.tweak],
        ['Output key', r.outputKey],
        ['Parity', String(r.parity)],
        ['scriptPubKey', r.scriptPubKey],
        ['Address', S.scriptToAddress(hexToBytes(r.scriptPubKey), state.tx.network) || '—']
      ]);
      leavesEl.innerHTML = r.leaves.length ? `
        <div class="subhead">Per-leaf spending data</div>
        ${r.leaves.map(l => `
          <div class="card open" style="margin-bottom:8px">
            <div class="card-head" style="cursor:default">
              <span class="idx">LEAF ${l.index}</span>
              <span class="tag violet">v0x${l.version.toString(16)}</span>
              <span class="meta">${l.script.length / 2} bytes · ${l.merklePath.length} sibling${l.merklePath.length === 1 ? '' : 's'}</span>
            </div>
            <div class="card-body">
              <div class="mb">${hlAsm(l.script, { trim: 32 })}</div>
              <dl class="kv">${kvRows([
                ['TapLeaf hash', l.leafHash],
                ['Control block', l.controlBlock],
                ['Merkle path', l.merklePath.join('  ') || '(none)']
              ])}</dl>
              <div class="flexrow mt">
                <button class="btn sm" data-act="leaf-to-input" data-i="${l.index}">Send this leaf to an input</button>
              </div>
            </div>
          </div>`).join('')}` : '';
    } catch (e) {
      out.innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`;
      layout.textContent = '—';
      leavesEl.innerHTML = '';
    }
  }

  /* ---- estimator ---- */

  function renderEstimator() {
    state.est = state.est || {
      inputs: Object.keys(TOOLS.INPUT_COSTS).map(t => ({ type: t, count: t === 'P2WPKH' ? 1 : 0 })),
      outputs: Object.keys(TOOLS.OUTPUT_COSTS).map(t => ({ type: t, count: t === 'P2WPKH' ? 2 : 0 }))
    };
    const row = (kind, list, costs) => list.map((r, i) => `
      <div class="leafrow" style="grid-template-columns:1fr 74px">
        <label class="check" style="cursor:default">
          <span style="font-family:var(--mono);font-size:11px">${esc(r.type)}</span>
          <span class="mutedc small">${esc(costs[r.type].note || costs[r.type] + ' B')}</span>
        </label>
        <input type="number" min="0" class="mono" data-est="${kind}" data-i="${i}" value="${r.count}">
      </div>`).join('');
    $('#est-inputs').innerHTML = row('inputs', state.est.inputs, TOOLS.INPUT_COSTS);
    $('#est-outputs').innerHTML = row('outputs', state.est.outputs, TOOLS.OUTPUT_COSTS);
    recalcEstimate();
  }

  function recalcEstimate() {
    const rate = parseFloat($('#est-rate').value) || 0;
    const r = TOOLS.estimate(state.est.inputs.filter(x => x.count > 0), state.est.outputs.filter(x => x.count > 0), rate);
    $('#est-out').innerHTML =
      tile('Size', `${r.total}<span style="font-size:12px;color:var(--muted)"> B</span>`, `${r.base} B base`, 'blue') +
      tile('vSize', `${r.vsize}<span style="font-size:12px;color:var(--muted)"> vB</span>`, r.segwit ? `${r.discount}% segwit discount` : 'legacy', 'violet') +
      tile('Weight', groupNum(r.weight), `${(r.weight / 4000).toFixed(1)}% of a block’s 4M WU`, '') +
      tile('Fee', groupNum(r.fee), `at ${rate} sat/vB`, 'accent');
  }

  /* ---- units ---- */

  function recalcUnits() {
    const el = $('#unit-out');
    if (!el) return;
    try {
      const r = TOOLS.convertUnits($('#unit-in').value, $('#unit-from').value);
      const dust = r.isDust.p2wpkh ? '<span class="tag amber">below P2WPKH dust</span>'
        : r.isDust.p2pkh ? '<span class="tag amber">below P2PKH dust</span>' : '<span class="tag green">above dust</span>';
      el.innerHTML = r.values.map(v =>
        `<div class="p"><div class="pk">${esc(v.label)}</div><div class="pv">${esc(v.value)}</div></div>`).join('') +
        `<div class="p"><div class="pk">8-byte LE (as serialized)</div><div class="pv">${esc(r.hex)}</div></div>` +
        `<div class="p"><div class="pk">Dust check</div><div class="pv">${dust}</div></div>`;
    } catch (e) { el.innerHTML = `<div class="p"><div class="pk">Error</div><div class="pv redc">${esc(e.message)}</div></div>`; }
  }

  function recalcBase() {
    const el = $('#base-out');
    const r = TOOLS.convertBase($('#base-in').value);
    if (!r) { el.innerHTML = ''; return; }
    if (r.error) { el.innerHTML = `<dt class="redc">Error</dt><dd>${esc(r.error)}</dd>`; return; }
    el.innerHTML = kvRows([
      ['Decimal', r.decimal], ['Hex', r.hexPrefixed], ['Binary', r.binary], ['Octal', r.octal],
      ['Bytes', String(r.bytes)], ['Little-endian', r.littleEndian],
      ['Base58', r.base58], ['Base64', r.base64],
      ['CScriptNum', r.scriptNum], ['Varint', r.varint],
      ['Fits uint32 / int32', `${r.fitsU32 ? 'yes' : 'no'} / ${r.fitsI32 ? 'yes' : 'no'}`]
    ]);
  }

  /* ---- locktime + sequence ---- */

  function recalcLocktime() {
    const info = TOOLS.locktimeInfo($('#lt-in').value, null, $('#lt-height').value);
    const rows = [['Raw', String(info.raw)], ['Hex (LE in the tx)', info.hex], ['Kind', info.kind], ['Meaning', info.meaning]];
    if (info.utc) rows.push(['UTC', info.utc], ['Local', info.local]);
    if (info.eta) rows.push(['ETA', info.eta]);
    $('#lt-out').innerHTML = kvRows(rows);
  }

  function recalcSequence() {
    const type = $('#seq-type').value;
    const val = parseFloat($('#seq-val').value) || 0;
    const encoded = TOOLS.encodeSequence(
      type === 'disabled' ? { disabled: true } : type === 'time' ? { type: 'time', seconds: val * 512 } : { blocks: val });
    const rawIn = $('#seq-raw').value.trim();
    const decodeTarget = rawIn ? (parseInt(rawIn.replace(/^0x/i, ''), 16) >>> 0) : encoded;
    const d = TOOLS.decodeSequence(decodeTarget);
    $('#seq-out').innerHTML = kvRows([
      ['Encoded', '0x' + encoded.toString(16).padStart(8, '0')],
      ['Decoding', d.hex],
      ['Relative timelock', d.relative],
      ['Signals RBF', d.rbf ? 'yes (BIP125)' : 'no'],
      ['nLockTime enabled', d.locktimeEnabled ? 'yes' : 'no — this input is final']
    ]);
  }

  /* ---- code generation ---- */

  function renderCode() {
    const tabs = $('#code-tabs');
    if (!tabs) return;
    state.codeLang = state.codeLang || 'py-coincurve';
    tabs.innerHTML = TOOLS.CODE_LANGS.map(l =>
      `<button data-lang="${l.id}" class="${state.codeLang === l.id ? 'on' : ''}">${esc(l.label)}</button>`).join('') +
      '<span class="grow"></span>';
    const pkgs = state.tx.inputs.map((_, i) => signingPackage(i));
    const psbt = safe(() => bytesToBase64(PSBT.build(state.tx, state.tx.psbtVersion)), '');
    const src = TOOLS.generateCode(state.codeLang, pkgs, { network: state.tx.network, psbt });
    state.lastCode = src;
    $('#code-body').innerHTML = highlightCode(src, state.codeLang);
  }

  /** Lightweight tokeniser — enough to make the snippets readable, not a parser. */
  function highlightCode(src, lang) {
    const isShell = lang === 'cli';
    const kw = isShell
      ? /\b(bitcoin-cli|decoderawtransaction|decodepsbt|analyzepsbt|walletprocesspsbt|finalizepsbt|testmempoolaccept|sendrawtransaction|signrawtransactionwithkey)\b/g
      : /\b(import|from|for|in|if|not|else|continue|print|def|return|const|let|var|function|new|of|export|assert|True|False|None|null|true|false)\b/g;
    let out = esc(src);
    /* comments first so keywords inside them are not re-coloured */
    out = out.replace(/(^|\n)(\s*(?:#|\/\/)[^\n]*)/g, (m, a, b) => `${a}<span class="c-com">${b}</span>`);
    out = out.replace(/(&quot;&quot;&quot;[\s\S]*?&quot;&quot;&quot;)/g, '<span class="c-com">$1</span>');
    out = out.replace(/(&#39;[^&\n]*?&#39;|&quot;[^&\n]*?&quot;)/g, '<span class="c-str">$1</span>');
    out = out.replace(kw, '<span class="c-kw">$&</span>');
    out = out.replace(/\b(\d+)\b/g, '<span class="c-num">$1</span>');
    return out;
  }

  function wireToolkit() {
    /* descriptors */
    $('#desc-tpl').onchange = (e) => {
      const t = TOOLS.DESC_TEMPLATES.find(x => x.id === e.target.value);
      if (t) { $('#desc-in').value = t.pattern; $('#btn-desc-check').click(); }
    };
    $('#btn-desc-check').onclick = () => {
      const v = $('#desc-in').value.trim();
      if (!v) return;
      try {
        const r = TOOLS.descVerify(v);
        $('#desc-in').value = r.suggested;
        $('#desc-out').innerHTML = r.ok
          ? `<div class="ok-text">Checksum valid (<span class="mono">#${esc(r.expected)}</span>).</div>`
          : r.given
            ? `<div class="warn-text">Checksum was <span class="mono">#${esc(r.given)}</span>, should be <span class="mono">#${esc(r.expected)}</span> — corrected above.</div>`
            : `<div class="ok-text">Checksum added: <span class="mono">#${esc(r.suggested.split('#')[1])}</span></div>`;
      } catch (e) { $('#desc-out').innerHTML = `<div class="err-text">${esc(e.message)}</div>`; }
    };
    $('#btn-desc-from-tx').onclick = () => {
      const rows = [];
      state.tx.inputs.forEach((inp, i) => {
        if (!inp.scriptPubKey) return;
        const d = safe(() => TOOLS.descriptorFor(inp.scriptPubKey, {
          network: state.tx.network,
          innerScript: inp.redeemScript ? hexToBytes(inp.redeemScript) : (inp.witnessScript ? hexToBytes(inp.witnessScript) : null),
          internalKey: inp.taproot && inp.taproot.internalKey ? inp.taproot.internalKey : null
        }), null);
        if (d) rows.push([`Input ${i}`, d]);
      });
      state.tx.outputs.forEach((o, i) => {
        const r = TX.resolveOutput(o, state.tx.network);
        if (!r.script || !r.script.length) return;
        const d = safe(() => TOOLS.descriptorFor(bytesToHex(r.script), { network: state.tx.network }), null);
        if (d) rows.push([`Output ${i}`, d]);
      });
      $('#desc-out').innerHTML = rows.length
        ? `<dl class="kv">${kvRows(rows)}</dl>`
        : '<div class="hint-text">Nothing to describe yet — fill in some scripts first.</div>';
    };

    /* extended keys */
    $('#btn-xkey').onclick = () => {
      try {
        const r = TOOLS.decodeXKey($('#xkey-in').value);
        const rows = [
          ['Prefix', `${r.prefix} (${r.version})`], ['Network', r.network], ['Key type', r.kind],
          ['Typical use', r.scriptHint], ['Depth', String(r.depth)],
          ['Parent fingerprint', r.parentFingerprint], ['Child number', r.childNumber],
          ['Chain code', r.chainCode]
        ];
        if (r.publicKey) {
          rows.push(['Public key', r.publicKey], ['Own fingerprint', r.fingerprint],
            ['x-only', r.xOnly], ['On curve', r.pointValid ? 'yes' : 'NO — malformed']);
        }
        let html = kvRows(rows);
        if (r.warning) html += `<dt class="redc">Warning</dt><dd class="v-warn">${esc(r.warning)}</dd>`;
        if (r.anomaly) html += `<dt class="amberc">Anomaly</dt><dd class="v-warn">${esc(r.anomaly)}</dd>`;
        $('#xkey-out').innerHTML = html;
      } catch (e) { $('#xkey-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; }
    };

    /* taproot tree */
    $('#btn-leaf-add').onclick = () => {
      state.leaves = state.leaves || [];
      state.leaves.push({ script: '', version: 'c0' });
      renderLeaves();
    };
    $('#btn-tree-build').onclick = buildTree;
    $('#btn-tree-nums').onclick = () => {
      $('#tree-internal').value = NUMS_POINT;
      toast('Using the BIP341 NUMS point — no key-path spend is possible.');
      buildTree();
    };
    $('#btn-tree-apply').onclick = () => {
      if (!state.lastTree) { toast('Build the tree first.', 'warn'); return; }
      const idx = parseInt(prompt('Apply to which input index?', '0'), 10);
      const inp = state.tx.inputs[idx];
      if (!inp) { toast(`There is no input #${idx}.`, 'err'); return; }
      inp.scriptPubKey = state.lastTree.scriptPubKey;
      inp.taproot.internalKey = state.lastTree.internalKey;
      inp.taproot.merkleRoot = state.lastTree.merkleRoot || '';
      inp.algorithm = 'schnorr';
      if (state.lastTree.leaves.length) {
        inp.taproot.path = 'script';
        inp.taproot.leafScript = state.lastTree.leaves[0].script;
        inp.taproot.leafVersion = state.lastTree.leaves[0].version;
        inp.taproot.controlBlock = state.lastTree.leaves[0].controlBlock;
      }
      renderAll();
      toast(`Input #${idx} is now the taproot output ${shortHex(state.lastTree.outputKey, 8)}.`);
    };
    $('#stage').addEventListener('input', (e) => {
      const l = e.target.closest('[data-leaf]');
      if (!l) return;
      state.leaves[Number(l.dataset.leaf)][l.dataset.k] = l.value;
    });
    $('#stage').addEventListener('click', (e) => {
      const d = e.target.closest('[data-act="leaf-del"]');
      if (d) { state.leaves.splice(Number(d.dataset.i), 1); renderLeaves(); buildTree(); return; }
      const a = e.target.closest('[data-act="leaf-to-input"]');
      if (a && state.lastTree) {
        const leaf = state.lastTree.leaves[Number(a.dataset.i)];
        const idx = parseInt(prompt('Send this leaf to which input index?', '0'), 10);
        const inp = state.tx.inputs[idx];
        if (!inp) { toast(`There is no input #${idx}.`, 'err'); return; }
        inp.scriptPubKey = state.lastTree.scriptPubKey;
        inp.taproot.internalKey = state.lastTree.internalKey;
        inp.taproot.merkleRoot = state.lastTree.merkleRoot || '';
        inp.taproot.path = 'script';
        inp.taproot.leafScript = leaf.script;
        inp.taproot.leafVersion = leaf.version;
        inp.taproot.controlBlock = leaf.controlBlock;
        inp.algorithm = 'schnorr';
        renderAll();
        toast(`Leaf ${leaf.index} applied to input #${idx}.`);
      }
    });

    /* units / bases */
    ['#unit-in', '#unit-from'].forEach(s => { $(s).oninput = recalcUnits; $(s).onchange = recalcUnits; });
    $('#base-in').oninput = recalcBase;

    /* locktime / sequence */
    ['#lt-in', '#lt-height'].forEach(s => $(s).oninput = recalcLocktime);
    $('#btn-lt-date').onclick = () => {
      try { $('#lt-in').value = TOOLS.dateToLocktime($('#lt-date').value.trim()); recalcLocktime(); }
      catch (e) { toast(e.message, 'err'); }
    };
    $('#btn-lt-apply').onclick = () => {
      const v = parseInt($('#lt-in').value, 10) || 0;
      state.tx.locktime = v;
      state.tx.locktimeMode = v === 0 ? 'disabled' : v < TX.LOCKTIME_THRESHOLD ? 'height' : 'time';
      renderAll();
      toast(`nLockTime set to ${groupNum(v)}.`);
    };
    ['#seq-type', '#seq-val', '#seq-raw'].forEach(s => { $(s).oninput = recalcSequence; $(s).onchange = recalcSequence; });

    /* estimator */
    $('#est-rate').oninput = recalcEstimate;
    $('#stage').addEventListener('input', (e) => {
      const t = e.target.closest('[data-est]');
      if (!t) return;
      state.est[t.dataset.est][Number(t.dataset.i)].count = Math.max(0, parseInt(t.value, 10) || 0);
      recalcEstimate();
    });

    /* pubkeys */
    $('#btn-pk').onclick = () => {
      try {
        const r = TOOLS.pubkeyInfo($('#pk-in').value);
        if (!r.valid) { $('#pk-out').innerHTML = `<dt class="redc">Invalid</dt><dd>${esc(r.error)}</dd>`; return; }
        $('#pk-out').innerHTML = kvRows([
          ['Input form', r.form], ['Compressed', r.compressed], ['Uncompressed', r.uncompressed],
          ['x-only (BIP340)', r.xOnly], ['Y parity', r.yParity === 0 ? 'even' : 'odd'],
          ['HASH160 (compressed)', r.hash160], ['HASH160 (uncompressed)', r.hash160Uncompressed],
          ['SHA256', r.sha256]
        ]);
      } catch (e) { $('#pk-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; }
    };
    $('#btn-pk-scripts').onclick = () => {
      try {
        const r = TOOLS.scriptsForPubkey($('#pk-in').value, state.tx.network);
        if (r.error) { $('#pk-scripts').innerHTML = `<div class="err-text">${esc(r.error)}</div>`; return; }
        $('#pk-scripts').innerHTML = `<div class="tbl-wrap"><table class="data">
          <thead><tr><th>Form</th><th>Address</th><th>scriptPubKey</th><th></th></tr></thead>
          <tbody>${r.rows.map(x => `<tr>
            <td class="k">${esc(x.label)}</td>
            <td class="m v-addr">${esc(x.address)}</td>
            <td class="m brk">${esc(shortHex(x.script, 16))}</td>
            <td>${copyVal(x.script, 'Copy scriptPubKey')}</td></tr>`).join('')}</tbody></table></div>`;
      } catch (e) { $('#pk-scripts').innerHTML = `<div class="err-text">${esc(e.message)}</div>`; }
    };

    /* merkle */
    $('#btn-merkle').onclick = () => {
      const ids = $('#mk-in').value.split(/\s+/).filter(Boolean);
      if (!ids.length) { $('#mk-out').innerHTML = ''; return; }
      try {
        const r = TOOLS.merkleRoot(ids);
        $('#mk-out').innerHTML = kvRows([
          ['Leaves', String(ids.length)], ['Tree levels', String(r.levels)],
          ['Merkle root (display order)', r.root],
          ['Merkle root (internal/LE)', r.internal]
        ]);
      } catch (e) { $('#mk-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; }
    };

    /* script analyser */
    const runAnalyse = () => {
      const v = $('#an-in').value.trim();
      if (!v) { $('#an-out').innerHTML = ''; $('#an-asm').innerHTML = ''; return; }
      try {
        const b = hexToBytes(v);
        const r = TOOLS.analyseScript(b);
        $('#an-asm').innerHTML = hlAsm(b, { lg: true });
        const rows = [
          ['Detected type', r.type], ['Size', `${r.size} bytes`],
          ['Opcodes (non-push)', String(r.opCount)], ['Sigops (worst case)', String(r.sigops)],
          ['Data pushed', `${r.pushBytes} bytes · largest ${r.maxPush}`],
          ['OP_IF nesting', String(r.ifDepth)],
          ['HASH160', r.hash160], ['SHA256', r.sha256]
        ];
        if (r.parseError) rows.push(['Parse error', r.parseError]);
        if (r.overSizeLimit) rows.push(['Over 10 000-byte consensus limit', 'YES']);
        if (r.overOpLimit) rows.push(['Over the 201-opcode limit', 'YES']);
        if (r.p2shOverSize) rows.push(['Too large for P2SH/P2WSH', `${r.size} B > 520 B`]);
        r.notes.forEach(n => rows.push(['Note', n]));
        $('#an-out').innerHTML = kvRows(rows);
      } catch (e) { $('#an-out').innerHTML = `<dt class="redc">Error</dt><dd>${esc(e.message)}</dd>`; }
    };
    $('#btn-analyse').onclick = runAnalyse;
    $('#btn-analyse-lab').onclick = () => { $('#an-in').value = $('#script-hex').value; runAnalyse(); };

    /* code export */
    $('#code-tabs').addEventListener('click', (e) => {
      const b = e.target.closest('[data-lang]');
      if (!b) return;
      state.codeLang = b.dataset.lang;
      renderCode();
    });
    $('#btn-code-copy').onclick = () => copyText(state.lastCode || '');
    $('#btn-code-save').onclick = () => {
      const ext = state.codeLang.startsWith('py') || state.codeLang === 'verify-py' ? 'py'
        : state.codeLang === 'cli' ? 'sh' : 'mjs';
      download(`sign-${state.codeLang}.${ext}`, state.lastCode || '', 'text/plain');
    };

    /* pipeline + flow jump targets */
    $('#stage').addEventListener('click', (e) => {
      const g = e.target.closest('[data-goto]');
      if (!g) return;
      showWorkspace(g.dataset.goto);
      const focus = g.dataset.focus;
      if (focus !== undefined) {
        const card = $(`[data-card="${g.dataset.goto === 'inputs' ? 'in' : 'out'}"][data-idx="${focus}"]`);
        if (card) {
          card.classList.add('open', 'pinned');
          if (card.scrollIntoView) card.scrollIntoView({ block: 'center', behavior: 'smooth' });
          setTimeout(() => card.classList.remove('pinned'), 1600);
        }
      }
    });
  }

  /* ============================== MULTISIG =============================== */

  const MS_KEY = 'idleanvil-multisig-v1';

  function loadMs() {
    const saved = safe(() => JSON.parse(localStorage.getItem(MS_KEY)), null);
    state.ms = Object.assign({
      keys: [], m: 2, sort: 'entered', primary: 'p2wsh',
      internalKey: MULTISIG.NUMS, history: [], lastAddresses: {}, lastFlip: null
    }, saved || {});
    if (!state.ms.keys.length) state.ms.keys = MULTISIG.exampleKeys(3).map(hex => ({ raw: hex, enabled: true, useUncompressed: false }));
  }
  const saveMs = () => safe(() => localStorage.setItem(MS_KEY, JSON.stringify({
    keys: state.ms.keys, m: state.ms.m, sort: state.ms.sort,
    primary: state.ms.primary, internalKey: state.ms.internalKey
  })));

  /** Render a string with per-character change highlighting. */
  function diffHtml(before, after, cls = 'ch') {
    if (!after) return '';
    const d = MULTISIG.diffString(before, after);
    return d.chars.map(c => `<span class="${cls}${c.changed ? ' changed' : ''}">${esc(c.c)}</span>`).join('');
  }

  function renderMultisig(opts = {}) {
    const ms = state.ms;
    const built = MULTISIG.build({
      keys: ms.keys, m: ms.m, sort: ms.sort,
      network: state.tx.network, internalKey: ms.internalKey
    });
    state.msBuilt = built;

    /* ---- key rows (only rebuilt on structural change, to keep focus) ---- */
    if (!opts.keepRows) {
      $('#ms-keys').innerHTML = ms.keys.map((k, i) => {
        const a = built.keys[i];
        const pos = a.finalPosition;
        const moved = pos !== undefined && pos !== built.ordered.filter(x => x.index < a.index).length;
        return `
        <div class="keyrow ${k.enabled === false ? 'disabled' : ''}">
          <span class="kn">${i + 1}</span>
          <span class="kpos ${ms.sort === 'bip67' && pos !== undefined ? 'moved' : ''}"
                title="${pos !== undefined ? 'position ' + pos + ' in the script' : 'not in the script'}">${pos !== undefined ? '→' + pos : '·'}</span>
          <input type="text" class="mono ${a.raw && !a.valid ? 'err' : a.valid ? 'good' : ''}"
                 data-mskey="${i}" value="${esc(k.raw)}" spellcheck="false"
                 placeholder="02… / 03… / 04… / x-only">
          <span class="kstat ${a.valid ? 'ok' : a.raw ? 'bad' : ''}"
                title="${esc(a.error || '')}">${a.valid ? 'on curve' : a.raw ? (a.error || '').slice(0, 18) : '—'}</span>
          <span class="kform">${a.valid ? esc(a.usesUncompressed ? 'uncomp.' : a.form) : ''}</span>
          <button class="iconbtn" data-act="ms-toggle" data-i="${i}" title="${k.enabled === false ? 'include' : 'exclude'} this key">
            ${k.enabled === false ? ico('x', 13) : ico('check-circle', 13)}</button>
          <button class="iconbtn" data-act="ms-up" data-i="${i}" title="Move up" style="transform:rotate(180deg)">${ico('chevron', 13)}</button>
          <button class="iconbtn" data-act="ms-del" data-i="${i}" title="Remove">${ico('trash', 13)}</button>
        </div>`;
      }).join('') || '<div class="empty-note">No keys yet — add one, or load the examples.</div>';
    } else {
      /* live-update just the per-row status while the user types */
      ms.keys.forEach((k, i) => {
        const a = built.keys[i];
        const row = $(`[data-mskey="${i}"]`);
        if (!row) return;
        row.classList.toggle('err', !!(a.raw && !a.valid));
        row.classList.toggle('good', !!a.valid);
        const wrap = row.closest('.keyrow');
        const stat = wrap.querySelector('.kstat');
        stat.className = 'kstat ' + (a.valid ? 'ok' : a.raw ? 'bad' : '');
        stat.textContent = a.valid ? 'on curve' : a.raw ? (a.error || '').slice(0, 18) : '—';
        stat.title = a.error || '';
        wrap.querySelector('.kform').textContent = a.valid ? (a.usesUncompressed ? 'uncomp.' : a.form) : '';
        const pos = wrap.querySelector('.kpos');
        pos.textContent = a.finalPosition !== undefined ? '→' + a.finalPosition : '·';
      });
    }

    /* ---- policy ---- */
    $('#ms-m').textContent = built.m;
    $('#ms-n').textContent = built.n;
    const slider = $('#ms-mslider');
    slider.max = Math.max(1, built.n);
    slider.value = built.m;
    $('#nav-ms-count').textContent = built.n ? `${built.m}/${built.n}` : '0';
    const combos = combinations(built.n, built.m);
    const spare = built.n - built.m;
    $('#ms-policy-note').innerHTML = built.n
      ? `Any <strong>${built.m}</strong> of these <strong>${built.n}</strong> cosigner${built.n === 1 ? '' : 's'} can spend — ` +
        `<strong>${combos}</strong> distinct signing combination${combos === 1 ? '' : 's'}. ` +
        (spare > 0
          ? `You can lose <strong>${spare}</strong> key${spare === 1 ? '' : 's'} and still recover the funds.`
          : 'Every key is required, so losing any one of them loses the funds.')
      : 'Add public keys to define a policy.';
    $('#ms-sort-note').textContent = ms.sort === 'bip67'
      ? 'Keys are sorted lexicographically before going into the script, so every cosigner derives the same address regardless of the order they type them in (BIP67 / sortedmulti).'
      : 'The script keeps your order exactly. Every cosigner must use the same order to arrive at the same address.';
    $('#ms-internal').value = ms.internalKey;

    /* ---- variants ---- */
    $$('#ms-primary button').forEach(b => b.classList.toggle('on', b.dataset.v === ms.primary));
    const prev = ms.lastAddresses || {};
    const nowAddresses = {};

    $('#ms-variants').innerHTML = built.variants.map(v => {
      const addr = v.address || '';
      nowAddresses[v.id] = addr;
      const changed = prev[v.id] !== undefined && prev[v.id] !== addr;
      const body = addr
        ? `<div class="vaddr">${changed ? diffHtml(prev[v.id], addr) : esc(addr)}</div>`
        : `<div class="vaddr none">${esc(v.addressNote || 'no address for this form')}</div>`;
      const cost = v.spendVbytes ? `<span>spend ≈ <b>${v.spendVbytes} vB</b></span>` : '';
      return `
      <div class="msvar ${ms.primary === v.id ? 'primary' : ''} ${v.standard ? '' : 'bad'}"
           style="border-left-color:${TYPE_COLOR[v.id.toUpperCase()] || 'var(--accent)'}" data-act="ms-primary" data-v="${v.id}">
        <div class="vh">
          <span class="vname">${esc(v.label)}</span>
          <span class="vhint">${esc(v.hint)}</span>
          <div class="tools">
            <span class="tag ${v.standard ? 'green' : 'amber'}">${v.standard ? 'STANDARD' : 'NON-STANDARD'}</span>
          </div>
        </div>
        <div class="vb">
          ${body}
          <div class="vmeta">
            <span>output <b>${v.size} B</b></span>
            ${v.innerSize ? `<span>script <b>${v.innerSize} B</b></span>` : ''}
            ${cost}
          </div>
          <div class="vmeta"><span class="mutedc">${esc(v.spend)}</span></div>
          ${v.notes.map(nt => `<div class="vmeta"><span class="${v.standard ? 'mutedc' : 'amberc'}">${esc(nt)}</span></div>`).join('')}
        </div>
      </div>`;
    }).join('') || '<div class="empty-note">Nothing to build yet.</div>';

    /* ---- headline address + avalanche readout ---- */
    const primary = built.variants.find(v => v.id === ms.primary) || built.variants[0];
    const bigEl = $('#ms-address');
    const addrNow = primary && primary.address ? primary.address : '';
    const addrBefore = prev[ms.primary];

    if (addrNow) {
      bigEl.classList.remove('none');
      const d = MULTISIG.diffString(addrBefore, addrNow);
      bigEl.innerHTML = (addrBefore !== undefined && addrBefore !== addrNow)
        ? d.chars.map(c => `<span class="ch${c.changed ? ' changed' : ''}">${esc(c.c)}</span>`).join('')
        : addrNow.split('').map(c => `<span class="ch">${esc(c)}</span>`).join('');

      if (addrBefore !== undefined && addrBefore !== addrNow) {
        const pct = Math.round(d.changed / d.total * 100);
        $('#ms-avalanche').innerHTML = `
          <span><strong class="amberc">${d.changed}</strong> of ${d.total} characters changed</span>
          <div class="bar"><i style="width:${pct}%"></i></div>
          <span class="mono">${pct}%</span>
          ${d.lengthChanged ? '<span class="amberc">length changed too</span>' : ''}`;
      } else {
        $('#ms-avalanche').innerHTML = `<span class="mutedc">${addrNow.length} characters · ${esc(primary.label)} on ${esc(netOf().label)}</span>`;
      }
    } else {
      bigEl.className = 'addrbig none';
      bigEl.textContent = built.n ? (primary ? primary.addressNote : 'no address for this form') : 'add a public key to begin';
      $('#ms-avalanche').innerHTML = '';
    }

    /* ---- history trail ---- */
    if (addrNow && addrBefore !== undefined && addrBefore !== addrNow) {
      const d = MULTISIG.diffString(addrBefore, addrNow);
      ms.history.unshift({
        t: Date.now(), m: built.m, n: built.n, variant: ms.primary,
        address: addrNow, changed: d.changed, total: d.total, reason: opts.reason || 'edit'
      });
      ms.history = ms.history.slice(0, 14);
    }
    renderMsHistory();

    ms.lastAddresses = nowAddresses;

    /* ---- checks ---- */
    const rows = [];
    built.errors.forEach(e => rows.push(['red', 'ERROR', e]));
    built.warnings.forEach(e => rows.push(['amber', 'WARNING', e]));
    if (built.complete && !built.errors.length) {
      rows.push(['green', 'OK', `${built.m}-of-${built.n} is well formed on ${netOf().label}.`]);
      if (built.m === built.n) rows.push(['blue', 'NOTE', 'm equals n — losing any single key makes the funds unspendable.']);
      if (built.m === 1) rows.push(['amber', 'NOTE', '1-of-n means any single cosigner can spend alone.']);
      if (built.n > 15) rows.push(['blue', 'NOTE', `${built.n} keys exceeds what P2SH can hold; use P2WSH or taproot.`]);
    }
    $('#ms-checks').innerHTML = rows.length ? rows.map(([c, t, msg]) =>
      `<div class="vrow"><span class="tag ${c}">${t}</span><div class="vtxt"><div class="vt">${esc(msg)}</div></div></div>`).join('')
      : '<div class="vrow"><span class="tag grey">—</span><div class="vtxt">Nothing to report.</div></div>';

    /* ---- descriptor ---- */
    $('#ms-descriptor').value = (built.descriptors && built.descriptors[ms.primary]) || '';
    $('#btn-ms-undo').disabled = !ms.lastFlip;
    $('#btn-ms-node').disabled = !nc().connected || !addrNow;

    saveMs();
  }

  function combinations(n, k) {
    if (k > n || k < 0) return 0;
    let r = 1;
    for (let i = 1; i <= k; i++) r = r * (n - k + i) / i;
    return Math.round(r);
  }

  function renderMsHistory() {
    const h = state.ms.history || [];
    $('#ms-history').innerHTML = h.length ? h.map(e => `
      <div class="histrow" title="${esc(e.reason)} · ${new Date(e.t).toLocaleTimeString()}">
        <span class="hm">${e.m}-of-${e.n}</span>
        <span class="ha">${esc(shortHex(e.address, 14))}</span>
        <span class="hd ${e.changed / e.total > 0.5 ? 'big' : ''}">${e.changed}/${e.total}</span>
      </div>`).join('') : '<div class="empty-note">Edit something to start the trail.</div>';
  }

  function wireMultisig() {
    loadMs();

    const rebuild = (reason, keepRows) => renderMultisig({ reason, keepRows });

    $('#btn-ms-addkey').onclick = () => {
      state.ms.keys.push({ raw: '', enabled: true, useUncompressed: false });
      rebuild('added a key slot');
    };
    $('#btn-ms-example').onclick = () => {
      state.ms.keys = MULTISIG.exampleKeys(3).map(hex => ({ raw: hex, enabled: true, useUncompressed: false }));
      state.ms.m = 2;
      rebuild('loaded examples');
      toast('Loaded three valid secp256k1 points as example cosigners.');
    };
    $('#btn-ms-clear').onclick = () => {
      state.ms.keys = []; state.ms.history = [];
      rebuild('cleared');
    };
    $('#btn-ms-paste').onclick = () => {
      openModal('Paste public keys', `
        <div class="field"><label>One key per line — blank lines and commas are ignored</label>
          <textarea id="ms-paste-box" class="mono" rows="10" placeholder="02…&#10;03…&#10;02…"></textarea></div>
        <label class="check mt"><input type="checkbox" id="ms-paste-replace" checked> replace the current list</label>`,
        `<button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" id="ms-paste-go">Add</button>`);
      $('#ms-paste-go').onclick = () => {
        const lines = $('#ms-paste-box').value.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
        if (!lines.length) { toast('Nothing to add.', 'warn'); return; }
        const added = lines.map(raw => ({ raw: raw.toLowerCase(), enabled: true, useUncompressed: false }));
        state.ms.keys = $('#ms-paste-replace').checked ? added : state.ms.keys.concat(added);
        closeModal();
        rebuild(`pasted ${added.length} keys`);
        const bad = state.msBuilt.keys.filter(k => k.raw && !k.valid).length;
        toast(bad ? `Added ${added.length}; ${bad} did not validate.` : `Added ${added.length} keys.`);
      };
    };

    /* typing in a key field: live, without rebuilding the rows */
    $('#stage').addEventListener('input', (e) => {
      const f = e.target.closest('[data-mskey]');
      if (!f) return;
      state.ms.keys[Number(f.dataset.mskey)].raw = f.value.trim().toLowerCase();
      state.ms.lastFlip = null;
      rebuild('edited a key', true);
    });

    $('#ms-mslider').oninput = (e) => { state.ms.m = Number(e.target.value); rebuild('changed m', true); };
    $('#ms-internal').oninput = (e) => { state.ms.internalKey = e.target.value.trim(); rebuild('changed the internal key', true); };
    $('#btn-ms-nums').onclick = () => { state.ms.internalKey = MULTISIG.NUMS; rebuild('used the NUMS point'); };
    $('#ms-sort').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      state.ms.sort = b.dataset.v;
      $$('#ms-sort button').forEach(x => x.classList.toggle('on', x === b));
      rebuild('changed key order');
    });
    $('#ms-primary').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      state.ms.primary = b.dataset.v;
      rebuild('switched variant');
    });
    $('#btn-ms-copyaddr').onclick = () => {
      const v = (state.msBuilt.variants || []).find(x => x.id === state.ms.primary);
      if (v && v.address) copyText(v.address); else toast('No address for that variant.', 'warn');
    };
    $('#btn-ms-clearhist').onclick = () => { state.ms.history = []; renderMsHistory(); };

    /* the avalanche demo */
    $('#btn-ms-flip').onclick = () => {
      const candidates = state.ms.keys.map((k, i) => ({ k, i })).filter(x => x.k.enabled !== false && x.k.raw.length > 4);
      if (!candidates.length) { toast('Add a key first.', 'warn'); return; }
      const pick = candidates[Math.floor(Math.random() * candidates.length)];
      const r = MULTISIG.flipDigit(pick.k.raw);
      state.ms.lastFlip = { index: pick.i, previous: pick.k.raw, ...r };
      state.ms.keys[pick.i].raw = r.hex;
      rebuild(`flipped key ${pick.i + 1} digit ${r.position}: ${r.from}→${r.to}`);
      const valid = state.msBuilt.keys[pick.i].valid;
      toast(`Key ${pick.i + 1}, character ${r.position}: ${r.from} → ${r.to}. ` +
        (valid ? 'Still a valid point — look at the address.' : 'That is no longer on the curve.'));
    };
    $('#btn-ms-undo').onclick = () => {
      const f = state.ms.lastFlip;
      if (!f) return;
      state.ms.keys[f.index].raw = f.previous;
      state.ms.lastFlip = null;
      rebuild('undid the flip');
    };

    /* row actions */
    $('#stage').addEventListener('click', (e) => {
      const t = e.target.closest('[data-act^="ms-"]');
      if (!t) return;
      const i = Number(t.dataset.i);
      switch (t.dataset.act) {
        case 'ms-toggle':
          state.ms.keys[i].enabled = state.ms.keys[i].enabled === false;
          rebuild(state.ms.keys[i].enabled ? `included key ${i + 1}` : `excluded key ${i + 1}`);
          break;
        case 'ms-del':
          state.ms.keys.splice(i, 1);
          rebuild(`removed key ${i + 1}`);
          break;
        case 'ms-up':
          if (i > 0) { const a = state.ms.keys; [a[i - 1], a[i]] = [a[i], a[i - 1]]; rebuild('reordered keys'); }
          break;
        case 'ms-primary':
          state.ms.primary = t.dataset.v;
          rebuild('switched variant');
          break;
        case 'ms-to-output': msApply('output'); break;
        case 'ms-to-input': msApply('input'); break;
        case 'ms-to-lab': msApply('lab'); break;
        case 'ms-export': msExport(); break;
        case 'ms-check-node': msCheckNode(); break;
      }
    });
  }

  function msVariant() {
    const b = state.msBuilt;
    if (!b || !b.variants.length) { toast('Build a valid key set first.', 'warn'); return null; }
    const v = b.variants.find(x => x.id === state.ms.primary);
    if (!v) { toast('That variant is not available.', 'warn'); return null; }
    return v;
  }

  function msApply(where) {
    const v = msVariant();
    if (!v) return;
    const idx = parseInt($('#ms-target').value, 10) || 0;

    if (where === 'lab') {
      loadIntoScriptLab(v.witnessScript || v.redeemScript || v.tapLeaf || v.spk);
      return;
    }
    if (where === 'output') {
      const out = state.tx.outputs[idx];
      if (!out) { toast(`There is no output #${idx}.`, 'err'); return; }
      if (v.address) { out.mode = 'address'; out.address = v.address; }
      else { out.mode = 'raw'; out.rawAsm = S.toAsm(v.spk); }
      renderAll();
      toast(`Output #${idx} now pays the ${v.label} ${state.msBuilt.m}-of-${state.msBuilt.n}.`);
      return;
    }
    /* input */
    const inp = state.tx.inputs[idx];
    if (!inp) { toast(`There is no input #${idx}.`, 'err'); return; }
    inp.scriptPubKey = bytesToHex(v.spk);
    inp.redeemScript = v.redeemScript ? bytesToHex(v.redeemScript) : '';
    inp.witnessScript = v.witnessScript ? bytesToHex(v.witnessScript) : '';
    if (v.id === 'p2tr') {
      inp.algorithm = 'schnorr';
      inp.sighashType = 0;
      inp.taproot.internalKey = v.internalKey;
      inp.taproot.merkleRoot = bytesToHex(v.merkleRoot);
      inp.taproot.leafScript = bytesToHex(v.tapLeaf);
      inp.taproot.controlBlock = bytesToHex(v.controlBlock);
      inp.taproot.path = 'script';
    } else {
      inp.algorithm = 'ecdsa';
      inp.taproot.internalKey = '';
      inp.taproot.path = 'key';
    }
    /* pre-seed the signature slots so Finalize knows who must sign */
    inp.partialSigs = state.msBuilt.ordered.map(k => ({
      pubkey: v.id === 'p2tr' ? k.xonly : (k.usesUncompressed ? k.uncompressed : k.compressed),
      signature: ''
    }));
    renderAll();
    toast(`Input #${idx} set up to spend the ${v.label} ${state.msBuilt.m}-of-${state.msBuilt.n} — ${state.msBuilt.ordered.length} signature slots added.`);
  }

  function msExport() {
    const b = state.msBuilt;
    const v = msVariant();
    if (!v) return;
    const doc = {
      workbench: 'idleanvil/1.0',
      created: new Date().toISOString(),
      network: state.tx.network,
      policy: { m: b.m, n: b.n, keyOrder: b.sort, combinations: combinations(b.n, b.m) },
      cosigners: b.ordered.map((k, i) => ({
        position: i, compressed: k.compressed, xonly: k.xonly,
        hash160: k.hash160, form: k.form, enteredAt: k.index
      })),
      primary: v.id,
      variants: b.variants.map(x => ({
        type: x.id, address: x.address, scriptPubKey: bytesToHex(x.spk),
        redeemScript: x.redeemScript ? bytesToHex(x.redeemScript) : null,
        witnessScript: x.witnessScript ? bytesToHex(x.witnessScript) : null,
        tapLeaf: x.tapLeaf ? bytesToHex(x.tapLeaf) : null,
        controlBlock: x.controlBlock ? bytesToHex(x.controlBlock) : null,
        outputSize: x.size, spendVbytes: x.spendVbytes || null, standard: x.standard
      })),
      descriptors: b.descriptors,
      note: 'Public keys only. This document cannot spend anything; it describes where funds may be received.'
    };
    download(`multisig-${b.m}of${b.n}-${state.tx.network}.json`, JSON.stringify(doc, null, 2), 'application/json');
  }

  async function msCheckNode() {
    const v = msVariant();
    if (!v || !nc().connected) { toast('Connect a node first.', 'warn'); return; }
    const el = $('#ms-nodeout');
    el.innerHTML = '<div class="hint-text mt">checking…</div>';
    try {
      const [bal, utxos, hist] = await Promise.all([
        nc().getBalance(v.spk), nc().listUnspent(v.spk), nc().getHistory(v.spk).catch(() => [])
      ]);
      const total = utxos.reduce((a, u) => a + BigInt(u.value), 0n);
      el.innerHTML = `<dl class="kv mt">${kvRows([
        ['Address', v.address || '(no address form)'],
        ['Confirmed', `${groupNum(bal.confirmed)} sat`],
        ['Unconfirmed', `${groupNum(bal.unconfirmed)} sat`],
        ['UTXOs', `${utxos.length} (${groupNum(total)} sat)`],
        ['History', `${hist.length} transaction${hist.length === 1 ? '' : 's'}`]
      ])}</dl>${utxos.length ? `<button class="btn sm mt" data-act="utxo-add-all">Add all as inputs</button>` : ''}`;
      state.lastUtxos = utxos.map(u => ({ ...u, scriptPubKey: bytesToHex(v.spk) }));
    } catch (e) {
      el.innerHTML = `<div class="err-text mt">${esc(e.message)}</div>`;
    }
  }

  /* ================================ NODE ================================= */

  const NODE_KEY = 'idleanvil-node-v1';
  const nc = () => NODE.client;

  function loadNodeSettings() {
    const saved = safe(() => JSON.parse(localStorage.getItem(NODE_KEY)), null);
    state.node = Object.assign(
      { endpoints: Object.assign({}, NODE.DEFAULT_ENDPOINTS), autoconnect: false },
      saved || {});
    state.node.endpoints = Object.assign({}, NODE.DEFAULT_ENDPOINTS, state.node.endpoints);
  }
  const saveNodeSettings = () => safe(() => localStorage.setItem(NODE_KEY, JSON.stringify(state.node)));

  function renderNodeEndpoints() {
    const el = $('#node-endpoints');
    if (!el) return;
    el.innerHTML = Object.keys(NETWORKS).map(id => {
      const active = id === state.tx.network;
      return `<div class="leafrow" style="grid-template-columns:96px 1fr 78px">
        <span class="ln" style="${active ? '' : 'color:var(--muted);background:transparent;border-color:var(--line)'}">${esc(NETWORKS[id].label)}</span>
        <input type="text" class="mono" data-endpoint="${id}" value="${esc(state.node.endpoints[id] || '')}" placeholder="ws://host:port">
        <button class="btn sm" data-act="node-use" data-net="${id}">${active ? 'Connect' : 'Switch'}</button>
      </div>`;
    }).join('');
    $('#node-autoconnect').checked = !!state.node.autoconnect;
  }

  function renderNodeStatus() {
    const c = nc();
    const pill = $('#node-pill');
    const navState = $('#nav-node-state');
    const headerPill = $('#conn-pill');
    const st = c.status;

    if (pill) {
      pill.className = 'pill ' + (st === 'connected' ? 'ok' : '');
      pill.style.color = st === 'error' ? 'var(--red)' : '';
      pill.style.borderColor = st === 'error' ? 'var(--red)' : '';
      pill.textContent = st === 'connected' ? `CONNECTED · height ${groupNum(c.info.height || 0)}`
        : st === 'connecting' ? 'CONNECTING…' : st === 'error' ? 'CONNECTION FAILED' : 'DISCONNECTED';
    }
    if (navState) {
      navState.textContent = st === 'connected' ? 'live' : st === 'connecting' ? '…' : st === 'error' ? '!' : 'off';
      navState.style.background = st === 'connected' ? 'var(--green)' : st === 'error' ? 'var(--red)' : '';
      navState.style.color = st === 'connected' || st === 'error' ? '#04120f' : '';
    }
    if (headerPill) {
      const live = st === 'connected';
      headerPill.className = 'pill ' + (live ? 'ok' : '');
      headerPill.textContent = live
        ? `LIVE · ${netOf().short} · ${groupNum(c.info.height || 0)} · NO KEYS`
        : 'OFFLINE · NO KEYS';
      headerPill.title = live
        ? `Connected to ${c.url}. Chain lookups only — this page holds no private keys.`
        : 'This page is not contacting anything and holds no private keys.';
    }

    $$('#btn-node-connect').forEach(b => b.disabled = st === 'connecting');
    const live = st === 'connected';
    ['#btn-node-disconnect', '#btn-utxo-scan', '#btn-txfetch', '#btn-fee-refresh', '#btn-bc-check']
      .forEach(s => { const b = $(s); if (b) b.disabled = !live; });
    const send = $('#btn-bc-send');
    if (send) send.disabled = !live || !($('#bc-hex') || {}).value;

    const box = $('#node-status');
    if (box) {
      if (st === 'connected') {
        const mismatch = c.info.chainMismatch;
        box.innerHTML = mismatch
          ? `<div class="banner red">${ico('alert', 18)}<div><strong>Wrong chain.</strong> ${esc(mismatch)}.
               Switch the network selector or point at a different server before you use any of this data.</div></div>`
          : `<div class="ok-text">Connected to <span class="mono">${esc(c.url)}</span>${c.info.chainMatch ? ' — genesis hash matches ' + esc(netOf().label) : ''}.</div>`;
      } else if (st === 'error') {
        box.innerHTML = `<div class="err-text">${esc(state.nodeError || 'connection failed')}</div>`;
      } else box.innerHTML = '<div class="hint-text">Not connected.</div>';
    }

    const chain = $('#node-chain');
    if (chain) {
      chain.innerHTML = live ? kvRows([
        ['Endpoint', c.url],
        ['Server', c.info.serverName || c.info.version || '—'],
        ['Protocol', c.info.protocol || '—'],
        ['Height', groupNum(c.info.height || 0)],
        ['Genesis', c.info.genesis || '—'],
        ['Chain check', c.info.chainMatch === true ? `matches ${netOf().label}` : c.info.chainMatch === false ? 'MISMATCH' : 'not reported'],
        ['Pruning', c.info.pruning === undefined || c.info.pruning === null ? 'no' : String(c.info.pruning)]
      ]) : '<dt class="mutedc">—</dt><dd>not connected</dd>';
    }
    const banner = $('#node-banner');
    if (banner) banner.textContent = (live && c.info.banner) ? c.info.banner : '—';
  }

  function renderNodeLog() {
    const el = $('#node-log');
    if (!el) return;
    const c = nc();
    if (!c.log.length) { el.textContent = 'nothing yet'; return; }
    el.innerHTML = c.log.slice(-60).map(e => {
      const col = e.dir === 'out' ? 'var(--blue)' : e.dir === 'in' ? 'var(--accent)' : e.dir === 'err' ? 'var(--red)' : 'var(--muted)';
      const arrow = e.dir === 'out' ? '→' : e.dir === 'in' ? '←' : e.dir === 'err' ? '✕' : '·';
      const t = new Date(e.t).toISOString().slice(11, 19);
      return `<div><span class="mutedc">${t}</span> <span style="color:${col}">${arrow}</span> ${esc(e.text.slice(0, 300))}</div>`;
    }).join('');
    el.scrollTop = el.scrollHeight;
  }

  async function nodeConnect(networkId) {
    const target = networkId || state.tx.network;
    if (target !== state.tx.network) {
      state.tx.network = target;
      renderAll();
    }
    const url = state.node.endpoints[target];
    if (!url) { toast('No endpoint configured for that network.', 'warn'); return; }
    state.nodeError = null;
    renderNodeStatus();
    try {
      await nc().connect(url, target);
      toast(`Connected to ${url} — ${netOf().label} at height ${groupNum(nc().info.height)}.`);
      if (nc().info.chainMismatch) toast('Chain mismatch — see the Node workspace.', 'err');
      refreshFees();
    } catch (e) {
      state.nodeError = e.message;
      toast(e.message, 'err');
    }
    renderNodeStatus();
    renderNodeLog();
  }

  async function refreshFees() {
    const el = $('#fee-table');
    if (!el || !nc().connected) return;
    el.innerHTML = '<div class="empty-note">loading…</div>';
    try {
      const rows = await nc().feeTable();
      let relay = null;
      try { relay = await nc().relayFee(); } catch (e) {}
      el.innerHTML = `<table class="data">
        <thead><tr><th>Target</th><th class="num">sat/vB</th><th>Fee for this tx</th><th></th></tr></thead>
        <tbody>
        ${rows.map(r => {
          const m = TX.measure(state.tx);
          const fee = r.satPerVb ? Math.ceil(m.vsize * r.satPerVb) : null;
          return `<tr>
            <td class="k">${r.blocks} block${r.blocks === 1 ? '' : 's'}</td>
            <td class="num ${r.satPerVb ? 'accent' : 'mutedc'}">${r.satPerVb ? r.satPerVb.toFixed(2) : (r.error ? '⚠' : 'n/a')}</td>
            <td class="m">${fee !== null ? groupNum(fee) + ' sat' : '—'}</td>
            <td>${r.satPerVb ? `<button class="btn sm" data-act="use-rate" data-v="${r.satPerVb.toFixed(3)}">Use</button>` : ''}</td>
          </tr>`;
        }).join('')}
        ${relay !== null ? `<tr><td class="k">min relay</td><td class="num amberc">${relay.toFixed(3)}</td><td class="m">floor</td><td></td></tr>` : ''}
        </tbody></table>`;
    } catch (e) {
      el.innerHTML = `<div class="vrow"><span class="tag red">ERROR</span><div class="vtxt">${esc(e.message)}</div></div>`;
    }
  }

  async function scanUtxos() {
    const q = $('#utxo-query').value.trim();
    const sum = $('#utxo-summary'), list = $('#utxo-list');
    if (!q) return;
    let spk;
    try {
      spk = /^[0-9a-fA-F]+$/.test(q) && q.length % 2 === 0
        ? hexToBytes(q)
        : S.addressToScript(q, state.tx.network).script;
    } catch (e) { sum.innerHTML = `<div class="err-text">${esc(e.message)}</div>`; list.innerHTML = ''; return; }

    sum.innerHTML = '<div class="hint-text">scanning…</div>';
    list.innerHTML = '';
    try {
      const [utxos, bal] = await Promise.all([nc().listUnspent(spk), nc().getBalance(spk).catch(() => null)]);
      state.lastUtxos = utxos.map(u => ({ ...u, scriptPubKey: bytesToHex(spk) }));
      const total = utxos.reduce((a, u) => a + BigInt(u.value), 0n);
      sum.innerHTML = `<div class="pairs">
        <div class="p"><div class="pk">Script type</div><div class="pv">${esc(S.classify(spk).type)}</div></div>
        <div class="p"><div class="pk">UTXOs</div><div class="pv">${utxos.length}</div></div>
        <div class="p"><div class="pk">Spendable</div><div class="pv">${fmtSat(total)}</div></div>
        ${bal ? `<div class="p"><div class="pk">Unconfirmed</div><div class="pv">${fmtSat(bal.unconfirmed || 0)}</div></div>` : ''}
      </div>`;
      list.innerHTML = utxos.length ? `
        <div class="flexrow mt mb"><button class="btn sm" data-act="utxo-add-all">Add all ${utxos.length} as inputs</button></div>
        <div class="tbl-wrap"><table class="data">
        <thead><tr><th>Outpoint</th><th class="num">Value</th><th class="num">Height</th><th></th></tr></thead>
        <tbody>${utxos.map((u, i) => `<tr>
          <td class="m">${esc(shortHex(u.tx_hash, 10))}:${u.tx_pos}</td>
          <td class="num">${groupNum(u.value)}</td>
          <td class="num ${u.height ? '' : 'amberc'}">${u.height || 'mempool'}</td>
          <td><button class="btn sm" data-act="utxo-add" data-i="${i}">Add as input</button></td>
        </tr>`).join('')}</tbody></table></div>` : '<div class="empty-note">No unspent outputs for that script.</div>';
    } catch (e) {
      sum.innerHTML = `<div class="err-text">${esc(e.message)}</div>`;
    }
  }

  /** Turn a fetched prevout into a workbench input. */
  function addPrevoutAsInput(p) {
    const inp = TX.newInput();
    inp.txid = p.txid;
    inp.vout = p.vout;
    inp.amount = BigInt(p.amount);
    inp.scriptPubKey = p.scriptPubKey;
    if (p.prevTxHex) inp.prevTxHex = p.prevTxHex;
    if (p.scriptType === 'P2TR') { inp.algorithm = 'schnorr'; inp.sighashType = 0; }
    /* replace a pristine placeholder input rather than piling up next to it */
    const first = state.tx.inputs[0];
    if (state.tx.inputs.length === 1 && !first.txid && !first.scriptPubKey) state.tx.inputs[0] = inp;
    else state.tx.inputs.push(inp);
    renderAll();
  }

  async function fetchTx() {
    const txid = $('#txfetch-id').value.trim();
    const out = $('#txfetch-out');
    if (!/^[0-9a-fA-F]{64}$/.test(txid)) { out.innerHTML = '<div class="err-text">A txid is 64 hex characters.</div>'; return; }
    out.innerHTML = '<div class="hint-text">fetching…</div>';
    try {
      const raw = await nc().getTransaction(txid);
      const dec = TX.decodeRaw(raw);
      state.lastFetchedTx = { raw, dec };
      $('#btn-txfetch-input').disabled = false;
      $('#btn-txfetch-inspect').disabled = false;
      out.innerHTML = `
        <dl class="kv">${kvRows([
          ['TXID', dec.txid],
          ['Matches request', dec.txid === txid.toLowerCase() ? 'yes' : 'NO — server returned a different transaction'],
          ['Version', String(dec.version)],
          ['SegWit', dec.segwit ? 'yes' : 'no'],
          ['Inputs / Outputs', `${dec.inputs.length} / ${dec.outputs.length}`],
          ['Size / vSize', `${dec.size} B / ${dec.vsize} vB`],
          ['Output total', `${groupNum(dec.outTotal)} sat`],
          ['nLockTime', String(dec.locktime)]
        ])}</dl>
        <div class="subhead mt">Outputs</div>
        <div class="tbl-wrap"><table class="data">
          <thead><tr><th>#</th><th class="num">Value</th><th>Type</th><th>Address / script</th><th></th></tr></thead>
          <tbody>${dec.outputs.map((o, i) => {
            const spk = hexToBytes(o.script);
            const cls = S.classify(spk);
            const addr = S.scriptToAddress(spk, state.tx.network);
            return `<tr>
              <td class="m">${i}</td>
              <td class="num">${groupNum(o.amount)}</td>
              <td class="m" style="color:${TYPE_COLOR[cls.type] || 'var(--muted)'}">${cls.type}</td>
              <td class="m brk">${esc(addr || shortHex(o.script, 14))}</td>
              <td><button class="btn sm" data-act="fetched-out" data-i="${i}">Spend this</button></td>
            </tr>`;
          }).join('')}</tbody></table></div>`;
    } catch (e) {
      out.innerHTML = `<div class="err-text">${esc(e.message)}</div>`;
      $('#btn-txfetch-input').disabled = true;
      $('#btn-txfetch-inspect').disabled = true;
    }
  }

  /* ---------------------------- broadcasting ---------------------------- */

  function checkBroadcast() {
    const hex = $('#bc-hex').value.trim();
    const out = $('#bc-out');
    if (!hex) { out.innerHTML = '<div class="hint-text">Nothing to check.</div>'; return null; }
    try {
      const dec = TX.decodeRaw(hex);
      const unsigned = dec.inputs.every(i => !i.scriptSig && !i.witness.length);
      const partly = dec.inputs.some(i => !i.scriptSig && !i.witness.length);
      out.innerHTML = `
        <dl class="kv mt">${kvRows([
          ['TXID (once mined)', dec.txid],
          ['WTXID', dec.wtxid],
          ['Size / vSize / weight', `${dec.size} B / ${dec.vsize} vB / ${dec.weight} WU`],
          ['Inputs / Outputs', `${dec.inputs.length} / ${dec.outputs.length}`],
          ['Output total', `${groupNum(dec.outTotal)} sat`],
          ['Network', netOf().label]
        ])}</dl>
        ${unsigned ? `<div class="banner red mt">${ico('alert', 18)}<div><strong>Every input is unsigned.</strong> This will be rejected.</div></div>`
          : partly ? `<div class="banner mt">${ico('alert', 18)}<div>Some inputs have no unlocking data — the node will very likely reject this.</div></div>`
          : `<div class="ok-text mt">All ${dec.inputs.length} inputs carry unlocking data.</div>`}`;
      $('#btn-bc-send').disabled = !nc().connected;
      return dec;
    } catch (e) {
      out.innerHTML = `<div class="err-text">${esc(e.message)}</div>`;
      $('#btn-bc-send').disabled = true;
      return null;
    }
  }

  function confirmBroadcast() {
    const hex = $('#bc-hex').value.trim();
    if (!hex) { toast('Nothing to broadcast.', 'warn'); return; }
    let dec;
    try { dec = TX.decodeRaw(hex); } catch (e) { toast(e.message, 'err'); return; }

    const isMain = state.tx.network === 'mainnet';
    const outs = dec.outputs.map((o, i) => {
      const spk = hexToBytes(o.script);
      const addr = S.scriptToAddress(spk, state.tx.network);
      return `<tr><td class="m">${i}</td><td class="num">${groupNum(o.amount)} sat</td>
        <td class="m brk">${esc(addr || S.classify(spk).type + ' ' + shortHex(o.script, 12))}</td></tr>`;
    }).join('');

    openModal(`Broadcast to ${netOf().label}?`, `
      <div class="banner ${isMain ? 'red' : ''}">
        ${ico('alert', 18)}
        <div>${isMain
          ? '<strong>This is mainnet.</strong> Real funds move and nothing can be undone.'
          : `This publishes to <strong>${esc(netOf().label)}</strong> via <span class="mono">${esc(nc().url)}</span>. It cannot be recalled.`}</div>
      </div>
      <dl class="kv mt">${kvRows([
        ['TXID', dec.txid],
        ['Size / vSize', `${dec.size} B / ${dec.vsize} vB`],
        ['Inputs', String(dec.inputs.length)],
        ['Output total', `${groupNum(dec.outTotal)} sat`],
        ['Endpoint', nc().url]
      ])}</dl>
      <div class="subhead mt-lg">Where the money goes</div>
      <div class="tbl-wrap"><table class="data"><thead><tr><th>#</th><th class="num">Value</th><th>Destination</th></tr></thead>
        <tbody>${outs}</tbody></table></div>
      ${isMain ? `<div class="field mt-lg"><label class="redc">Type BROADCAST to confirm</label>
        <input type="text" id="bc-confirm-text" class="mono" placeholder="BROADCAST" autocomplete="off"></div>` : ''}
      <div class="subhead mt-lg">Raw</div>
      <div class="code">${esc(hex)}</div>`,
      `<button class="btn" data-act="modal-close">Cancel</button>
       <button class="btn danger" id="btn-bc-really" style="border-color:var(--red)">Broadcast now</button>`);

    $('#btn-bc-really').onclick = async () => {
      if (isMain) {
        const typed = ($('#bc-confirm-text') || {}).value || '';
        if (typed.trim().toUpperCase() !== 'BROADCAST') { toast('Type BROADCAST to confirm.', 'warn'); return; }
      }
      const btn = $('#btn-bc-really');
      btn.disabled = true; btn.textContent = 'sending…';
      try {
        const txid = await nc().broadcast(hex);
        closeModal();
        $('#bc-out').innerHTML = `<div class="banner blue mt" style="border-color:var(--green);background:var(--green-bg)">
          ${ico('check-circle', 18)}<div><strong>Accepted.</strong> The node returned txid
          <span class="mono brk">${esc(txid)}</span>${txid !== dec.txid ? ' — note this differs from the locally computed txid.' : '.'}</div></div>`;
        toast(`Broadcast accepted: ${String(txid).slice(0, 16)}…`);
      } catch (e) {
        btn.disabled = false; btn.textContent = 'Broadcast now';
        $('#modal-body').insertAdjacentHTML('afterbegin',
          `<div class="banner red">${ico('alert', 18)}<div><strong>Rejected.</strong> ${esc(e.message)}</div></div>`);
      }
      renderNodeLog();
    };
  }

  /* ------------------------------ node wiring --------------------------- */

  function renderNode() {
    renderNodeEndpoints();
    renderNodeStatus();
    renderNodeLog();
  }

  function wireNode() {
    loadNodeSettings();

    nc().on('status', () => { renderNodeStatus(); });
    nc().on('log', () => { if (state.ws === 'node') renderNodeLog(); });
    nc().on('header', (h) => {
      renderNodeStatus();
      toast(`New block — height ${groupNum(h.height)}.`);
    });

    $('#btn-node-connect').onclick = () => nodeConnect();
    $('#btn-node-disconnect').onclick = () => { nc().disconnect(); toast('Disconnected.'); renderNodeStatus(); };
    $('#btn-node-reset').onclick = () => {
      state.node.endpoints = Object.assign({}, NODE.DEFAULT_ENDPOINTS);
      saveNodeSettings(); renderNodeEndpoints(); toast('Endpoints reset.');
    };
    $('#btn-node-refresh').onclick = async () => {
      if (!nc().connected) return;
      try { await nc().getHeight(); renderNodeStatus(); toast(`Height ${groupNum(nc().info.height)}.`); }
      catch (e) { toast(e.message, 'err'); }
    };
    $('#btn-node-clearlog').onclick = () => { nc().log.length = 0; renderNodeLog(); };
    $('#node-autoconnect').onchange = (e) => { state.node.autoconnect = e.target.checked; saveNodeSettings(); };
    $('#btn-fee-refresh').onclick = refreshFees;
    $('#btn-utxo-scan').onclick = scanUtxos;
    $('#btn-txfetch').onclick = fetchTx;
    $('#btn-txfetch-inspect').onclick = () => {
      if (!state.lastFetchedTx) return;
      state.inspectSrc = 'paste';
      $$('#inspect-src button').forEach(x => x.classList.toggle('on', x.dataset.s === 'paste'));
      $('#inspect-paste-wrap').classList.remove('hidden');
      $('#inspect-hex').value = state.lastFetchedTx.raw;
      showWorkspace('inspector');
      runInspector();
    };
    $('#btn-txfetch-input').onclick = () => {
      if (!state.lastFetchedTx) return;
      const vout = parseInt($('#txfetch-vout').value, 10) || 0;
      const o = state.lastFetchedTx.dec.outputs[vout];
      if (!o) { toast(`That transaction has no output ${vout}.`, 'err'); return; }
      addPrevoutAsInput({
        txid: state.lastFetchedTx.dec.txid, vout, amount: o.amount,
        scriptPubKey: o.script, prevTxHex: state.lastFetchedTx.raw,
        scriptType: S.classify(hexToBytes(o.script)).type
      });
      toast(`Added ${shortHex(state.lastFetchedTx.dec.txid, 8)}:${vout} — ${groupNum(o.amount)} sat.`);
    };
    $('#btn-bc-load').onclick = () => {
      $('#bc-hex').value = bytesToHex(TX.serialize(state.tx, { final: true }));
      checkBroadcast();
    };
    $('#btn-bc-check').onclick = checkBroadcast;
    $('#btn-bc-send').onclick = confirmBroadcast;
    $('#bc-hex').oninput = () => { $('#btn-bc-send').disabled = !nc().connected || !$('#bc-hex').value.trim(); };

    /* delegated: endpoint edits, per-row actions */
    $('#stage').addEventListener('input', (e) => {
      const ep = e.target.closest('[data-endpoint]');
      if (!ep) return;
      state.node.endpoints[ep.dataset.endpoint] = ep.value.trim();
      saveNodeSettings();
    });
    $('#stage').addEventListener('click', (e) => {
      const use = e.target.closest('[data-act="node-use"]');
      if (use) { nodeConnect(use.dataset.net); return; }

      const rate = e.target.closest('[data-act="use-rate"]');
      if (rate) {
        state.tx.feeRate = parseFloat(rate.dataset.v);
        $('#f-feerate').value = state.tx.feeRate;
        update();
        toast(`Fee rate set to ${state.tx.feeRate} sat/vB.`);
        return;
      }
      const add = e.target.closest('[data-act="utxo-add"]');
      if (add && state.lastUtxos) {
        const u = state.lastUtxos[Number(add.dataset.i)];
        addPrevoutAsInput({ txid: u.tx_hash, vout: u.tx_pos, amount: u.value, scriptPubKey: u.scriptPubKey,
          scriptType: S.classify(hexToBytes(u.scriptPubKey)).type });
        toast(`Added ${shortHex(u.tx_hash, 8)}:${u.tx_pos} — ${groupNum(u.value)} sat.`);
        return;
      }
      const all = e.target.closest('[data-act="utxo-add-all"]');
      if (all && state.lastUtxos) {
        for (const u of state.lastUtxos) {
          addPrevoutAsInput({ txid: u.tx_hash, vout: u.tx_pos, amount: u.value, scriptPubKey: u.scriptPubKey,
            scriptType: S.classify(hexToBytes(u.scriptPubKey)).type });
        }
        toast(`Added ${state.lastUtxos.length} inputs.`);
        return;
      }
      const fo = e.target.closest('[data-act="fetched-out"]');
      if (fo && state.lastFetchedTx) {
        const i = Number(fo.dataset.i);
        const o = state.lastFetchedTx.dec.outputs[i];
        addPrevoutAsInput({ txid: state.lastFetchedTx.dec.txid, vout: i, amount: o.amount,
          scriptPubKey: o.script, prevTxHex: state.lastFetchedTx.raw,
          scriptType: S.classify(hexToBytes(o.script)).type });
        toast(`Added output ${i} as an input.`);
      }
    });

    /* per-input "fetch prevout" button */
    $('#stage').addEventListener('click', async (e) => {
      const b = e.target.closest('[data-act="fetch-prevout"]');
      if (!b) return;
      const i = Number(b.dataset.idx);
      const inp = state.tx.inputs[i];
      if (!nc().connected) { toast('Connect to a node first (Node workspace).', 'warn'); return; }
      if (!/^[0-9a-fA-F]{64}$/.test(inp.txid || '')) { toast('Set a valid previous TXID first.', 'warn'); return; }
      b.disabled = true;
      try {
        const p = await nc().fetchPrevout(inp.txid, inp.vout);
        inp.amount = BigInt(p.amount);
        inp.scriptPubKey = p.scriptPubKey;
        inp.prevTxHex = p.prevTxHex;
        if (p.scriptType === 'P2TR') { inp.algorithm = 'schnorr'; if (inp.sighashType === 1) inp.sighashType = 0; }
        renderAll();
        toast(`Input #${i}: ${p.scriptType}, ${groupNum(p.amount)} sat.`);
      } catch (err) { toast(err.message, 'err'); b.disabled = false; }
    });

    renderNode();
    if (state.node.autoconnect) setTimeout(() => nodeConnect(), 300);
  }

  /* ================================ DOCK ================================= */

  function updateDock() {
    const tx = state.tx;
    const m = TX.measure(tx);
    $('#d-size').textContent = m.total + ' B';
    $('#d-vsize').textContent = m.vsize + ' vB';
    $('#d-weight').textContent = m.weight + ' WU';
    $('#d-nin').textContent = tx.inputs.length;
    $('#d-nout').textContent = tx.outputs.length;
    $('#d-intotal').textContent = groupNum(m.inTotal);
    $('#d-outtotal').textContent = groupNum(m.outTotal);
    const feeEl = $('#d-fee'), rateEl = $('#d-rate');
    feeEl.textContent = groupNum(m.fee);
    feeEl.className = 'v ' + (m.fee < 0n ? 'red' : m.fee === 0n ? 'amber' : 'accent');
    rateEl.textContent = m.feeRate.toFixed(2);
    rateEl.className = 'v ' + (m.feeRate < 1 ? 'amber' : 'accent');

    const hex = bytesToHex(TX.serialize(tx, { final: false }));
    const hexEl = $('#dock-hex');
    hexEl.textContent = hex || '—';
    hexEl.classList.toggle('empty', !hex);
    $('#dock-txid').textContent = 'candidate txid ' + shortHex(TX.txid(tx, false), 8);

    let psbtB64 = '';
    try { psbtB64 = bytesToBase64(PSBT.build(tx, tx.psbtVersion)); } catch (e) { psbtB64 = '⚠ ' + e.message; }
    const pEl = $('#dock-psbt');
    pEl.textContent = psbtB64 || '—';
    pEl.classList.toggle('empty', !psbtB64);
    $('#dock-psbt-ver').textContent = `v${tx.psbtVersion}`;

    const res = VALIDATE.run(tx);
    const status = $('#d-status');
    const label = res.worst === 'invalid' ? 'INVALID' : res.worst === 'nonstandard' ? 'NON-STANDARD' : res.worst === 'unknown' ? 'INCOMPLETE' : 'VALID';
    status.textContent = label;
    status.className = 'v ' + (res.worst === 'invalid' ? 'red' : res.worst === 'valid' ? 'accent' : 'amber');
    $('#nav-val-count').textContent = res.counts.invalid + res.counts.nonstandard + res.counts.unknown;

    const top = res.rows.filter(r => r.sev !== 'valid').slice(0, 6);
    $('#dock-val').innerHTML = top.length
      ? top.map(r => `<div><span class="${r.sev === 'invalid' ? 'redc' : r.sev === 'info' ? 'bluec' : 'amberc'}">${r.sev === 'invalid' ? '✕' : r.sev === 'info' ? 'i' : '!'}</span> ${esc(r.title)}</div>`).join('')
      : '<span class="greenc">No issues — structurally sound and standard.</span>';

    $('#nav-in-count').textContent = tx.inputs.length;
    $('#nav-out-count').textContent = tx.outputs.length;
    $('#side-network').textContent = netOf().label.toUpperCase();
    $('#side-dot').className = 'dot ' + (tx.network === 'mainnet' ? 'amber' : tx.network === 'regtest' ? 'blue' : '');
    $('#side-note').textContent = tx.network === 'mainnet' ? 'real funds — be careful' : 'test network';

    $('#lt-hex').textContent = '0x' + (tx.locktime >>> 0).toString(16).padStart(8, '0');
    $('#f-locktime-desc').value = TX.describeLocktime(tx.locktime);
    $('#locktime-note').textContent = TX.describeLocktime(tx.locktime);

    $('#tx-glance').innerHTML = kvRows([
      ['Network', netOf().label], ['Version', String(tx.version)],
      ['Serialization', tx.serialization === 'auto' ? (TX.hasWitness(tx) ? 'automatic → segwit' : 'automatic → legacy') : tx.serialization],
      ['Inputs / Outputs', `${tx.inputs.length} / ${tx.outputs.length}`],
      ['Weight', `${m.weight} WU (${m.vsize} vB)`],
      ['Input total', `${groupNum(m.inTotal)} sat`],
      ['Output total', `${groupNum(m.outTotal)} sat`],
      ['Fee', `${groupNum(m.fee)} sat @ ${m.feeRate.toFixed(2)} sat/vB`],
      ['Candidate txid', TX.txid(tx, false)],
      ['Estimate basis', m.estimated ? 'standard-spend estimate (unsigned)' : 'actual']
    ]);
  }

  /* ====================== ribbon / pipeline / flow ======================= */

  const NET_BLURB = {
    mainnet:  ['mainnet', 'Real funds. Every address, script and amount here is live — verify independently before you broadcast.'],
    testnet3: ['test',    'Testnet3 coins have no value. Faucet-funded and frequently reorganised.'],
    testnet4: ['test',    'Testnet4 (BIP94) — the current test chain, with the difficulty-reset rules fixed.'],
    signet:   ['signet',  'Signet blocks are signed by a trusted authority, so the chain stays stable and predictable.'],
    regtest:  ['regtest', 'Your own private chain. Mine instantly with generatetoaddress and reset whenever you like.']
  };

  function renderRibbon() {
    const n = netOf();
    const [kind, blurb] = NET_BLURB[n.id] || NET_BLURB.mainnet;
    const el = $('#net-ribbon');
    if (!el) return;
    el.className = `ribbon ${kind}`;
    el.innerHTML = `${ico(n.id === 'mainnet' ? 'alert' : 'globe', 16)}
      <strong>${esc(n.label)}</strong>
      <span class="body">${esc(blurb)}</span>
      <span class="sp"></span>
      <span class="tag ${n.id === 'mainnet' ? 'amber' : 'grey'}">${esc(n.hrp)}1… · P2PKH 0x${n.p2pkh.toString(16).padStart(2, '0')} · P2SH 0x${n.p2sh.toString(16).padStart(2, '0')}</span>`;
  }

  /** construct → sign → finalize progress, derived from actual state. */
  function renderPipeline() {
    const tx = state.tx;
    const hasOutpoints = tx.inputs.every(i => /^[0-9a-f]{64}$/i.test(i.txid || ''));
    const hasPrevouts = tx.inputs.every(i => i.scriptPubKey && BigInt(i.amount || 0) > 0n);
    const hasOutputs = tx.outputs.some(o => (TX.resolveOutput(o, tx.network).script || []).length);
    const sigCount = tx.inputs.reduce((a, i) =>
      a + (i.partialSigs || []).filter(s => s.signature).length + (i.tapKeySig ? 1 : 0) + (i.tapScriptSigs || []).length, 0);
    const assembled = tx.inputs.every(i => i.scriptSig || (i.witness || []).length);

    const steps = [
      ['Outpoints', hasOutpoints, 'inputs'],
      ['Prevout data', hasPrevouts, 'inputs'],
      ['Outputs', hasOutputs, 'outputs'],
      ['Signing data', hasPrevouts && hasOutputs, 'signing'],
      ['Signatures', sigCount > 0, 'finalize'],
      ['Assembled', assembled, 'finalize']
    ];
    const firstUndone = steps.findIndex(s => !s[1]);
    const el = $('#pipeline');
    if (!el) return;
    el.innerHTML = steps.map(([label, done, ws], i) =>
      `<div class="pstep ${done ? 'done' : i === firstUndone ? 'now' : ''}" data-goto="${ws}" title="${done ? 'complete' : 'still to do'}">
        <span class="pn">${done ? '✓' : i + 1}</span>${esc(label)}</div>`).join('');
  }

  const TYPE_COLOR = {
    P2PKH: 'var(--blue)', P2SH: 'var(--amber)', P2WPKH: 'var(--accent)', P2WSH: 'var(--green)',
    P2TR: 'var(--violet)', P2PK: 'var(--blue)', MULTISIG: 'var(--green)', OP_RETURN: 'var(--pink)',
    NONSTANDARD: 'var(--red)', WITNESS_UNKNOWN: 'var(--red)', EMPTY: 'var(--faint)'
  };

  function renderFlow() {
    const el = $('#tx-flow');
    if (!el) return;
    const tx = state.tx;
    const m = TX.measure(tx);
    const maxIn = tx.inputs.reduce((a, i) => a > BigInt(i.amount || 0) ? a : BigInt(i.amount || 0), 1n);
    const maxOut = tx.outputs.reduce((a, o) => a > BigInt(o.amount || 0) ? a : BigInt(o.amount || 0), 1n);
    const scale = maxIn > maxOut ? maxIn : maxOut;

    const item = (side, idx, type, amount, label, dust) => {
      const c = TYPE_COLOR[type] || 'var(--muted)';
      const pct = scale > 0n ? Number(BigInt(amount || 0) * 100n / scale) : 0;
      return `<div class="flow-item" style="border-left-color:${c}" data-goto="${side}" data-focus="${idx}">
        <div class="t1"><span class="n">#${idx}</span>
          <span class="ty" style="color:${c}">${esc(type)}</span>
          <span style="margin-left:auto">${fmtSat(amount, { dustLimit: dust })}</span></div>
        <div class="t2">${esc(label || '—')}</div>
        <div class="bar"><i style="width:${pct}%;background:${c}"></i></div>
      </div>`;
    };

    const ins = tx.inputs.map((inp, i) => {
      const spk = safe(() => hexToBytes(inp.scriptPubKey), null);
      const type = spk && spk.length ? S.classify(spk).type : 'EMPTY';
      return item('inputs', i, type, inp.amount, inp.txid ? shortHex(inp.txid, 7) + ':' + inp.vout : 'no outpoint');
    }).join('') || '<div class="empty-note">no inputs</div>';

    const outs = tx.outputs.map((o, i) => {
      const r = TX.resolveOutput(o, tx.network);
      const type = r.script && r.script.length ? S.classify(r.script).type : 'EMPTY';
      const dust = r.script && r.script.length ? VALIDATE.dustThreshold(r.script) : 0n;
      const label = o.mode === 'address' ? (o.address || 'no address')
        : o.mode === 'opreturn' ? `data: ${(o.opret.payload || '').slice(0, 28) || '(empty)'}`
        : (r.error ? '⚠ ' + r.error : shortHex(bytesToHex(r.script), 12));
      return item('outputs', i, type, o.amount, label, dust);
    }).join('') || '<div class="empty-note">no outputs</div>';

    const feeCls = m.fee < 0n ? 'redc' : m.fee === 0n ? 'amberc' : 'accent';
    el.innerHTML = `
      <div class="flow">
        <div class="flow-col">
          <div class="h"><span>Inputs (${tx.inputs.length})</span><span>${groupNum(m.inTotal)} sat</span></div>
          ${ins}
        </div>
        <div class="flow-arrow">${ico('arrow-right', 22)}</div>
        <div class="flow-col">
          <div class="h"><span>Outputs (${tx.outputs.length})</span><span>${groupNum(m.outTotal)} sat</span></div>
          ${outs}
        </div>
        <div class="flow-fee">
          <span>Miner fee — the difference the transaction leaves behind</span>
          <span class="${feeCls}">${fmtSat(m.fee)} &nbsp;·&nbsp; ${m.feeRate.toFixed(2)} sat/vB${m.estimated ? ' (estimated)' : ''}</span>
        </div>
      </div>`;
  }

  function renderTiles() {
    const el = $('#tx-tiles');
    if (!el) return;
    const m = TX.measure(state.tx);
    const res = VALIDATE.run(state.tx);
    const witFrac = m.total ? m.witBytes / m.total : 0;
    const baseFrac = m.total ? (m.total - m.witBytes) / m.total : 1;
    const budget = Math.min(1, m.weight / 400000);
    const statusCls = res.worst === 'invalid' ? 'red' : res.worst === 'valid' ? 'accent' : 'amber';

    el.innerHTML = `
      <div class="tiles">
        ${tile('vSize', `${m.vsize}<span style="font-size:12px;color:var(--muted)"> vB</span>`,
          meter([['base', baseFrac], ['wit', witFrac]]) + `<span class="small">${m.total - m.witBytes} B base + ${m.witBytes} B witness</span>`, 'blue')}
        ${tile('Weight', `${groupNum(m.weight)}`,
          meter([[budget > .9 ? 'bad' : budget > .5 ? 'warn' : 'ok', budget]]) + `<span class="small">${(budget * 100).toFixed(1)}% of the 400k standardness budget</span>`, 'violet')}
        ${tile('Fee', groupNum(m.fee), `${m.feeRate.toFixed(2)} sat/vB${m.estimated ? ' · estimated' : ''}`,
          m.fee < 0n ? 'red' : m.fee === 0n ? 'amber' : 'accent')}
        ${tile('Segwit saving', m.segwit ? `${Math.round((1 - m.vsize / m.total) * 100)}%` : '—',
          m.segwit ? 'witness data is discounted 4×' : 'legacy serialization', 'accent')}
        ${tile('Findings', String(res.counts.invalid + res.counts.nonstandard + res.counts.unknown),
          `${res.counts.invalid} invalid · ${res.counts.nonstandard} non-standard`, statusCls)}
      </div>`;
  }

  /* ============================ update cycle ============================= */

  let updateTimer = null;
  function update() {
    refreshInputCards();
    refreshOutputCards();
    updateDock();
    renderRibbon();
    renderPipeline();
    if (state.ws === 'transaction') { renderFlow(); renderTiles(); }
    if (state.ws === 'validation') renderValidation();
    if (state.ws === 'psbt') renderPsbt();
    clearTimeout(updateTimer);
    updateTimer = setTimeout(persist, 400);
  }

  function renderAll() {
    bindHeader();
    renderForensicControls();
    renderInputs();
    renderOutputs();
    renderScriptLab();
    renderFlow();
    renderTiles();
    if (state.ws === 'signing') renderSigning();
    if (state.ws === 'psbt') renderPsbt();
    if (state.ws === 'finalize') renderFinalize();
    if (state.ws === 'validation') renderValidation();
    if (state.ws === 'inspector') runInspector();
    if (state.ws === 'toolkit') renderToolkit();
    if (state.ws === 'multisig') renderMultisig({ reason: 'network or transaction changed' });
    if (state.ws === 'node') renderNode();
    else renderNodeEndpoints();
    renderNodeStatus();
    update();
  }

  /* ============================== actions ================================ */

  const ACTIONS = {
    'toggle-card': (el) => {
      const card = el.closest('.card');
      card.classList.toggle('open');
      const idx = Number(card.dataset.idx);
      const coll = !card.classList.contains('open');
      if (card.dataset.card === 'in') state.tx.inputs[idx].collapsed = coll;
      else state.tx.outputs[idx].collapsed = coll;
    },
    'del-input': (el) => {
      const i = Number(el.dataset.idx);
      if (state.tx.inputs.length <= 1) { toast('Keep at least one input — clear its fields instead.', 'warn'); return; }
      state.tx.inputs.splice(i, 1); renderInputs(); update();
    },
    'dup-input': (el) => {
      const i = Number(el.dataset.idx);
      const copy = JSON.parse(JSON.stringify(state.tx.inputs[i], (k, v) => typeof v === 'bigint' ? v.toString() : v));
      copy.amount = BigInt(copy.amount || 0);
      copy.id = 'i' + Math.random().toString(36).slice(2, 9);
      state.tx.inputs.splice(i + 1, 0, copy); renderInputs(); update();
    },
    'move-input-up': (el) => {
      const i = Number(el.dataset.idx);
      if (i === 0) return;
      const a = state.tx.inputs;
      [a[i - 1], a[i]] = [a[i], a[i - 1]];
      renderInputs(); update();
    },
    'del-output': (el) => {
      const i = Number(el.dataset.idx);
      if (state.tx.outputs.length <= 1) { toast('Keep at least one output — clear its fields instead.', 'warn'); return; }
      state.tx.outputs.splice(i, 1); renderOutputs(); update();
    },
    'dup-output': (el) => {
      const i = Number(el.dataset.idx);
      const copy = JSON.parse(JSON.stringify(state.tx.outputs[i], (k, v) => typeof v === 'bigint' ? v.toString() : v));
      copy.amount = BigInt(copy.amount || 0);
      copy.id = 'o' + Math.random().toString(36).slice(2, 9);
      state.tx.outputs.splice(i + 1, 0, copy); renderOutputs(); update();
    },
    'move-output-up': (el) => {
      const i = Number(el.dataset.idx);
      if (i === 0) return;
      const a = state.tx.outputs;
      [a[i - 1], a[i]] = [a[i], a[i - 1]];
      renderOutputs(); update();
    },
    'seq': (el) => {
      state.tx.inputs[Number(el.dataset.idx)].sequence = parseInt(el.dataset.v, 16) >>> 0;
      renderInputs(); update();
    },
    'out-mode': (el) => {
      const i = Number(el.dataset.idx);
      state.tx.outputs[i].mode = el.dataset.v;
      renderOutputs(); update();
    },
    'btc-amount': () => {},
    'max-amount': (el) => {
      const i = Number(el.dataset.idx);
      const m = TX.measure(state.tx);
      const others = state.tx.outputs.reduce((a, o, k) => k === i ? a : a + BigInt(o.amount || 0), 0n);
      const fee = BigInt(Math.ceil(m.vsize * (state.tx.feeRate || 0)));
      const left = m.inTotal - others - fee;
      if (left <= 0n) { toast('Nothing left after the other outputs and the fee.', 'warn'); return; }
      state.tx.outputs[i].amount = left;
      renderOutputs(); update();
      toast(`Set output #${i} to ${groupNum(left)} sat (leaves ${groupNum(fee)} sat fee at ${state.tx.feeRate} sat/vB).`);
    },
    'add-witness': (el) => { state.tx.inputs[Number(el.dataset.idx)].witness.push(''); renderInputs(); update(); },
    'del-witness': (el) => {
      state.tx.inputs[Number(el.dataset.idx)].witness.splice(Number(el.dataset.wi), 1);
      renderInputs(); update();
    },
    'add-sig': (el) => {
      const inp = state.tx.inputs[Number(el.dataset.idx)];
      inp.partialSigs = inp.partialSigs || []; inp.partialSigs.push({ pubkey: '', signature: '' });
      renderInputs(); update();
    },
    'del-sig': (el) => {
      state.tx.inputs[Number(el.dataset.idx)].partialSigs.splice(Number(el.dataset.si), 1);
      renderInputs(); update();
    },
    'add-bip32': (el) => {
      const inp = state.tx.inputs[Number(el.dataset.idx)];
      inp.bip32 = inp.bip32 || []; inp.bip32.push({ pubkey: '', fingerprint: '', path: "m/84'/0'/0'/0/0" });
      renderInputs(); update();
    },
    'del-bip32': (el) => {
      state.tx.inputs[Number(el.dataset.idx)].bip32.splice(Number(el.dataset.di), 1);
      renderInputs(); update();
    },
    'opret-prefix': (el) => {
      const o = state.tx.outputs[Number(el.dataset.idx)].opret;
      const prefix = el.dataset.v;
      if (!prefix) return;
      /* switch to hex so the marker bytes survive verbatim, then keep whatever was there */
      const existing = o.encoding === 'hex' ? o.payload : bytesToHex(safe(() => TX.encodePayload(o.payload || '', o.encoding), new Uint8Array(0)));
      o.encoding = 'hex';
      o.payload = prefix + (existing.startsWith(prefix) ? existing.slice(prefix.length) : existing);
      renderOutputs(); update();
    },
    'add-extra': (el) => {
      const o = state.tx.outputs[Number(el.dataset.idx)].opret;
      o.extraPayloads = o.extraPayloads || []; o.extraPayloads.push({ encoding: 'utf8', value: '' });
      renderOutputs(); update();
    },
    'del-extra': (el) => {
      state.tx.outputs[Number(el.dataset.idx)].opret.extraPayloads.splice(Number(el.dataset.ei), 1);
      renderOutputs(); update();
    },
    'finalize-one': (el) => {
      const i = Number(el.dataset.idx);
      const inp = state.tx.inputs[i];
      const r = FINALIZE.finalizeInput(inp);
      if (!r.ok) { toast(`Input #${i}: ${r.note}`, 'warn'); return; }
      inp.scriptSig = r.scriptSig;
      inp.witness = r.witness.slice();   // empty items are meaningful — keep them
      toast(`Input #${i} assembled — ${r.note}`);
      renderAll();
    },
    'raw-from-hex': (el) => {
      const i = Number(el.dataset.idx);
      const h = prompt('Paste the scriptPubKey hex:');
      if (!h) return;
      try { state.tx.outputs[i].rawAsm = S.toAsm(hexToBytes(h.trim())); renderOutputs(); update(); }
      catch (e) { toast(e.message, 'err'); }
    },
    'raw-to-lab': (el) => {
      const i = Number(el.dataset.idx);
      loadIntoScriptLab(TX.resolveOutput(state.tx.outputs[i], state.tx.network).script);
    },
    'op-cat': (el) => { state.opCat = el.dataset.v; renderScriptLab(); },
    'op-add': (el) => { state.canvas.push({ kind: 'op', op: el.dataset.v }); renderCanvas(); persist(); },
    'canvas-del': (el) => { state.canvas.splice(Number(el.dataset.ci), 1); renderCanvas(); persist(); },
    'canvas-up': (el) => {
      const i = Number(el.dataset.ci); if (i === 0) return;
      [state.canvas[i - 1], state.canvas[i]] = [state.canvas[i], state.canvas[i - 1]];
      renderCanvas(); persist();
    },
    'canvas-down': (el) => {
      const i = Number(el.dataset.ci); if (i >= state.canvas.length - 1) return;
      [state.canvas[i + 1], state.canvas[i]] = [state.canvas[i], state.canvas[i + 1]];
      renderCanvas(); persist();
    },
    'imp-psbt': () => mergePsbt(false),
    'imp-psbt-replace': () => mergePsbt(true),
    'imp-der': importDer,
    'imp-schnorr': importSchnorr,
    'imp-rs': importRs,
    'imp-json': importJson,
    'imp-verify': () => verifyImported(false),
    'imp-verify-schnorr': () => verifyImported(true),
    'imp-raw': () => {
      const h = $('#imp-raw').value.trim();
      if (!h) return;
      try {
        const dec = TX.decodeRaw(h);
        state.tx = normaliseTx(TX.fromDecoded(dec, state.tx.network));
        renderAll();
        toast(`Loaded a ${dec.size}-byte transaction — txid ${dec.txid.slice(0, 16)}…`);
      } catch (e) { toast(e.message, 'err'); }
    }
  };

  function mergePsbt(replace) {
    const raw = $('#imp-psbt').value.trim();
    if (!raw) { toast('Paste the signed PSBT.', 'warn'); return; }
    let parsed;
    try { parsed = PSBT.parse(raw); } catch (e) { toast(e.message, 'err'); return; }
    const diff = PSBT.diff(state.tx, parsed);
    const { tx } = PSBT.toModel(parsed, state.tx.network);
    if (replace) state.tx = normaliseTx(tx);
    else {
      tx.inputs.forEach((src, i) => {
        const dst = state.tx.inputs[i];
        if (!dst) { state.tx.inputs[i] = src; return; }
        if (src.partialSigs && src.partialSigs.length) dst.partialSigs = src.partialSigs;
        if (src.tapKeySig) dst.tapKeySig = src.tapKeySig;
        if (src.tapScriptSigs && src.tapScriptSigs.length) dst.tapScriptSigs = src.tapScriptSigs;
        if (src.scriptSig) { dst.scriptSig = src.scriptSig; dst.manualScriptSig = true; }
        if (src.witness && src.witness.length) { dst.witness = src.witness; dst.manualWitness = true; }
        if (src.redeemScript && !dst.redeemScript) dst.redeemScript = src.redeemScript;
        if (src.witnessScript && !dst.witnessScript) dst.witnessScript = src.witnessScript;
        if (src.scriptPubKey && !dst.scriptPubKey) dst.scriptPubKey = src.scriptPubKey;
        if (src.amount && !dst.amount) dst.amount = src.amount;
      });
    }
    renderAll();
    const added = diff.filter(d => d.added > 0).length;
    $('#finalize-status').insertAdjacentHTML('afterbegin',
      `<div class="vrow"><span class="tag teal">MERGED</span><div class="vtxt"><div class="vt">${added} input(s) gained a signature</div>
       <div class="vd">${diff.map(d => `#${d.index} ${d.status}`).join(' · ')}</div></div></div>`);
    toast(replace ? 'Transaction replaced from the PSBT.' : `Merged — ${added} input(s) gained a signature.`);
  }

  /* ============================== demos ================================== */

  const DEMO_H160 = '85d85df6e72e4c5f6e8f9a0b1c2d3e4f5c33ad5d';
  const DEMO_H160_B = '9a1633caf7b9d0e1f2a3b4c5d6e7f80912345678';
  const DEMO_TXID = 'f3b2c9a7d8e6f1b3c4d5e6f708192a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f';
  const PK = [
    '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
    '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'
  ];
  const XONLY = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

  function loadDemo(kind) {
    const net = state.tx.network;
    const tx = TX.newTx();
    tx.network = net;
    const addrOf = (script) => S.scriptToAddress(script, net) || '';

    if (kind === 'p2wpkh') {
      const i0 = TX.newInput();
      i0.txid = DEMO_TXID; i0.vout = 0; i0.amount = 500000n;
      i0.scriptPubKey = bytesToHex(S.p2wpkh(hexToBytes(DEMO_H160)));
      tx.inputs = [i0];
      const o0 = TX.newOutput(); o0.amount = 300000n; o0.mode = 'address';
      o0.address = addrOf(S.p2wpkh(hexToBytes(DEMO_H160_B)));
      const o1 = TX.newOutput(); o1.amount = 197000n; o1.mode = 'address';
      o1.address = addrOf(S.p2wpkh(hexToBytes(DEMO_H160)));
      o1.label = 'change';
      tx.outputs = [o0, o1];
    } else if (kind === 'opreturn') {
      const i0 = TX.newInput();
      i0.txid = DEMO_TXID; i0.vout = 1; i0.amount = 120000n;
      i0.scriptPubKey = bytesToHex(S.p2pkh(hexToBytes(DEMO_H160)));
      tx.inputs = [i0];
      const o0 = TX.newOutput(); o0.amount = 0n; o0.mode = 'opreturn';
      o0.opret.encoding = 'utf8'; o0.opret.payload = 'PuzzleForensics';
      const o1 = TX.newOutput(); o1.amount = 117000n; o1.mode = 'address';
      o1.address = addrOf(S.p2pkh(hexToBytes(DEMO_H160)));
      tx.outputs = [o0, o1];
    } else if (kind === 'taproot') {
      const t = BC.taprootTweak(hexToBytes(XONLY), null);
      const i0 = TX.newInput();
      i0.txid = DEMO_TXID; i0.vout = 0; i0.amount = 1000000n;
      i0.scriptPubKey = bytesToHex(S.p2tr(t.outputKey));
      i0.algorithm = 'schnorr'; i0.sighashType = 0;
      i0.taproot.internalKey = XONLY; i0.taproot.path = 'key';
      tx.inputs = [i0];
      const o0 = TX.newOutput(); o0.amount = 990000n; o0.mode = 'address';
      o0.address = addrOf(S.p2tr(t.outputKey));
      tx.outputs = [o0];
    } else if (kind === 'multisig') {
      const ws = S.multisig(2, PK.map(p => hexToBytes(p)));
      const i0 = TX.newInput();
      i0.txid = DEMO_TXID; i0.vout = 2; i0.amount = 2000000n;
      i0.scriptPubKey = bytesToHex(S.p2wsh(BC.sha256(ws)));
      i0.witnessScript = bytesToHex(ws);
      tx.inputs = [i0];
      const o0 = TX.newOutput(); o0.amount = 1_950_000n; o0.mode = 'address';
      o0.address = addrOf(S.p2wsh(BC.sha256(ws)));
      tx.outputs = [o0];
    }
    state.tx = normaliseTx(tx);
    renderAll();
    toast(`Loaded the ${kind} example on ${netOf().label}.`);
  }

  /* ============================== exports ================================ */

  function doExport(kind) {
    const tx = state.tx;
    const unsigned = TX.serialize(tx, { final: false, forceWitness: false });
    switch (kind) {
      case 'hex-copy': return copyText(bytesToHex(unsigned));
      case 'hex-file': return download('unsigned-tx.hex', bytesToHex(unsigned), 'text/plain');
      case 'txn-file': return download('unsigned-tx.txn', unsigned);
      case 'psbt0-b64': return copyText(bytesToBase64(PSBT.build(tx, 0)));
      case 'psbt0-hex': return copyText(bytesToHex(PSBT.build(tx, 0)));
      case 'psbt0-bin': return download('transaction-v0.psbt', PSBT.build(tx, 0));
      case 'psbt2-b64': return copyText(bytesToBase64(PSBT.build(tx, 2)));
      case 'psbt2-hex': return copyText(bytesToHex(PSBT.build(tx, 2)));
      case 'psbt2-bin': return download('transaction-v2.psbt', PSBT.build(tx, 2));
      case 'signing-json': return download('signing-package.json', JSON.stringify(signingPackageAll(), null, 2), 'application/json');
      case 'signing-copy': return copyText(JSON.stringify(signingPackageAll(), null, 2));
      case 'project': return download('idleanvil-project.json', serializeState(), 'application/json');
    }
  }

  /* ================================ modal ================================ */

  function openModal(title, bodyHtml, footHtml = '') {
    $('#modal-title').textContent = title;
    $('#modal-body').innerHTML = bodyHtml;
    $('#modal-foot').innerHTML = footHtml || `<button class="btn" data-act="modal-close">Close</button>`;
    $('#modal').classList.add('open');
  }
  const closeModal = () => $('#modal').classList.remove('open');

  const HELP_HTML = `
  <p><strong>idleAnvil</strong> is a single-page, fully offline Bitcoin transaction workbench. It <strong>constructs, inspects and exports</strong> —
  it never signs, and there is nowhere to type a private key.</p>
  <div class="subhead mt-lg">The intended flow</div>
  <p class="mono small">construct → inspect → compute signing data → export → sign elsewhere → import signatures → finalize</p>
  <div class="subhead mt-lg">Workspaces</div>
  <dl class="kv">
    <dt>Transaction</dt><dd>version, locktime, network, serialization, forensic switches</dd>
    <dt>Inputs</dt><dd>outpoints, prevout data, redeem/witness scripts, taproot fields, per-input sighash</dd>
    <dt>Outputs</dt><dd>addresses, script templates, raw scripts, the OP_RETURN builder</dd>
    <dt>Script Lab</dt><dd>opcode palette, ASM ↔ hex, P2SH/P2WSH/tapleaf derivations</dd>
    <dt>Signing Data</dt><dd>preimage, digest, z, and everything a signer needs — per input</dd>
    <dt>PSBT Lab</dt><dd>build and decode BIP174 v0 / BIP370 v2; Bitcoin Core command helpers</dd>
    <dt>Finalize</dt><dd>import PSBTs, DER, Schnorr, r/s or signing JSON; assemble scriptSig and witness</dd>
    <dt>Inspector</dt><dd>byte-level decoding with field mapping</dd>
    <dt>Validation</dt><dd>consensus / policy findings and the sighash commitment matrix</dd>
    <dt>Raw Lab</dt><dd>hashes, DER surgery, address conversion, taproot bench, signature verification</dd>
    <dt>Toolkit</dt><dd>output descriptors, extended keys, taproot trees, unit/base/time conversion, size estimates, merkle roots, script analysis</dd>
    <dt>Node</dt><dd>optional Electrum-over-WebSocket link for fees, UTXOs, prevout lookup and a confirmed broadcast</dd>
  </dl>
  <div class="subhead mt-lg">Connecting a node</div>
  <p>Everything above works with no network at all. The <strong>Node</strong> workspace can optionally link to a local
    Electrum server over WebSocket — the testnet default is <span class="mono">ws://127.0.0.1:50002</span>.
    The port must be a WebSocket listener (<span class="mono">ws =</span> in <span class="mono">fulcrum.conf</span>);
    a browser cannot speak to a plain TCP or SSL Electrum port. The genesis hash is checked on connect, broadcasting
    always asks first, and no private key is ever transmitted because this page holds none.</p>
  <div class="subhead mt-lg">Reading the colours</div>
  <p>Colour means something here. Opcodes are tinted by category —
    <span class="asm"><span class="t op-push">push</span> · <span class="t op-stack">stack</span> ·
    <span class="t op-control">control</span> · <span class="t op-arith">arithmetic</span> ·
    <span class="t op-crypto">crypto</span> · <span class="t op-locktime">locktime</span></span> —
    with data pushes boxed and non-minimal or disabled ones flagged. Values are typed:
    <span class="v-addr mono">addresses</span>, <span class="v-hash mono">hashes</span>,
    <span class="v-num mono">numbers</span>, <span class="v-warn mono">warnings</span>.
    Amounts turn amber below dust and red when negative.</p>
  <div class="subhead mt-lg">Shortcuts</div>
  <p><kbd>1</kbd>–<kbd>9</kbd> <kbd>0</kbd> <kbd>-</kbd> switch workspace · <kbd>Ctrl</kbd>+<kbd>S</kbd> save project ·
  <kbd>Ctrl</kbd>+<kbd>O</kbd> open · <kbd>Ctrl</kbd>+<kbd>E</kbd> copy unsigned hex · <kbd>Esc</kbd> close dialogs</p>
  <div class="subhead mt-lg">What it implements</div>
  <p class="small">SHA-256 · RIPEMD-160 · SHA-1 · secp256k1 point arithmetic · BIP340 Schnorr verification · ECDSA verification ·
  Base58Check · Bech32 (BIP173) · Bech32m (BIP350) · transaction serialization (BIP144) · script assembler and disassembler ·
  legacy, BIP143 and BIP341 signature hashes · BIP174 and BIP370 PSBT · BIP341 taproot tweaking and tapleaf hashing.
  All of it is in the js/ files next to this page; nothing is fetched. <span class="mono">node verify.js</span> runs the in-repo regression checks.</p>
  <div class="banner mt-lg">${ico('alert', 18)}<div>Everything is computed locally in your browser. Verify any transaction independently
  before broadcasting it on mainnet — this tool is a bench, not an authority.</div></div>`;

  /* ================================ init ================================= */

  function wireGlobal() {
    let pendingFile = null;      // which reader the hidden <input type=file> is serving

    /* navigation */
    $('#sidebar').addEventListener('click', (e) => {
      const n = e.target.closest('.navitem');
      if (n) showWorkspace(n.dataset.ws);
    });

    /* mode switch */
    $('#modeswitch').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (!b) return;
      state.mode = b.dataset.mode;
      $$('#modeswitch button').forEach(x => x.classList.toggle('on', x === b));
      document.body.classList.toggle('forensic', state.mode === 'forensic');
      persist();
    });

    /* theme */
    $('#btn-theme').onclick = () => {
      const cur = document.documentElement.dataset.theme;
      document.documentElement.dataset.theme = cur === 'dark' ? 'light' : 'dark';
      persist();
    };
    $('#btn-help').onclick = () => openModal('About idleAnvil', HELP_HTML);
    $('#modal-close').onclick = closeModal;
    $('#modal').addEventListener('click', (e) => {
      if (e.target.id === 'modal' || e.target.closest('[data-act="modal-close"]')) closeModal();
    });

    /* export menu */
    $('#btn-export').onclick = (e) => { e.stopPropagation(); $('#export-menu').classList.toggle('open'); };
    $('#export-menu').addEventListener('click', (e) => {
      const b = e.target.closest('[data-export]');
      if (!b) return;
      $('#export-menu').classList.remove('open');
      try { doExport(b.dataset.export); } catch (err) { toast(err.message, 'err'); }
    });
    document.addEventListener('click', () => $('#export-menu').classList.remove('open'));

    /* new / open / save */
    $('#btn-new').onclick = () => {
      if (!confirm('Start a new transaction? The current one will be discarded.')) return;
      const net = state.tx.network;
      state.tx = TX.newTx(); state.tx.network = net;
      state.canvas = [];
      renderAll();
      toast('New transaction.');
    };
    $('#btn-save').onclick = () => doExport('project');
    $('#btn-open').onclick = () => { pendingFile = 'project'; $('#file-input').click(); };

    $('#file-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      const target = pendingFile;
      reader.onload = () => {
        try {
          if (target === 'psbt') {
            const buf = new Uint8Array(reader.result);
            const isBinary = buf[0] === 0x70 && buf[1] === 0x73 && buf[2] === 0x62 && buf[3] === 0x74;
            $('#psbt-in').value = isBinary ? bytesToHex(buf) : new TextDecoder().decode(buf);
            decodePsbtInput(false);
            toast(`Loaded ${file.name} (${buf.length} bytes).`);
          } else {
            const d = reviveState(new TextDecoder().decode(new Uint8Array(reader.result)));
            state.tx = normaliseTx(d.tx || d);
            if (d.canvas) state.canvas = d.canvas;
            renderAll();
            toast(`Opened ${file.name}.`);
          }
        } catch (err) { toast('Could not read that file: ' + err.message, 'err'); }
      };
      reader.readAsArrayBuffer(file);
      e.target.value = '';
    });

    /* dock collapse */
    $('#btn-dock-toggle').onclick = () => $('#app').classList.toggle('dock-collapsed');

    /* copy delegation (whole document) */
    document.addEventListener('click', (e) => {
      const c = e.target.closest('[data-copy-el]');
      if (c && c.dataset.copyEl) {
        const el = document.getElementById(c.dataset.copyEl);
        if (el) { copyText(el.value !== undefined ? el.value : el.textContent, c); return; }
      }
      const v = e.target.closest('[data-copy-val]');
      if (v) { copyText(v.dataset.copyVal, v); }
    });
    /* the copy button that sits inside an input wrapper with no id */
    document.addEventListener('click', (e) => {
      const b = e.target.closest('.with-copy .iconbtn');
      if (!b || b.dataset.copyEl || b.dataset.copyVal) return;
      const wrap = b.closest('.with-copy');
      const f = wrap.querySelector('input, textarea');
      if (f) copyText(f.value, b);
    });

    /* ---------- the main delegated handlers on the stage ---------- */

    $('#stage').addEventListener('click', (e) => {
      const a = e.target.closest('[data-act]');
      if (!a) return;
      const fn = ACTIONS[a.dataset.act];
      if (fn) { fn(a, e); }
    });

    $('#stage').addEventListener('input', onFieldChange);
    $('#stage').addEventListener('change', onFieldChange);

    /* forensic toggles */
    $('#stage').addEventListener('change', (e) => {
      const f = e.target.closest('[data-forensic]');
      if (!f) return;
      state.tx.forensic[f.dataset.forensic] = f.checked;
      renderAll();
    });
    $('#btn-reset-forensic').onclick = () => { state.tx.forensic = {}; renderAll(); toast('Forensic controls reset.'); };

    /* demos */
    $('#stage').addEventListener('click', (e) => {
      const d = e.target.closest('[data-demo]');
      if (d) loadDemo(d.dataset.demo);
    });

    /* inputs / outputs toolbars */
    $('#btn-add-input').onclick = () => { state.tx.inputs.push(TX.newInput()); renderInputs(); update(); };
    $('#btn-add-output').onclick = () => { state.tx.outputs.push(TX.newOutput()); renderOutputs(); update(); };
    $('#btn-in-expand').onclick = () => { state.tx.inputs.forEach(i => i.collapsed = false); renderInputs(); update(); };
    $('#btn-in-collapse').onclick = () => { state.tx.inputs.forEach(i => i.collapsed = true); renderInputs(); update(); };
    $('#btn-out-expand').onclick = () => { state.tx.outputs.forEach(o => o.collapsed = false); renderOutputs(); update(); };
    $('#btn-out-collapse').onclick = () => { state.tx.outputs.forEach(o => o.collapsed = true); renderOutputs(); update(); };
    $('#btn-in-paste').onclick = () => {
      openModal('Import inputs from a raw transaction',
        `<div class="field"><label>Raw transaction hex — its outputs become spendable prevouts</label>
          <textarea id="modal-rawtx" class="mono" rows="6"></textarea></div>
         <div class="field mt"><label>Which output index to spend</label><input type="number" id="modal-rawvout" value="0" min="0"></div>`,
        `<button class="btn" data-act="modal-close">Cancel</button><button class="btn primary" id="modal-import-prev">Add as input</button>`);
      $('#modal-import-prev').onclick = () => {
        try {
          const dec = TX.decodeRaw($('#modal-rawtx').value.trim());
          const vout = parseInt($('#modal-rawvout').value, 10) || 0;
          const po = dec.outputs[vout];
          if (!po) throw new Error(`that transaction has no output at index ${vout}`);
          const inp = TX.newInput();
          inp.txid = dec.txid; inp.vout = vout; inp.amount = po.amount;
          inp.scriptPubKey = po.script; inp.prevTxHex = bytesToHex(dec.bytes);
          state.tx.inputs.push(inp);
          closeModal(); renderInputs(); update();
          toast(`Added ${dec.txid.slice(0, 12)}…:${vout} — ${groupNum(po.amount)} sat.`);
        } catch (err) { toast(err.message, 'err'); }
      };
    };
    $('#btn-set-fee').onclick = () => {
      const m = TX.measure(state.tx);
      const rate = state.tx.feeRate || 1;
      const target = BigInt(Math.ceil(m.vsize * rate));
      const last = state.tx.outputs[state.tx.outputs.length - 1];
      if (!last) return;
      const others = state.tx.outputs.slice(0, -1).reduce((a, o) => a + BigInt(o.amount || 0), 0n);
      const left = m.inTotal - others - target;
      if (left <= 0n) { toast('Not enough input value to cover the other outputs plus that fee.', 'warn'); return; }
      last.amount = left;
      renderOutputs(); update();
      toast(`Last output set to ${groupNum(left)} sat — fee ${groupNum(target)} sat at ${rate} sat/vB.`);
    };

    /* script lab */
    $('#script-asm').oninput = (e) => { state.canvas = []; compileScript(e.target.value, 'asm'); };
    $('#script-hex').oninput = (e) => { state.canvas = []; compileScript(e.target.value, 'hex'); };
    $('#btn-canvas-clear').onclick = () => { state.canvas = []; $('#script-asm').value = ''; $('#script-hex').value = ''; renderCanvas(); };
    $('#btn-push-add').onclick = () => {
      const v = $('#push-value').value.trim();
      if (!v) return;
      state.canvas.push({ kind: 'push', value: v });
      $('#push-value').value = '';
      renderCanvas(); persist();
    };
    $('#stage').addEventListener('input', (e) => {
      const c = e.target.closest('[data-act="canvas-edit"]');
      if (!c) return;
      state.canvas[Number(c.dataset.ci)].value = c.value;
      syncScriptFromCanvas();
    });
    /* canvas drag reorder */
    let dragIdx = null;
    $('#script-canvas').addEventListener('dragstart', (e) => {
      const it = e.target.closest('.canvas-item'); if (!it) return;
      dragIdx = Number(it.dataset.ci); it.classList.add('dragging');
    });
    $('#script-canvas').addEventListener('dragend', (e) => {
      $$('.canvas-item').forEach(x => x.classList.remove('dragging', 'over'));
    });
    $('#script-canvas').addEventListener('dragover', (e) => {
      e.preventDefault();
      const it = e.target.closest('.canvas-item');
      $$('.canvas-item').forEach(x => x.classList.remove('over'));
      if (it) it.classList.add('over');
    });
    $('#script-canvas').addEventListener('drop', (e) => {
      e.preventDefault();
      const it = e.target.closest('.canvas-item');
      if (!it || dragIdx === null) return;
      const to = Number(it.dataset.ci);
      const [moved] = state.canvas.splice(dragIdx, 1);
      state.canvas.splice(to, 0, moved);
      dragIdx = null;
      renderCanvas(); persist();
    });
    $('#stage').addEventListener('click', (e) => {
      const b = e.target.closest('[data-send]');
      if (!b) return;
      const hex = $('#script-hex').value.trim();
      if (!hex) { toast('The canvas is empty.', 'warn'); return; }
      const idx = parseInt($('#script-target-idx').value, 10) || 0;
      switch (b.dataset.send) {
        case 'out-raw': {
          const out = state.tx.outputs[idx];
          if (!out) { toast(`There is no output #${idx}.`, 'err'); return; }
          out.mode = 'raw'; out.rawAsm = $('#script-asm').value;
          renderOutputs(); toast(`Sent to output #${idx}.`); break;
        }
        case 'in-redeem':
        case 'in-witness':
        case 'in-leaf':
        case 'in-scriptsig': {
          const inp = state.tx.inputs[idx];
          if (!inp) { toast(`There is no input #${idx}.`, 'err'); return; }
          if (b.dataset.send === 'in-redeem') inp.redeemScript = hex;
          if (b.dataset.send === 'in-witness') inp.witnessScript = hex;
          if (b.dataset.send === 'in-leaf') { inp.taproot.leafScript = hex; inp.taproot.path = 'script'; }
          if (b.dataset.send === 'in-scriptsig') { inp.scriptSig = hex; inp.manualScriptSig = true; }
          renderInputs(); toast(`Sent to input #${idx}.`); break;
        }
      }
      update();
    });

    /* signing */
    $('#signing-input-sel').onchange = (e) => { state.signingIndex = Number(e.target.value); renderSigning(); renderCode(); };
    $('#btn-copy-signing-json').onclick = () => copyText(JSON.stringify(signingPackage(state.signingIndex), null, 2));
    $('#btn-export-signing').onclick = () => doExport('signing-json');

    /* psbt */
    $('#psbt-ver-seg').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      state.psbtVersion = Number(b.dataset.v);
      state.tx.psbtVersion = state.psbtVersion;
      $('#f-psbt-version').value = String(state.psbtVersion);
      renderPsbt(); update();
    });
    $('#btn-psbt-refresh').onclick = renderPsbt;
    $('#btn-psbt-parse').onclick = () => decodePsbtInput(false);
    $('#btn-psbt-load').onclick = () => decodePsbtInput(true);
    $('#btn-psbt-download').onclick = () => download(`transaction-v${state.psbtVersion}.psbt`, PSBT.build(state.tx, state.psbtVersion));
    $('#psbt-drop').onclick = () => { pendingFile = 'psbt'; $('#file-input').click(); };
    ['dragover', 'dragleave', 'drop'].forEach(ev => {
      $('#psbt-drop').addEventListener(ev, (e) => {
        e.preventDefault();
        $('#psbt-drop').classList.toggle('over', ev === 'dragover');
        if (ev !== 'drop') return;
        const file = e.dataTransfer.files[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = () => {
          const buf = new Uint8Array(reader.result);
          const isBinary = buf[0] === 0x70 && buf[1] === 0x73 && buf[2] === 0x62 && buf[3] === 0x74;
          $('#psbt-in').value = isBinary ? bytesToHex(buf) : new TextDecoder().decode(buf);
          decodePsbtInput(false);
        };
        reader.readAsArrayBuffer(file);
      });
    });

    /* finalize */
    $('#import-tabs').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      state.importTab = b.dataset.t; renderFinalize();
    });
    $('#btn-finalize-run').onclick = () => {
      const rep = FINALIZE.finalizeAll(state.tx);
      renderAll();
      const ok = rep.filter(r => r.ok).length;
      toast(`Assembled ${ok} of ${rep.length} inputs.`);
    };
    $('#btn-final-copy').onclick = () => copyText(bytesToHex(TX.serialize(state.tx, { final: true })));
    $('#btn-final-download').onclick = () => download('final-tx.hex', bytesToHex(TX.serialize(state.tx, { final: true })), 'text/plain');

    /* inspector */
    $('#inspect-src').addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      state.inspectSrc = b.dataset.s;
      $$('#inspect-src button').forEach(x => x.classList.toggle('on', x === b));
      $('#inspect-paste-wrap').classList.toggle('hidden', state.inspectSrc !== 'paste');
      runInspector();
    });
    $('#btn-inspect-run').onclick = runInspector;
    $('#btn-inspect-load').onclick = () => {
      try {
        const dec = TX.decodeRaw($('#inspect-hex').value.trim());
        state.tx = normaliseTx(TX.fromDecoded(dec, state.tx.network));
        renderAll();
        toast('Loaded into the workbench.');
      } catch (e) { toast(e.message, 'err'); }
    };
    $('#hexview').addEventListener('mouseover', (e) => {
      const b = e.target.closest('.byte');
      if (b) showByteInfo(b.dataset.fi, Number(b.dataset.bo));
    });
    $('#hexview').addEventListener('click', (e) => {
      const b = e.target.closest('.byte');
      if (b) showByteInfo(b.dataset.fi, Number(b.dataset.bo));
    });
    $('#inspect-table').addEventListener('mouseover', (e) => {
      const tr = e.target.closest('tr[data-fi]');
      if (tr) showByteInfo(tr.dataset.fi);
    });

    /* validation */
    $('#matrix-input').onchange = (e) => { state.matrixIndex = Number(e.target.value); renderMatrix(); };

    /* keyboard */
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { closeModal(); $('#export-menu').classList.remove('open'); return; }
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); doExport('project'); return; }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'o') { e.preventDefault(); $('#btn-open').click(); return; }
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'e') { e.preventDefault(); doExport('hex-copy'); return; }
      if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
      const order = ['transaction', 'inputs', 'outputs', 'script', 'signing', 'psbt', 'finalize',
                     'inspector', 'validation', 'rawlab', 'toolkit', 'multisig', 'node'];
      const n = parseInt(e.key, 10);
      if (n >= 1 && n <= 9) showWorkspace(order[n - 1]);
      if (e.key === '0') showWorkspace(order[9]);
      if (e.key === '-') showWorkspace(order[10]);
      if (e.key === '=') showWorkspace(order[11]);
      if (e.key === 'm') showWorkspace(order[12]);
    });

    wireRawLab();
    wireToolkit();
    wireMultisig();
    wireNode();
  }

  /** One handler for every bound field in the stage. */
  function onFieldChange(e) {
    const el = e.target.closest('[data-bind]');
    if (!el) {
      /* the BTC mirror field is handled separately */
      const btc = e.target.closest('[data-act="btc-amount"]');
      if (btc && e.type === 'change') {
        const i = Number(btc.dataset.idx);
        try {
          state.tx.outputs[i].amount = btcToSats(btc.value);
          renderOutputs(); update();
        } catch (err) { toast(err.message, 'err'); }
      }
      return;
    }
    const [scope, idxStr, ...pathParts] = el.dataset.bind.split(':');
    const path = pathParts.join(':');
    const idx = Number(idxStr);
    const target = scope === 'in' ? state.tx.inputs[idx] : state.tx.outputs[idx];
    if (!target) return;

    let value;
    if (el.type === 'checkbox') value = el.checked;
    else value = coerce(el.value, el.dataset.type);

    if (path === 'sequence' || path === 'vout') value = value >>> 0;   // both are uint32 by definition
    setPath(target, path, value);

    if (el.dataset.structural && e.type === 'change') {
      if (scope === 'in') renderInputs(); else renderOutputs();
    }
    update();
  }

  /* ------------------------------------------------------------------ go */

  /** Workspace deep links: idleanvil/#multisig opens straight into that workspace. */
  const hashWorkspace = () => {
    const h = (location.hash || '').replace(/^#\/?/, '').toLowerCase();
    return document.getElementById('ws-' + h) ? h : null;
  };

  function init() {
    const restored = restore();
    if (!restored) {
      state.tx = TX.newTx();
      state.canvas = [
        { kind: 'op', op: 'OP_DUP' }, { kind: 'op', op: 'OP_HASH160' },
        { kind: 'push', value: DEMO_H160 },
        { kind: 'op', op: 'OP_EQUALVERIFY' }, { kind: 'op', op: 'OP_CHECKSIG' }
      ];
    }
    state.psbtVersion = state.tx.psbtVersion || 0;
    document.body.classList.toggle('forensic', state.mode === 'forensic');
    $$('#modeswitch button').forEach(x => x.classList.toggle('on', x.dataset.mode === state.mode));
    wireGlobal();
    renderAll();
    if (!restored) loadDemo('p2wpkh');
    showWorkspace(hashWorkspace() || 'transaction');
    window.addEventListener('hashchange', () => { const ws = hashWorkspace(); if (ws) showWorkspace(ws); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
