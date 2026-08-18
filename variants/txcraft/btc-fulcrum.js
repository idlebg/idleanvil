/* btc-fulcrum.js — Electrum-protocol client for a local Fulcrum / ElectrumX server over WebSocket.
   Fulcrum must expose ws_port (or wss_port) in fulcrum.conf. Requires btc-core.js + btc-tx.js. */
(function (g) {
  const B = g.BTC;

  class Electrum {
    constructor(url, opts) {
      opts = opts || {};
      this.url = url;
      this.id = 0;
      this.pending = new Map();
      this.ws = null;
      this.status = 'idle';
      this.onStatus = opts.onStatus || function () { };
      this.onNotify = opts.onNotify || function () { };
      this.onLog = opts.onLog || function () { };
      this.timeout = opts.timeout || 12000;
    }
    _set(s, detail) { this.status = s; this.onStatus(s, detail); }
    connect() {
      return new Promise((resolve, reject) => {
        if (this.ws && this.ws.readyState === 1) return resolve(this);
        if (typeof location !== 'undefined' && location.protocol === 'https:' && /^ws:/.test(this.url)) {
          const m = 'This page is served over https, so the browser blocks a plain ws:// connection. Open the standalone file locally, serve it over http, or configure Fulcrum’s wss_port and use wss://.';
          this._set('error', m); return reject(new Error(m));
        }
        let ws;
        try { ws = new WebSocket(this.url); } catch (e) { this._set('error', e.message); return reject(e); }
        this.ws = ws;
        this._set('connecting');
        const timer = setTimeout(() => { try { ws.close(); } catch (e) { /* ignore */ } this._set('error', 'connection timed out'); reject(new Error('connection timed out')); }, this.timeout);
        ws.onopen = () => { clearTimeout(timer); this._set('open'); this.onLog('connected to ' + this.url, 'ok'); resolve(this); };
        ws.onerror = () => { clearTimeout(timer); this._set('error', 'the socket could not be opened — check the address, that Fulcrum is running, and that ws_port is set'); reject(new Error('socket error')); };
        ws.onclose = (ev) => {
          clearTimeout(timer);
          this.pending.forEach((p) => p.reject(new Error('connection closed')));
          this.pending.clear();
          if (this.status !== 'error') this._set('closed', ev.reason || '');
        };
        ws.onmessage = (ev) => String(ev.data).split('\n').filter((l) => l.trim()).forEach((line) => this._handle(line));
      });
    }
    _handle(line) {
      let msg;
      try { msg = JSON.parse(line); } catch (e) { this.onLog('unparseable frame: ' + line.slice(0, 80), 'err'); return; }
      if (msg.id != null && this.pending.has(msg.id)) {
        const p = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        clearTimeout(p.timer);
        if (msg.error) p.reject(new Error(typeof msg.error === 'string' ? msg.error : (msg.error.message || JSON.stringify(msg.error))));
        else p.resolve(msg.result);
      } else if (msg.method) this.onNotify(msg.method, msg.params);
    }
    call(method, params) {
      return new Promise((resolve, reject) => {
        if (!this.ws || this.ws.readyState !== 1) return reject(new Error('not connected'));
        const id = ++this.id;
        const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(method + ' timed out')); }, this.timeout);
        this.pending.set(id, { resolve: resolve, reject: reject, timer: timer });
        this.ws.send(JSON.stringify({ jsonrpc: '2.0', id: id, method: method, params: params || [] }) + '\n');
      });
    }
    close() { try { this.ws && this.ws.close(); } catch (e) { /* ignore */ } this._set('closed'); }
  }

  /* Electrum indexes by the reversed SHA256 of the output script. */
  const scriptHash = (script) => B.toHex(B.rev(B.sha256(script)));
  const addressScriptHash = (addr, network) => scriptHash(B.addressToScript(addr, network).script);

  const api = {
    Electrum: Electrum,
    scriptHash: scriptHash,
    addressScriptHash: addressScriptHash,
    async handshake(c) {
      const version = await c.call('server.version', ['txcraft', ['1.4', '1.5']]);
      let banner = '';
      try { banner = await c.call('server.banner', []); } catch (e) { banner = ''; }
      const head = await c.call('blockchain.headers.subscribe', []);
      let relayfee = null;
      try { relayfee = await c.call('blockchain.relayfee', []); } catch (e) { /* optional */ }
      return { version: version, banner: banner, height: head && head.height, relayfee: relayfee };
    },
    async rawTx(c, txid) { return c.call('blockchain.transaction.get', [txid, false]); },
    async prevout(c, txid, vout) {
      const hex = await c.call('blockchain.transaction.get', [txid, false]);
      const tx = B.parseTx(B.fromHex(hex));
      const got = B.txid(tx);
      if (got !== String(txid).trim().toLowerCase())
        throw new Error('server returned transaction ' + got.slice(0, 12) + '…, not the requested ' + String(txid).slice(0, 12) + '…');
      const o = tx.outs[vout];
      if (!o) throw new Error('vout ' + vout + ' does not exist in ' + txid.slice(0, 12) + '… (' + tx.outs.length + ' outputs)');
      return { value: o.value, script: B.toHex(o.script), rawTx: hex, tx: tx };
    },
    async listUnspent(c, addr, network) {
      const list = await c.call('blockchain.scripthash.listunspent', [addressScriptHash(addr, network)]);
      const spk = B.toHex(B.addressToScript(addr, network).script);
      return (list || []).map((u) => ({ txid: u.tx_hash, vout: u.tx_pos, value: u.value, height: u.height, script: spk }));
    },
    async history(c, addr, network) { return c.call('blockchain.scripthash.get_history', [addressScriptHash(addr, network)]); },
    async balance(c, addr, network) { return c.call('blockchain.scripthash.get_balance', [addressScriptHash(addr, network)]); },
    async feeRates(c) {
      const targets = [1, 2, 3, 6, 25];
      const out = {};
      for (const t of targets) {
        try {
          const btcPerKb = await c.call('blockchain.estimatefee', [t]);
          out[t] = btcPerKb > 0 ? (btcPerKb * 1e8) / 1000 : null;
        } catch (e) { out[t] = null; }
      }
      return out;
    },
    async broadcast(c, hex) { return c.call('blockchain.transaction.broadcast', [hex]); }
  };

  g.BTC.FX = api;
})(typeof window !== 'undefined' ? window : globalThis);
