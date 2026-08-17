/* ============================================================================
   node.js — optional Electrum-protocol client over WebSocket.
   OFF by default. Nothing here ever sees a private key: it fetches chain data
   and, only on explicit confirmation, broadcasts a finished transaction.
   Exposes: window.NODE
   ========================================================================== */
(function (global) {
  'use strict';
  const { bytesToHex, hexToBytes, reverse } = ENC;

  /* Default endpoints, one per chain. Testnet points at the user's server. */
  const DEFAULT_ENDPOINTS = {
    mainnet:  'ws://127.0.0.1:50004',
    testnet3: 'ws://127.0.0.1:50002',
    testnet4: 'ws://127.0.0.1:50002',
    signet:   'ws://127.0.0.1:50003',
    regtest:  'ws://127.0.0.1:50001'
  };

  /* Genesis block hashes — used to catch "connected to the wrong chain". */
  const GENESIS = {
    mainnet:  '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
    testnet3: '000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943',
    testnet4: '00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043',
    signet:   '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
    regtest:  '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
  };

  const CLIENT_NAME = 'idleAnvil/1.0';
  const PROTOCOL = ['1.4', '1.4.2'];
  const DEFAULT_TIMEOUT = 12000;

  /**
   * Electrum's index key for a script: sha256(scriptPubKey), byte-reversed, hex.
   */
  function scriptHash(scriptPubKey) {
    const b = scriptPubKey instanceof Uint8Array ? scriptPubKey : hexToBytes(scriptPubKey);
    return bytesToHex(reverse(BC.sha256(b)));
  }

  class ElectrumClient {
    constructor() {
      this.ws = null;
      this.url = null;
      this.status = 'disconnected';     // disconnected | connecting | connected | error
      this.nextId = 1;
      this.pending = new Map();
      this.buffer = '';
      this.listeners = { status: [], header: [], log: [], error: [] };
      this.info = {};                   // version, features, banner, height, genesis
      this.log = [];                    // recent traffic, newest last
      this.maxLog = 200;
      this.manualClose = false;
    }

    on(evt, fn) { (this.listeners[evt] || (this.listeners[evt] = [])).push(fn); return this; }
    emit(evt, payload) { (this.listeners[evt] || []).forEach(f => { try { f(payload); } catch (e) { /* listener errors never break the client */ } }); }

    _log(dir, text) {
      this.log.push({ t: Date.now(), dir, text: String(text).slice(0, 2000) });
      if (this.log.length > this.maxLog) this.log.shift();
      this.emit('log', this.log[this.log.length - 1]);
    }

    _setStatus(s, detail) {
      this.status = s;
      this.emit('status', { status: s, detail, url: this.url, info: this.info });
    }

    get connected() { return this.status === 'connected'; }

    /** Open the socket and complete the Electrum handshake. */
    connect(url, expectedNetwork) {
      if (this.ws) this.disconnect();
      this.url = url;
      this.manualClose = false;
      this.buffer = '';
      this.info = { expectedNetwork };
      this._setStatus('connecting');
      this._log('sys', `connecting to ${url}`);

      return new Promise((resolve, reject) => {
        let settled = false;
        let ws;
        try { ws = new WebSocket(url); }
        catch (e) {
          this._setStatus('error', e.message);
          return reject(new Error(`could not open ${url} — ${e.message}`));
        }
        this.ws = ws;

        const failTimer = setTimeout(() => {
          if (settled) return;
          settled = true;
          this._log('sys', 'connection timed out');
          this._setStatus('error', 'timed out');
          try { ws.close(); } catch (e) {}
          reject(new Error(`no response from ${url} within 10 s — is the server running and serving WebSocket on that port?`));
        }, 10000);

        ws.onopen = async () => {
          this._log('sys', 'socket open — negotiating');
          try {
            const version = await this.call('server.version', [CLIENT_NAME, PROTOCOL]);
            this.info.version = Array.isArray(version) ? version[0] : String(version);
            this.info.protocol = Array.isArray(version) ? version[1] : null;

            let features = null;
            try { features = await this.call('server.features', []); } catch (e) { /* optional */ }
            if (features) {
              this.info.genesis = features.genesis_hash || null;
              this.info.serverName = features.server_version || this.info.version;
              this.info.pruning = features.pruning;
              this.info.hashFunction = features.hash_function;
            }
            try { this.info.banner = await this.call('server.banner', []); } catch (e) {}

            const head = await this.call('blockchain.headers.subscribe', []);
            this.info.height = head && head.height;
            this.info.headerHex = head && head.hex;

            /* chain sanity check */
            this.info.chainMatch = null;
            if (this.info.genesis && expectedNetwork) {
              const want = GENESIS[expectedNetwork];
              this.info.chainMatch = want ? (this.info.genesis === want) : null;
              if (this.info.chainMatch === false) {
                const actual = Object.entries(GENESIS).find(([, g]) => g === this.info.genesis);
                this.info.chainMismatch =
                  `the server's genesis hash is ${this.info.genesis.slice(0, 16)}… which is ` +
                  (actual ? actual[0] : 'an unrecognised chain') + `, not ${expectedNetwork}`;
              }
            }

            clearTimeout(failTimer);
            settled = true;
            this._setStatus('connected');
            this._log('sys', `connected — ${this.info.serverName || this.info.version || 'server'} at height ${this.info.height}`);
            resolve(this.info);
          } catch (e) {
            clearTimeout(failTimer);
            settled = true;
            this._setStatus('error', e.message);
            this._log('err', 'handshake failed: ' + e.message);
            try { ws.close(); } catch (_) {}
            reject(new Error('handshake failed — ' + e.message));
          }
        };

        ws.onmessage = (ev) => this._onData(ev.data);

        ws.onerror = () => {
          this._log('err', 'socket error');
          if (!settled) {
            clearTimeout(failTimer);
            settled = true;
            this._setStatus('error', 'socket error');
            reject(new Error(
              `could not reach ${url}. Check that the server is running, that it exposes the ` +
              `Electrum protocol over WebSocket (not plain TCP), and that the port is right.`));
          }
        };

        ws.onclose = (ev) => {
          const wasConnected = this.status === 'connected';
          this.ws = null;
          for (const [, p] of this.pending) p.reject(new Error('connection closed'));
          this.pending.clear();
          if (!this.manualClose && wasConnected) {
            this._log('sys', `connection closed (code ${ev.code})`);
            this._setStatus('error', `closed (code ${ev.code})`);
          } else if (this.manualClose) {
            this._log('sys', 'disconnected');
            this._setStatus('disconnected');
          }
        };
      });
    }

    disconnect() {
      this.manualClose = true;
      if (this.ws) { try { this.ws.close(); } catch (e) {} }
      this.ws = null;
      this.pending.clear();
      this._setStatus('disconnected');
    }

    /**
     * Two framings exist in the wild and we accept both:
     *   - newline-delimited JSON (TCP-style, and what most WS bridges forward)
     *   - one complete JSON value per WebSocket frame, no terminator
     *     (this is what Fulcrum's native `ws` listener does)
     */
    _onData(raw) {
      let text;
      if (typeof raw === 'string') text = raw;
      else if (raw instanceof ArrayBuffer) text = new TextDecoder().decode(new Uint8Array(raw));
      else if (raw && typeof raw.toString === 'function') text = raw.toString();
      else return;

      this.buffer += text;

      let idx;
      while ((idx = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, idx).trim();
        this.buffer = this.buffer.slice(idx + 1);
        if (line) this._handleMessage(line);
      }

      /* no terminator: if what remains is a complete JSON value, take it now */
      const t = this.buffer.trim();
      if ((t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))) {
        this.buffer = '';
        this._handleMessage(t);
        return;
      }
      /* never let a malformed stream grow without bound */
      if (this.buffer.length > 8 * 1024 * 1024) {
        this._log('err', 'receive buffer exceeded 8 MB without a complete message — discarding');
        this.buffer = '';
      }
    }

    _handleMessage(line) {
      let msg;
      try { msg = JSON.parse(line); }
      catch (e) { this._log('err', 'unparsable frame: ' + line.slice(0, 160)); return; }
      this._log('in', line);

      if (Array.isArray(msg)) { msg.forEach(m => this._dispatch(m)); return; }
      this._dispatch(msg);
    }

    _dispatch(msg) {
      if (msg.id !== undefined && msg.id !== null && this.pending.has(msg.id)) {
        const p = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        clearTimeout(p.timer);
        if (msg.error) {
          const text = typeof msg.error === 'string' ? msg.error : (msg.error.message || JSON.stringify(msg.error));
          p.reject(new Error(text));
        } else p.resolve(msg.result);
        return;
      }
      if (msg.method === 'blockchain.headers.subscribe' && msg.params && msg.params[0]) {
        this.info.height = msg.params[0].height;
        this.emit('header', msg.params[0]);
      }
    }

    /** JSON-RPC call. Rejects on server error, timeout or a closed socket. */
    call(method, params = [], timeout = DEFAULT_TIMEOUT) {
      return new Promise((resolve, reject) => {
        if (!this.ws || this.ws.readyState !== 1)
          return reject(new Error('not connected'));
        const id = this.nextId++;
        const payload = JSON.stringify({ jsonrpc: '2.0', id, method, params });
        const timer = setTimeout(() => {
          this.pending.delete(id);
          reject(new Error(`${method} timed out after ${timeout / 1000} s`));
        }, timeout);
        this.pending.set(id, { resolve, reject, timer, method });
        this._log('out', payload);
        try { this.ws.send(payload + '\n'); }
        catch (e) { clearTimeout(timer); this.pending.delete(id); reject(e); }
      });
    }

    /* ------------------------- high-level helpers ------------------------ */

    async getHeight() {
      const h = await this.call('blockchain.headers.subscribe', []);
      this.info.height = h.height;
      return h.height;
    }

    /** Raw transaction hex for a txid. */
    getTransaction(txid) {
      return this.call('blockchain.transaction.get', [String(txid).trim(), false]);
    }

    getTransactionVerbose(txid) {
      return this.call('blockchain.transaction.get', [String(txid).trim(), true]);
    }

    listUnspent(scriptPubKey) {
      return this.call('blockchain.scripthash.listunspent', [scriptHash(scriptPubKey)]);
    }

    getBalance(scriptPubKey) {
      return this.call('blockchain.scripthash.get_balance', [scriptHash(scriptPubKey)]);
    }

    getHistory(scriptPubKey) {
      return this.call('blockchain.scripthash.get_history', [scriptHash(scriptPubKey)]);
    }

    /** @returns sat/vB, or null when the server cannot estimate. */
    async estimateFee(blocks) {
      const btcPerKvb = await this.call('blockchain.estimatefee', [blocks]);
      if (btcPerKvb === undefined || btcPerKvb === null || btcPerKvb < 0) return null;
      return (btcPerKvb * 1e8) / 1000;
    }

    async relayFee() {
      const btcPerKvb = await this.call('blockchain.relayfee', []);
      return (btcPerKvb * 1e8) / 1000;
    }

    /** Fee estimates across a spread of confirmation targets. */
    async feeTable(targets = [1, 2, 3, 6, 12, 25]) {
      const rows = [];
      for (const t of targets) {
        let rate = null, error = null;
        try { rate = await this.estimateFee(t); } catch (e) { error = e.message; }
        rows.push({ blocks: t, satPerVb: rate, error });
      }
      return rows;
    }

    /**
     * Publish a transaction. Irreversible — the UI must confirm before calling this.
     * @returns the txid the server reports
     */
    broadcast(rawHex) {
      return this.call('blockchain.transaction.broadcast', [String(rawHex).trim()], 25000);
    }

    /**
     * Everything needed to spend one outpoint: amount, scriptPubKey and the
     * full parent transaction (for PSBT non-witness UTXO).
     */
    async fetchPrevout(txid, vout) {
      const rawHex = await this.getTransaction(txid);
      const dec = TX.decodeRaw(rawHex);
      const out = dec.outputs[vout];
      if (!out) throw new Error(`${txid.slice(0, 12)}… has no output at index ${vout} (it has ${dec.outputs.length})`);
      if (dec.txid !== String(txid).trim().toLowerCase())
        throw new Error(`the server returned a transaction whose txid is ${dec.txid}, not the one requested`);
      return {
        txid: dec.txid, vout,
        amount: out.amount,
        scriptPubKey: out.script,
        scriptType: SCRIPT.classify(hexToBytes(out.script)).type,
        prevTxHex: rawHex,
        confirmations: null
      };
    }
  }

  global.NODE = {
    DEFAULT_ENDPOINTS, GENESIS, scriptHash,
    client: new ElectrumClient(),
    ElectrumClient
  };
})(window);
