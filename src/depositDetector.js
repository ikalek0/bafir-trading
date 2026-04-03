// depositDetector.js — Detecta ingresos reales en Binance y los pone en cola para distribuir
// Polling cada 5 min del historial de depósitos de Binance (endpoint público con API key)
"use strict";

const https = require("https");
const crypto = require("crypto");

class DepositDetector {
  constructor({ apiKey, apiSecret, onDeposit }) {
    this.apiKey    = apiKey    || process.env.BINANCE_API_KEY    || "";
    this.apiSecret = apiSecret || process.env.BINANCE_API_SECRET || "";
    this.onDeposit = onDeposit; // callback(deposit)
    this.seenIds   = new Set(); // IDs ya procesados
    this.pending   = [];        // depósitos pendientes de distribución
    this.lastCheck = 0;
    this.intervalId = null;
    this.enabled = !!(this.apiKey && this.apiSecret);
  }

  start(intervalMs = 5 * 60 * 1000) {
    if (!this.enabled) {
      console.log("[DepositDetector] Sin credenciales Binance — detector desactivado");
      return;
    }
    console.log("[DepositDetector] Iniciado — polling cada", intervalMs / 60000, "min");
    this._check();
    this.intervalId = setInterval(() => this._check(), intervalMs);
  }

  stop() {
    if (this.intervalId) clearInterval(this.intervalId);
  }

  async _check() {
    if (!this.enabled) return;
    try {
      // Obtener depósitos de los últimos 7 días
      const since = Date.now() - 7 * 24 * 3600 * 1000;
      const deposits = await this._fetchDeposits(since);
      let newFound = 0;
      for (const dep of deposits) {
        // Solo depósitos completados (status=1)
        if (dep.status !== 1) continue;
        const id = dep.id || dep.txId || `${dep.amount}_${dep.insertTime}`;
        if (this.seenIds.has(id)) continue;
        this.seenIds.add(id);
        // Evitar duplicados en pending
        if (this.pending.find(p => p.id === id)) continue;
        const item = {
          id,
          asset:      dep.coin || dep.asset || "USDT",
          amount:     parseFloat(dep.amount),
          amountUSD:  await this._toUSD(dep.coin || dep.asset, parseFloat(dep.amount)),
          txId:       dep.txId || "",
          network:    dep.network || "",
          address:    dep.address || "",
          insertTime: dep.insertTime || Date.now(),
          distributed: false,
        };
        this.pending.push(item);
        newFound++;
        console.log(`[DepositDetector] Nuevo ingreso: ${item.amount} ${item.asset} (~$${item.amountUSD.toFixed(2)})`);
        if (this.onDeposit) this.onDeposit(item);
      }
      this.lastCheck = Date.now();
      if (newFound) console.log(`[DepositDetector] ${newFound} nuevo(s) ingreso(s) pendiente(s) de distribución`);
    } catch (e) {
      console.warn("[DepositDetector] Error al consultar Binance:", e.message);
    }
  }

  async _fetchDeposits(since) {
    const params = { startTime: since, status: 1, timestamp: Date.now(), recvWindow: 10000 };
    const query  = new URLSearchParams(params).toString();
    const sig    = crypto.createHmac("sha256", this.apiSecret).update(query).digest("hex");
    const url    = `https://api.binance.com/sapi/v1/capital/deposit/hisrec?${query}&signature=${sig}`;
    return new Promise((resolve, reject) => {
      https.get(url, { headers: { "X-MBX-APIKEY": this.apiKey }, timeout: 8000 }, res => {
        let d = "";
        res.on("data", c => d += c);
        res.on("end", () => {
          try {
            const parsed = JSON.parse(d);
            if (Array.isArray(parsed)) resolve(parsed);
            else reject(new Error(parsed.msg || "Respuesta inesperada"));
          } catch (e) { reject(e); }
        });
      }).on("error", reject);
    });
  }

  async _toUSD(asset, amount) {
    if (!asset || asset === "USDT" || asset === "USDC" || asset === "BUSD") return amount;
    try {
      const price = await new Promise((resolve, reject) => {
        https.get(`https://api.binance.com/api/v3/ticker/price?symbol=${asset}USDT`, { timeout: 4000 }, res => {
          let d = "";
          res.on("data", c => d += c);
          res.on("end", () => {
            try { resolve(parseFloat(JSON.parse(d).price) || 1); }
            catch { resolve(1); }
          });
        }).on("error", () => resolve(1));
      });
      return amount * price;
    } catch { return amount; }
  }

  getPending() {
    return this.pending.filter(p => !p.distributed);
  }

  markDistributed(id) {
    const p = this.pending.find(p => p.id === id);
    if (p) p.distributed = true;
    // Limpiar los distribuidos viejos (>30 días)
    const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
    this.pending = this.pending.filter(p => !p.distributed || p.insertTime > cutoff);
  }

  toJSON() {
    return { seenIds: [...this.seenIds].slice(-500), pending: this.pending };
  }

  loadJSON(data) {
    if (!data) return;
    if (data.seenIds) data.seenIds.forEach(id => this.seenIds.add(id));
    if (data.pending) this.pending = data.pending;
  }
}

module.exports = { DepositDetector };
