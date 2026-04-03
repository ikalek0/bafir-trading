// bafir_features_patch.js
// PARCHE PARA bafir-trading — ROI TWR, Alertas Telegram, Informe semanal, Score confianza
// ─────────────────────────────────────────────────────────────────────────────

const https = require('https');

// ══════════════════════════════════════════════════════════════════════════════
// MÓDULO 1: ROI sobre capital aportado — Time-Weighted Return (TWR)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Calcula TWR (Time-Weighted Return) para un cliente o global.
 * TWR elimina el efecto de depósitos/retiros en el rendimiento.
 *
 * Algoritmo:
 *   TWR = (∏ (1 + Rp_i)) - 1
 *   donde Rp_i = rendimiento del sub-período i (entre flujos de capital)
 */
function calcTWR(cashFlows) {
  // cashFlows: [{ date, portfolioValueBefore, cashFlow, portfolioValueAfter }]
  // portfolioValueBefore: valor cartera antes del flujo
  // cashFlow: depósito (+) o retiro (-)
  // portfolioValueAfter: valor cartera después del flujo
  if (!cashFlows || cashFlows.length === 0) return 0;

  let twr = 1;
  for (const flow of cashFlows) {
    const { portfolioValueBefore, cashFlow } = flow;
    const denom = portfolioValueBefore + cashFlow;
    if (denom > 0 && flow.portfolioValueAfter != null) {
      twr *= flow.portfolioValueAfter / denom;
    }
  }
  return twr - 1;
}

/**
 * Calcula ROI simple (capital aportado vs valor actual)
 */
function calcSimpleROI(capitalAportado, valorActual) {
  if (!capitalAportado || capitalAportado <= 0) return 0;
  return (valorActual - capitalAportado) / capitalAportado;
}

/**
 * Calcula ROI y TWR para un cliente dado su historial de movimientos
 */
function calcClientROI(client) {
  const { capitalAportado, valorActual, cashFlows } = client;
  const simpleROI = calcSimpleROI(capitalAportado, valorActual);
  const twr = cashFlows?.length > 0 ? calcTWR(cashFlows) : simpleROI;
  const gananciaAbsoluta = valorActual - capitalAportado;

  return {
    clientId: client.id,
    clientName: client.name,
    capitalAportado,
    valorActual,
    gananciaAbsoluta,
    simpleROI: (simpleROI * 100).toFixed(2) + '%',
    twr: (twr * 100).toFixed(2) + '%',
    twrAnnualized: annualizeReturn(twr, client.daysSinceStart),
  };
}

function annualizeReturn(totalReturn, days) {
  if (!days || days <= 0) return null;
  const annualized = Math.pow(1 + totalReturn, 365 / days) - 1;
  return (annualized * 100).toFixed(2) + '%';
}

// SQL para añadir campos a la tabla de clientes:
const SQL_CLIENT_ROI = `
-- Añadir a tabla clients (si no existen):
ALTER TABLE clients ADD COLUMN IF NOT EXISTS capital_aportado NUMERIC(20,8) DEFAULT 0;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS dias_inicio INTEGER DEFAULT 0;

-- Tabla de movimientos de capital (para TWR preciso):
CREATE TABLE IF NOT EXISTS capital_flows (
  id SERIAL PRIMARY KEY,
  client_id INTEGER REFERENCES clients(id),
  flow_date TIMESTAMPTZ DEFAULT NOW(),
  portfolio_value_before NUMERIC(20,8),
  cash_flow NUMERIC(20,8),          -- positivo = depósito, negativo = retiro
  portfolio_value_after NUMERIC(20,8),
  notes TEXT
);
CREATE INDEX IF NOT EXISTS idx_capital_flows_client ON capital_flows(client_id, flow_date);
`;

// ══════════════════════════════════════════════════════════════════════════════
// MÓDULO 2: Alertas Telegram configurables
// ══════════════════════════════════════════════════════════════════════════════

class TelegramAlerts {
  constructor(botToken, defaultChatId) {
    this.botToken = botToken || process.env.TELEGRAM_BOT_TOKEN;
    this.defaultChatId = defaultChatId || process.env.TELEGRAM_CHAT_ID;
    // { [clientId]: { chatId, gainThreshold, lossThreshold, enabled } }
    this.clientAlerts = {};
    this.sentAlerts = new Set(); // dedup within session
  }

  configureClient(clientId, config) {
    this.clientAlerts[clientId] = {
      chatId: config.chatId || this.defaultChatId,
      gainThreshold: config.gainThreshold || 5,   // % ganancia para alertar
      lossThreshold: config.lossThreshold || -3,  // % pérdida para alertar
      enabled: config.enabled !== false,
    };
  }

  async sendMessage(chatId, message, parseMode = 'HTML') {
    if (!this.botToken) {
      console.warn('[Telegram] Sin token, mensaje no enviado:', message.substring(0, 50));
      return false;
    }
    return new Promise((resolve) => {
      const body = JSON.stringify({ chat_id: chatId, text: message, parse_mode: parseMode });
      const options = {
        hostname: 'api.telegram.org',
        path: `/bot${this.botToken}/sendMessage`,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      };
      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => {
          try {
            const r = JSON.parse(data);
            resolve(r.ok);
          } catch { resolve(false); }
        });
      });
      req.on('error', () => resolve(false));
      req.write(body);
      req.end();
    });
  }

  async checkAndAlert(clientId, currentPnlPct, clientName, botType = 'LIVE') {
    const cfg = this.clientAlerts[clientId];
    if (!cfg?.enabled) return;

    const alertKey = `${clientId}_${Math.floor(currentPnlPct * 10)}_${new Date().toDateString()}`;
    if (this.sentAlerts.has(alertKey)) return;

    const pnlPctNum = parseFloat(currentPnlPct) || 0;

    if (pnlPctNum >= cfg.gainThreshold) {
      const msg = [
        `🟢 <b>BAFIR Trading — Alerta de ganancia</b>`,
        ``,
        `👤 Cliente: <b>${clientName}</b>`,
        `📈 P&L actual: <b>+${pnlPctNum.toFixed(2)}%</b>`,
        `⚠️ Umbral configurado: ${cfg.gainThreshold}%`,
        `🤖 Bot: ${botType}`,
        ``,
        `<i>${new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' })}</i>`,
      ].join('\n');
      await this.sendMessage(cfg.chatId, msg);
      this.sentAlerts.add(alertKey);

    } else if (pnlPctNum <= cfg.lossThreshold) {
      const msg = [
        `🔴 <b>BAFIR Trading — Alerta de pérdida</b>`,
        ``,
        `👤 Cliente: <b>${clientName}</b>`,
        `📉 P&L actual: <b>${pnlPctNum.toFixed(2)}%</b>`,
        `⚠️ Umbral configurado: ${cfg.lossThreshold}%`,
        `🤖 Bot: ${botType}`,
        ``,
        `<i>${new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' })}</i>`,
      ].join('\n');
      await this.sendMessage(cfg.chatId, msg);
      this.sentAlerts.add(alertKey);
    }
  }

  // Alert on significant bot event
  async alertBotEvent(event, details = {}) {
    if (!this.defaultChatId) return;
    const icons = { trade_open: '📊', trade_close: '✅', circuit_breaker: '🚨', sync_update: '🔄', error: '❌' };
    const icon = icons[event] || 'ℹ️';
    const msg = [
      `${icon} <b>BAFIR — ${event.replace(/_/g, ' ').toUpperCase()}</b>`,
      ...Object.entries(details).map(([k, v]) => `• ${k}: <b>${v}</b>`),
      `<i>${new Date().toLocaleString('es-ES', { timeZone: 'Europe/Madrid' })}</i>`,
    ].join('\n');
    await this.sendMessage(this.defaultChatId, msg);
  }

  toJSON() { return { clientAlerts: this.clientAlerts }; }
  loadJSON(data) { if (data?.clientAlerts) this.clientAlerts = data.clientAlerts; }
}

// ══════════════════════════════════════════════════════════════════════════════
// MÓDULO 3: Informe semanal automático — cada lunes
// ══════════════════════════════════════════════════════════════════════════════

class WeeklyReporter {
  constructor(telegram, db) {
    this.telegram = telegram;
    this.db = db; // BafirDB instance
    this.lastReportDate = null;
    this.scheduled = false;
  }

  start() {
    if (this.scheduled) return;
    this.scheduled = true;
    setInterval(() => this._checkAndSend(), 60 * 60 * 1000);
    console.log('[WeeklyReport] Scheduler iniciado — informe cada lunes 8:00');
  }

  _checkAndSend() {
    const now = new Date();
    const isMonday = now.getDay() === 1;
    const isMorning = now.getHours() === 8;
    const dateStr = now.toDateString();
    if (isMonday && isMorning && this.lastReportDate !== dateStr) {
      this.lastReportDate = dateStr;
      this.generateAndSend().catch(e => console.error('[WeeklyReport] Error:', e.message));
    }
  }

  async generateAndSend() {
    console.log('[WeeklyReport] Generando informe semanal...');
    try {
      const report = await this._buildReport();
      if (!report) { console.log('[WeeklyReport] Sin datos suficientes'); return; }
      await this.telegram.sendMessage(this.telegram.defaultChatId, report);
      console.log('[WeeklyReport] Informe enviado');
    } catch (e) {
      console.error('[WeeklyReport] Error:', e.message);
    }
  }

  async _buildReport() {
    if (!this.telegram.defaultChatId) return null;

    // Obtener equity de bots desde BafirDB
    const botEquity = this.db.db?.botEquity || [];
    const since = Date.now() - 7 * 24 * 3600 * 1000;

    const liveEq  = botEquity.filter(e=>e.source==="live"  && e.ts>=since).map(e=>e.value);
    const paperEq = botEquity.filter(e=>e.source==="paper" && e.ts>=since).map(e=>e.value);

    const calcReturn = arr => arr.length>=2 ? ((arr[arr.length-1]-arr[0])/arr[0]*100).toFixed(2) : null;

    // Clientes
    const clients = (this.db.db?.clients||[]).filter(c=>c.active!==false);

    const week = new Date().toLocaleDateString('es-ES', {weekday:'long',day:'numeric',month:'long'});
    const lines = [`📊 <b>BAFIR Trading — Informe Semanal</b>`, `📅 Semana hasta el ${week}`, ``];

    const liveRet  = calcReturn(liveEq);
    const paperRet = calcReturn(paperEq);
    if (liveRet  !== null) lines.push(`${parseFloat(liveRet)>=0?"📈":"📉"} <b>Bot LIVE:</b>  ${liveRet}% esta semana`);
    if (paperRet !== null) lines.push(`${parseFloat(paperRet)>=0?"📈":"📉"} <b>Bot PAPER:</b> ${paperRet}% esta semana`);

    if (clients.length) {
      lines.push(``, `👥 <b>Clientes activos (${clients.length}):</b>`);
      for (const c of clients.slice(0, 8)) {
        const cap = c.capitalAportado || c.capital_aportado || c.totalDeposited || 0;
        const val = c.balance || c.totalValue || 0;
        const roi = cap > 0 ? ((val-cap)/cap*100).toFixed(1)+"%" : "N/A";
        lines.push(`   • ${c.name}: $${parseFloat(val).toFixed(0)} (ROI: ${roi})`);
      }
    }

    lines.push(``, `<i>Próximo informe: ${getNextMonday()}</i>`);
    return lines.join('\n');
  }
}

function getNextMonday() {
  const d = new Date();
  const daysUntilMonday = (8 - d.getDay()) % 7 || 7;
  d.setDate(d.getDate() + daysUntilMonday);
  return d.toLocaleDateString('es-ES', { weekday: 'long', day: 'numeric', month: 'long' });
}

// ══════════════════════════════════════════════════════════════════════════════
// MÓDULO 4: Score de confianza visible en dashboard (frontend snippet)
// ══════════════════════════════════════════════════════════════════════════════

const DASHBOARD_CONFIDENCE_WIDGET = `
<!-- Añadir en el panel de admin, sección de bots -->
<div class="confidence-panel">
  <div class="confidence-item" id="live-confidence">
    <span class="bot-label">🔴 LIVE Bot</span>
    <div class="score-bar">
      <div class="score-fill" id="live-score-fill"></div>
    </div>
    <span class="score-value" id="live-score-text">—</span>
    <span class="score-label" id="live-score-label">—</span>
  </div>
  <div class="confidence-item" id="paper-confidence">
    <span class="bot-label">🟢 PAPER Bot</span>
    <div class="score-bar">
      <div class="score-fill" id="paper-score-fill"></div>
    </div>
    <span class="score-value" id="paper-score-text">—</span>
    <span class="score-label" id="paper-score-label">—</span>
  </div>
</div>

<style>
.confidence-panel { display: flex; gap: 20px; margin: 16px 0; }
.confidence-item { flex: 1; background: rgba(255,255,255,0.05); border-radius: 12px; padding: 16px; }
.bot-label { font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; }
.score-bar { background: rgba(255,255,255,0.1); border-radius: 4px; height: 8px; margin: 10px 0 6px; overflow: hidden; }
.score-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; }
.score-value { font-size: 1.8rem; font-weight: 700; display: block; }
.score-label { font-size: 0.75rem; opacity: 0.7; }
</style>

<script>
async function updateConfidenceScores() {
  try {
    const [live, paper] = await Promise.all([
      fetch(LIVE_BOT_URL + '/confidence').then(r => r.json()).catch(() => null),
      fetch(PAPER_BOT_URL + '/confidence').then(r => r.json()).catch(() => null),
    ]);
    
    if (live) {
      document.getElementById('live-score-text').textContent = live.score;
      document.getElementById('live-score-label').textContent = live.label;
      const fill = document.getElementById('live-score-fill');
      fill.style.width = live.score + '%';
      fill.style.background = live.color;
    }
    if (paper) {
      document.getElementById('paper-score-text').textContent = paper.score;
      document.getElementById('paper-score-label').textContent = paper.label;
      const fill = document.getElementById('paper-score-fill');
      fill.style.width = paper.score + '%';
      fill.style.background = paper.color;
    }
  } catch(e) {}
}
setInterval(updateConfidenceScores, 30000);
updateConfidenceScores();
</script>
`;

// ══════════════════════════════════════════════════════════════════════════════
// MÓDULO 5: Endpoints API para bafir-trading/server.js
// ══════════════════════════════════════════════════════════════════════════════

const API_ENDPOINTS_SNIPPET = `
// ── ROI endpoints ─────────────────────────────────────────────────────────────
app.get('/api/clients/roi', requireAuth, async (req, res) => {
  try {
    const clients = await db.query(
      \`SELECT c.id, c.name, c.balance, c.capital_aportado,
              EXTRACT(DAY FROM NOW() - c.created_at) as dias_inicio,
              COALESCE(
                json_agg(json_build_object(
                  'portfolioValueBefore', cf.portfolio_value_before,
                  'cashFlow', cf.cash_flow,
                  'portfolioValueAfter', cf.portfolio_value_after
                ) ORDER BY cf.flow_date) FILTER (WHERE cf.id IS NOT NULL), '[]'
              ) as cash_flows
       FROM clients c
       LEFT JOIN capital_flows cf ON cf.client_id = c.id
       WHERE c.active = true
       GROUP BY c.id, c.name, c.balance, c.capital_aportado, c.created_at\`
    );
    
    const roiData = clients.rows.map(c => calcClientROI({
      id: c.id, name: c.name,
      capitalAportado: parseFloat(c.capital_aportado) || 0,
      valorActual: parseFloat(c.balance) || 0,
      cashFlows: c.cash_flows || [],
      daysSinceStart: parseInt(c.dias_inicio) || 0,
    }));
    
    // Global TWR
    const totalCapital = clients.rows.reduce((s, c) => s + parseFloat(c.capital_aportado || 0), 0);
    const totalValue = clients.rows.reduce((s, c) => s + parseFloat(c.balance || 0), 0);
    
    res.json({
      clients: roiData,
      global: {
        totalCapital: totalCapital.toFixed(2),
        totalValue: totalValue.toFixed(2),
        globalROI: calcSimpleROI(totalCapital, totalValue),
        globalROIPct: (calcSimpleROI(totalCapital, totalValue) * 100).toFixed(2) + '%',
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Telegram alert config ─────────────────────────────────────────────────────
app.post('/api/clients/:id/alerts', requireAuth, async (req, res) => {
  const { gainThreshold, lossThreshold, chatId, enabled } = req.body;
  telegramAlerts.configureClient(req.params.id, { gainThreshold, lossThreshold, chatId, enabled });
  // Persist to DB
  await db.query(
    \`INSERT INTO client_alert_config (client_id, gain_threshold, loss_threshold, chat_id, enabled)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (client_id) DO UPDATE SET gain_threshold=$2, loss_threshold=$3, chat_id=$4, enabled=$5\`,
    [req.params.id, gainThreshold, lossThreshold, chatId, enabled !== false]
  );
  res.json({ success: true });
});

// ── Manual trigger weekly report ──────────────────────────────────────────────
app.post('/api/reports/weekly', requireAdmin, async (req, res) => {
  weeklyReporter.generateAndSend().catch(console.error);
  res.json({ success: true, message: 'Informe en proceso de envío' });
});
`;

module.exports = {
  calcTWR, calcSimpleROI, calcClientROI,
  TelegramAlerts, WeeklyReporter,
  SQL_CLIENT_ROI, DASHBOARD_CONFIDENCE_WIDGET, API_ENDPOINTS_SNIPPET,
};
