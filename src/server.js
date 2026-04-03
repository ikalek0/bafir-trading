// ─── BAFIR TRADING v5 — MÁXIMA SEGURIDAD ─────────────────────────────────────
"use strict";

const express  = require("express");
const http     = require("http");
const path     = require("path");
const https    = require("https");
const crypto   = require("crypto");
const { BafirDB }    = require("./data");
const { rateLimiter, securityHeaders, corsRestricted, validateInput, securityLogger, sanitizeBody } = require("./security");
const { generateSecret, verifyToken, getQRUrl } = require("./totp");
const { log: auditLog, getRecent: getAuditLog, auditMiddleware } = require("./audit");
const { decrypt } = require("./encryption");
const { TelegramAlerts, WeeklyReporter, calcClientROI, calcSimpleROI } = require("./bafir_features_patch");
const { DepositDetector } = require("./depositDetector");

const PORT           = process.env.PORT    || 3001;
const BOT_SECRET     = process.env.BOT_SECRET     || "bafir_bot_secret";
const ALLOWED_ORIGINS= (process.env.ALLOWED_ORIGINS||"").split(",").filter(Boolean);
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // opcional, mejora el cifrado

const app = express();
const db  = new BafirDB();
const telegramAlerts  = new TelegramAlerts(process.env.TELEGRAM_TOKEN, process.env.TELEGRAM_CHAT_ID);
const weeklyReporter  = new WeeklyReporter(telegramAlerts, db);
weeklyReporter.start();

// WebSocket para notificaciones en tiempo real al admin
const { WebSocketServer, WebSocket } = require("ws");
const httpServer = http.createServer(app);
const wss = new WebSocketServer({ server: httpServer });
function broadcastAdmin(msg) {
  const d = JSON.stringify(msg);
  wss.clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(d); });
}

// Detector de depósitos Binance
const depositDetector = new DepositDetector({
  apiKey:    process.env.BINANCE_API_KEY,
  apiSecret: process.env.BINANCE_API_SECRET,
  onDeposit: (dep) => {
    // Persistir inmediatamente en disco
    db.db.depositDetector = depositDetector.toJSON();
    db.saveEquity();
    // Notificar al admin vía WebSocket en tiempo real
    broadcastAdmin({ type: "new_deposit", deposit: dep });
    // También por Telegram
    if (process.env.TELEGRAM_TOKEN && process.env.TELEGRAM_CHAT_ID) {
      telegramAlerts.sendMessage(process.env.TELEGRAM_CHAT_ID,
        `💰 <b>Nuevo ingreso detectado en Binance</b>\n\n` +
        `💵 Cantidad: <b>${dep.amount} ${dep.asset}</b> (~$${dep.amountUSD.toFixed(2)})\n` +
        `🔗 TxID: <code>${dep.txId||"—"}</code>\n` +
        `⏳ Pendiente de distribución en BAFIR`
      );
    }
  }
});
// Cargar estado persistido y arrancar
const savedDetector = db.db.depositDetector;
if (savedDetector) depositDetector.loadJSON(savedDetector);
depositDetector.start(5 * 60 * 1000); // polling cada 5 min

// Guardar estado del detector cada 10 min
setInterval(() => {
  db.db.depositDetector = depositDetector.toJSON();
  db.saveEquity();
}, 10 * 60 * 1000);

// ── Middlewares globales ──────────────────────────────────────────────────────
app.use(securityLogger);
app.use(auditMiddleware);
app.use(securityHeaders);
app.use(corsRestricted(ALLOWED_ORIGINS));
app.use(express.json({ limit:"100kb" }));
app.use(express.static(path.join(__dirname,"../public/shared"), { maxAge:"1d" }));

// ── Rate limiters ─────────────────────────────────────────────────────────────
const loginRL = rateLimiter.limit({ maxAttempts:5,  windowMs:15*60*1000, message:"Demasiados intentos. Espera 15 minutos." });
const apiRL   = rateLimiter.limit({ maxAttempts:200, windowMs:60*1000 });
const botRL   = rateLimiter.limit({ maxAttempts:120, windowMs:60*1000 });

// ── Sessions ──────────────────────────────────────────────────────────────────
const sessions      = {};
const SESSION_TTL   = 8 * 3600 * 1000;
const WARN_BEFORE   = 5 * 60 * 1000; // avisar 5 min antes de expirar

// Estado de 2FA pendiente (antes de completar login)
const pending2FA = {}; // { tempToken: { expiresAt } }

function createSession(role, clientId=null) {
  Object.keys(sessions).forEach(t => { const s=sessions[t]; if(s.role===role&&s.clientId===clientId) delete sessions[t]; });
  const token = crypto.randomBytes(48).toString("hex");
  sessions[token] = { role, clientId, expiresAt:Date.now()+SESSION_TTL, createdAt:Date.now() };
  return token;
}

function getSession(req) {
  const auth  = (req.headers.authorization||"").replace("Bearer ","").trim();
  if (!auth||auth.length<90) return null;
  const sess  = sessions[auth];
  if (!sess) return null;
  if (sess.expiresAt < Date.now()) { delete sessions[auth]; return null; }
  // Añadir info de expiración próxima
  sess.expiresInMs = sess.expiresAt - Date.now();
  sess.warnExpiry  = sess.expiresInMs < WARN_BEFORE;
  return sess;
}

setInterval(() => { const now=Date.now(); Object.keys(sessions).forEach(t=>{if(sessions[t].expiresAt<now)delete sessions[t];}); Object.keys(pending2FA).forEach(t=>{if(pending2FA[t].expiresAt<now)delete pending2FA[t];}); }, 3600000);

function requireAdmin(req, res, next) {
  const sess = getSession(req);
  if (sess?.role!=="admin") { auditLog("UNAUTHORIZED",{path:req.path},req); return res.status(401).json({error:"No autorizado"}); }
  req.session = sess;
  // IP whitelist check
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()||req.socket?.remoteAddress||"";
  if (!db.isIPAllowed(ip)) { auditLog("IP_BLOCKED",{ip,path:req.path},req); return res.status(403).json({error:"IP no autorizada"}); }
  next();
}

function requireClient(req, res, next) {
  const s = getSession(req);
  if (!s||(s.role!=="client"&&s.role!=="admin")) return res.status(401).json({error:"No autorizado"});
  req.session=s; next();
}

// ── AUTH ──────────────────────────────────────────────────────────────────────

// Paso 1: verificar contraseña
app.post("/api/auth/admin", loginRL,
  sanitizeBody(["password"]),
  validateInput({ password:{required:true,type:"string",maxLength:200} }),
  (req,res) => {
    const reqIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()||req.socket?.remoteAddress||"";
    if (!db.verifyAdmin(req.body.password)) {
      auditLog("LOGIN_FAIL",{role:"admin",ip:reqIp},req);
      return res.status(401).json({error:"Contraseña incorrecta"});
    }
    // ¿Tiene 2FA activado?
    if (db.is2FAEnabled()) {
      const tempToken = crypto.randomBytes(32).toString("hex");
      pending2FA[tempToken] = { expiresAt: Date.now()+5*60*1000 }; // 5 min para introducir el código
      auditLog("LOGIN_PENDING_2FA",{ip:reqIp},req);
      return res.json({ require2FA:true, tempToken });
    }
    // Sin 2FA — login directo
    // Login exitoso — notificar por Telegram (reqIp ya declarado arriba)
    const tgToken = process.env.TELEGRAM_TOKEN||"";
    const tgChat  = process.env.TELEGRAM_CHAT_ID||"";
    if(tgToken&&tgChat) {
      const body=JSON.stringify({chat_id:tgChat,text:`🔐 <b>Acceso a BAFIR</b>\nIP: ${reqIp}\n${new Date().toLocaleString("es-ES")}`,parse_mode:"HTML"});
      https.request({hostname:"api.telegram.org",path:`/bot${tgToken}/sendMessage`,method:"POST",headers:{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body)}},()=>{}).end(body);
    }
    auditLog("LOGIN_OK",{role:"admin",ip:reqIp},req);
    res.json({ token:createSession("admin"), role:"admin" });
  }
);

// Paso 2: verificar código 2FA
app.post("/api/auth/admin/2fa", loginRL,
  validateInput({ tempToken:{required:true,type:"string"}, code:{required:true,type:"string",maxLength:10} }),
  (req,res) => {
    const reqIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim()||req.socket?.remoteAddress||"";
    const { tempToken, code } = req.body;
    const pending = pending2FA[tempToken];
    if (!pending||pending.expiresAt<Date.now()) {
      auditLog("2FA_EXPIRED",{ip:reqIp},req);
      return res.status(401).json({error:"Sesión expirada. Vuelve a introducir tu contraseña."});
    }
    if (!verifyToken(db.get2FASecret(), code.replace(/\s/g,""))) {
      auditLog("2FA_FAIL",{ip:reqIp},req);
      return res.status(401).json({error:"Código incorrecto"});
    }
    delete pending2FA[tempToken];
    auditLog("LOGIN_OK_2FA",{role:"admin",ip:reqIp},req);
    res.json({ token:createSession("admin"), role:"admin" });
  }
);

app.post("/api/auth/client", loginRL,
  sanitizeBody(["clientId","password"]),
  validateInput({ clientId:{required:true,type:"string",maxLength:50}, password:{required:true,type:"string",maxLength:200} }),
  (req,res) => {
    const {clientId,password}=req.body;
    if (!db.verifyClient(clientId,password)) {
      auditLog("LOGIN_FAIL",{role:"client",clientId},req);
      return res.status(401).json({error:"Credenciales incorrectas"});
    }
    auditLog("LOGIN_OK",{role:"client",clientId},req);
    res.json({token:createSession("client",clientId),role:"client",clientId});
  }
);

app.post("/api/auth/logout",(req,res)=>{ delete sessions[(req.headers.authorization||"").replace("Bearer ","")]; res.json({ok:true}); });
app.get("/api/auth/me",(req,res)=>{ const s=getSession(req); if(!s) return res.status(401).json({error:"No autenticado"}); res.json({role:s.role,clientId:s.clientId,expiresInMs:s.expiresInMs,warnExpiry:s.warnExpiry}); });

// Renovar sesión (reset TTL)
app.post("/api/auth/renew", requireAdmin, (req,res) => {
  const auth = (req.headers.authorization||"").replace("Bearer ","");
  if (sessions[auth]) { sessions[auth].expiresAt = Date.now()+SESSION_TTL; }
  res.json({ok:true, expiresAt: sessions[auth]?.expiresAt});
});

// ── 2FA SETUP ─────────────────────────────────────────────────────────────────
app.get("/api/admin/2fa/setup", apiRL, requireAdmin, (req,res) => {
  const secret = generateSecret();
  const qrUrl  = getQRUrl(secret);
  // Guardamos temporalmente el secreto (no activado aún hasta verificar)
  req._2faSetupSecret = secret;
  res.json({ secret, qrUrl, status: db.get2FAStatus() });
});

app.post("/api/admin/2fa/enable", apiRL, requireAdmin,
  validateInput({ secret:{required:true,type:"string"}, code:{required:true,type:"string",maxLength:10} }),
  (req,res) => {
    const {secret,code}=req.body;
    if (!verifyToken(secret, code.replace(/\s/g,""))) {
      auditLog("2FA_SETUP_FAIL",{},req);
      return res.status(400).json({error:"Código incorrecto. Escanea el QR de nuevo."});
    }
    db.enable2FA(secret);
    auditLog("2FA_ENABLED",{},req);
    res.json({ok:true, message:"2FA activado correctamente"});
  }
);

app.post("/api/admin/2fa/disable", apiRL, requireAdmin,
  validateInput({ code:{required:true,type:"string",maxLength:10} }),
  (req,res) => {
    if (!verifyToken(db.get2FASecret(), req.body.code.replace(/\s/g,""))) {
      return res.status(400).json({error:"Código incorrecto"});
    }
    db.disable2FA();
    auditLog("2FA_DISABLED",{},req);
    res.json({ok:true});
  }
);

// ── IP WHITELIST ──────────────────────────────────────────────────────────────
app.get("/api/admin/security/ips",     apiRL, requireAdmin, (req,res)=>res.json(db.getIPWhitelist()));
app.post("/api/admin/security/ips",    apiRL, requireAdmin, validateInput({ip:{required:true,type:"string",maxLength:50}}), (req,res)=>{ db.addIP(req.body.ip,req.body.label||""); auditLog("IP_ADDED",{ip:req.body.ip},req); res.json({ok:true}); });
app.delete("/api/admin/security/ips/:ip", apiRL, requireAdmin, (req,res)=>{ db.removeIP(decodeURIComponent(req.params.ip)); res.json({ok:true}); });

// Mi IP actual (para añadirla fácilmente)
app.get("/api/admin/security/myip", requireAdmin, (req,res)=>{ const ip=req.headers["x-forwarded-for"]?.split(",")[0]?.trim()||req.socket?.remoteAddress||""; res.json({ip}); });

// ── AUDIT LOG ─────────────────────────────────────────────────────────────────
app.get("/api/admin/audit", apiRL, requireAdmin, (req,res)=>{ const n=Math.min(+(req.query.n||100),500); res.json(getAuditLog(n)); });

// ── ADMIN API ─────────────────────────────────────────────────────────────────
app.get("/api/admin/metrics",  apiRL, requireAdmin, (req,res)=>res.json(db.getGlobalMetrics()));

app.get("/api/admin/clients",  apiRL, requireAdmin, (req,res)=>{
  const fx=db.fxRate,eq=db.db.botEquity||[],last=(eq.filter(e=>e.source==="live").pop()||{value:10000}).value;
  res.json(db.getClients().map(c=>{
    const valUSD=last*(c.share||0)/100,depUSD=c.deposits.reduce((s,d)=>s+(d.currency==="EUR"?d.amount*fx:d.amount),0);
    return {id:c.id,name:c.name,email:c.email,share:c.share,active:c.active,createdAt:c.createdAt,currency:c.currency,depositMode:c.depositMode,nDeposits:c.deposits.length,totalDepDisplay:c.currency==="EUR"?+(depUSD/fx).toFixed(2):+depUSD.toFixed(2),valueDisplay:c.currency==="EUR"?+(valUSD/fx).toFixed(2):+valUSD.toFixed(2),pnlPct:depUSD>0?+((valUSD-depUSD)/depUSD*100).toFixed(2):0,distributionEnabled:c.distribution?.enabled||false,binanceConnected:!!(c.binanceApiKey&&c.binanceApiSecret)};
  }));
});

app.post("/api/admin/clients", apiRL, requireAdmin,
  sanitizeBody(["name","email","notes"]),
  validateInput({name:{required:true,type:"string",maxLength:100},email:{required:true,type:"string",maxLength:200},password:{required:true,type:"string",maxLength:200}}),
  (req,res)=>{ const{name,email,password,notes,currency,phone,depositMode,startDate}=req.body; auditLog("CLIENT_CREATED",{name,email},req); res.json({id:db.createClient({name,email,password,notes,currency:currency||"EUR",phone:phone||"",depositMode:depositMode||"managed",startDate:startDate||""})}); }
);

app.put("/api/admin/clients/:id",  apiRL, requireAdmin, (req,res)=>{ auditLog("CLIENT_UPDATED",{id:req.params.id},req); res.json({ok:db.updateClient(req.params.id,req.body)}); });
app.get("/api/admin/clients/:id/metrics", apiRL, requireAdmin, (req,res)=>{ const m=db.getClientMetrics(req.params.id); if(!m) return res.status(404).json({error:"No encontrado"}); res.json(m); });

app.post("/api/admin/clients/:id/deposits",   apiRL, requireAdmin, validateInput({amount:{required:true,type:"number",min:0.01},currency:{required:true}}), (req,res)=>{ auditLog("DEPOSIT_ADDED",{clientId:req.params.id,amount:req.body.amount},req); res.json({ok:db.addDeposit(req.params.id,req.body)}); });
app.delete("/api/admin/clients/:id/deposits/:did", apiRL, requireAdmin, (req,res)=>{ auditLog("DEPOSIT_REMOVED",{clientId:req.params.id,depId:req.params.did},req); res.json({ok:db.removeDeposit(req.params.id,req.params.did)}); });
app.post("/api/admin/clients/:id/withdrawals", apiRL, requireAdmin, validateInput({amount:{required:true,type:"number",min:0.01}}), (req,res)=>res.json({ok:db.addWithdrawal(req.params.id,req.body)}));
app.post("/api/admin/clients/:id/disbursements", apiRL, requireAdmin, validateInput({type:{required:true,type:"string",maxLength:30},amount:{required:true,type:"number",min:0.01}}), (req,res)=>{ auditLog("DISBURSEMENT",{clientId:req.params.id,...req.body},req); res.json({ok:db.addDisbursement(req.params.id,req.body)}); });
app.delete("/api/admin/clients/:id/disbursements/:did", apiRL, requireAdmin, (req,res)=>res.json({ok:db.removeDisbursement(req.params.id,req.params.did)}));
app.post("/api/admin/clients/:id/distributions/pay", apiRL, requireAdmin, (req,res)=>res.json({ok:db.markDistributionPaid(req.params.id,req.body.periodDate)}));
app.put("/api/admin/clients/:id/distribution", apiRL, requireAdmin, (req,res)=>res.json({ok:db.updateClient(req.params.id,{distribution:req.body})}));

app.post("/api/admin/password", apiRL, requireAdmin,
  validateInput({newPassword:{required:true,type:"string",maxLength:200}}),
  (req,res)=>{ if(req.body.newPassword.length<8) return res.status(400).json({error:"Mínimo 8 caracteres"}); db.setAdminPw(req.body.newPassword); auditLog("PASSWORD_CHANGED",{},req); res.json({ok:true}); }
);

// Binance balance — usa claves descifradas
app.post("/api/admin/clients/:id/binance-balance", apiRL, requireAdmin, async (req,res)=>{
  const keys=db.getDecryptedKeys(req.params.id);
  if(!keys?.apiKey) return res.status(400).json({error:"Sin API keys"});
  try {
    const ts=Date.now(),q=`timestamp=${ts}`,sig=crypto.createHmac("sha256",keys.apiSecret).update(q).digest("hex");
    const account=await new Promise((resolve,reject)=>{
      const r=https.get(`https://api.binance.com/api/v3/account?${q}&signature=${sig}`,{headers:{"X-MBX-APIKEY":keys.apiKey},timeout:6000},res2=>{let d="";res2.on("data",c=>d+=c);res2.on("end",()=>{try{resolve(JSON.parse(d))}catch(e){reject(e)}});});
      r.on("error",reject);
    });
    if(account.code) return res.status(400).json({error:"Error de Binance"});
    let total=0;
    for(const b of(account.balances||[]).filter(b=>parseFloat(b.free)+parseFloat(b.locked)>0)){
      const amt=parseFloat(b.free)+parseFloat(b.locked);
      if(["USDT","BUSD","USDC","DAI"].includes(b.asset)){total+=amt;continue;}
      try{const p=await new Promise((resolve,reject)=>{const r=https.get(`https://api.binance.com/api/v3/ticker/price?symbol=${b.asset}USDT`,{timeout:3000},res2=>{let d="";res2.on("data",c=>d+=c);res2.on("end",()=>{try{resolve(JSON.parse(d))}catch(e){reject(e)}});});r.on("error",reject);});if(p.price)total+=amt*parseFloat(p.price);}catch{}
    }
    res.json({totalUSDT:+total.toFixed(2)});
  }catch(e){res.status(500).json({error:"Error al consultar Binance"});}
});

// ── CAPITAL DEL GESTOR ────────────────────────────────────────────────────────
// ── Configuración de alertas ───────────────────────────────────────────────────
app.get("/api/admin/alert-config", apiRL, requireAdmin, (_,res) => {
  const cfg = db.db.alertConfig || {winPct:3, lossPct:3, paperWinPct:5, paperLossPct:4};
  res.json(cfg);
});
app.post("/api/admin/alert-config", apiRL, requireAdmin,
  validateInput({winPct:{type:"number",min:0.5,max:20},lossPct:{type:"number",min:0.5,max:20}}),
  (req,res) => {
    const cfg = {
      winPct:  +req.body.winPct  || 3,
      lossPct: +req.body.lossPct || 3,
      paperWinPct:  +req.body.paperWinPct  || 5,
      paperLossPct: +req.body.paperLossPct || 4,
    };
    db.db.alertConfig = cfg;
    const save = require("./data"); // already loaded
    db.saveAlertConfig && db.saveAlertConfig(cfg);
    // Push config to both bots
    const BOT_SECRET = process.env.BOT_SECRET||"bafir_bot_secret";
    const body = JSON.stringify({secret:BOT_SECRET, alertConfig:cfg});
    for(const url of [process.env.PAPER_BOT_URL, process.env.LIVE_BOT_URL||""].filter(Boolean)) {
      try {
        const mod2 = url.startsWith("https")?require("https"):require("http");
        const u = new URL("/api/set-alert-config", url);
        const r2 = mod2.request({hostname:u.hostname,path:u.pathname,method:"POST",
          headers:{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body)}},()=>{});
        r2.on("error",()=>{}); r2.write(body); r2.end();
      } catch(e) {}
    }
    res.json({ok:true, cfg});
  }
);

app.get("/api/admin/manager-capital",  apiRL, requireAdmin, (_,res)=>res.json(db.getManagerCapital()));
app.post("/api/admin/manager-capital", apiRL, requireAdmin,
  validateInput({amount:{required:true,type:"number",min:0}}),
  async (req,res)=>{
    const amount = +req.body.amount;
    const currency = req.body.currency||"EUR";
    const note = req.body.note||"";
    const fx = db.fxRate||1.08;
    const amountUSD = currency==="EUR" ? amount*fx : amount;

    // Verificar que el live bot tiene suficiente balance real
    const LIVE_URL = process.env.LIVE_BOT_URL||"";
    if (LIVE_URL) {
      try {
        const liveState = await new Promise((resolve) => {
          const mod = LIVE_URL.startsWith("https") ? https : require("http");
          mod.get(LIVE_URL+"/api/summary", {timeout:5000}, r => {
            let d=""; r.on("data",c=>d+=c);
            r.on("end",()=>{ try{resolve(JSON.parse(d));}catch{resolve(null);} });
          }).on("error",()=>resolve(null));
        });

        // Si el bot está en modo LIVE real, verificar que hay suficiente balance
        if (liveState && liveState.instance==="LIVE") {
          const realBalance = liveState.cash + Object.values(liveState.portfolio||{})
            .reduce((s,p)=>s+(p.qty*(liveState.prices?.[p.symbol]||p.entryPrice)),0);
          if (realBalance < amountUSD * 0.90) { // 10% tolerancia
            return res.status(400).json({
              error: `Balance insuficiente en Binance. Tienes ~$${realBalance.toFixed(2)} pero declaras $${amountUSD.toFixed(2)}. Añade más USDC a Binance primero.`,
              realBalance: +realBalance.toFixed(2),
              required: +amountUSD.toFixed(2)
            });
          }
        }
        // En modo PAPER-LIVE: guardar sin verificar balance real (aún no hay API key)

        // Enviar capital operativo al live bot
        const BOT_SECRET = process.env.BOT_SECRET||"bafir_bot_secret";
        const body = JSON.stringify({secret:BOT_SECRET, capitalUSD:amountUSD});
        const url = new URL("/api/set-capital", LIVE_URL);
        const mod2 = url.protocol==="https:" ? https : require("http");
        const req2 = mod2.request({
          hostname:url.hostname, path:url.pathname, method:"POST",
          headers:{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body)}
        }, r2 => { let d=""; r2.on("data",c=>d+=c); r2.on("end",()=>{ try{const r=JSON.parse(d); console.log(`[BAFIR] Capital enviado al live: $${amountUSD.toFixed(2)} → ${r.ok?"✅":"❌"}`); }catch{} }); });
        req2.on("error",e=>console.warn("[BAFIR] set-capital error:",e.message));
        req2.write(body); req2.end();
      } catch(e) { console.warn("[BAFIR] Error verificando live bot:", e.message); }
    }

    db.setManagerCapital(amount, currency, note);
    res.json({ok:true, amountUSD:+amountUSD.toFixed(2)});
  }
);
const PAPER_BOT_URL = process.env.PAPER_BOT_URL || "";
const LIVE_BOT_URL2 = process.env.LIVE_BOT_URL  || "";

function fetchBotState(url) {
  return new Promise(resolve => {
    if (!url) return resolve(null);
    try {
      const mod = url.startsWith("https") ? https : require("http");
      const req = mod.get(url + "/api/summary", { timeout:5000 }, res => {  // lightweight
        let d=""; res.on("data",c=>d+=c);
        res.on("end",()=>{ try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      });
      req.on("error", ()=>resolve(null));
      req.on("timeout", ()=>{ req.destroy(); resolve(null); });
    } catch { resolve(null); }
  });
}

// ── Live balances by currency ─────────────────────────────────────────────────
app.get("/api/admin/live-balances", apiRL, requireAdmin, async (_,res) => {
  const LIVE_URL = process.env.LIVE_BOT_URL||"";
  if(!LIVE_URL) return res.json({balances:[], error:"Live bot no configurado"});
  try {
    const liveState = await fetchBotState(LIVE_URL);
    if(!liveState) return res.json({balances:[], error:"Live bot no disponible"});
    
    // Build balance list from portfolio + cash
    const balances = [{asset:"USDC", free:+(liveState.cash||0).toFixed(2), valueUSD:+(liveState.cash||0).toFixed(2)}];
    for(const [sym, pos] of Object.entries(liveState.portfolio||{})) {
      const asset = sym.replace("USDC","").replace("USDT","");
      const price = liveState.prices?.[sym] || pos.entryPrice || 0;
      const valueUSD = +(pos.qty * price).toFixed(2);
      const pnlPct = price > 0 ? +((price - pos.entryPrice)/pos.entryPrice*100).toFixed(2) : 0;
      balances.push({
        asset, qty:+(pos.qty||0).toFixed(6), valueUSD, price:+price.toFixed(2),
        entryPrice:+pos.entryPrice.toFixed(2), pnlPct, symbol:sym
      });
    }
    const totalUSD = balances.reduce((s,b)=>s+b.valueUSD,0);
    res.json({balances, totalUSD:+totalUSD.toFixed(2), ts:Date.now()});
  } catch(e) { res.json({balances:[], error:e.message}); }
});

app.get("/api/bots/state", apiRL, requireAdmin, async (_,res) => {
  const [paperState, liveState] = await Promise.all([
    fetchBotState(PAPER_BOT_URL),
    fetchBotState(LIVE_BOT_URL2),
  ]);
  const eq = db.db.botEquity || [];
  // Verificar que no son el mismo bot (si las URLs son iguales devuelven los mismos datos)
  const sameBot = PAPER_BOT_URL === LIVE_BOT_URL2 || !LIVE_BOT_URL2;
  res.json({
    paper:       paperState,
    live:        sameBot ? null : liveState,
    paperEquity: eq.filter(e=>e.source==="paper").slice(-500),
    liveEquity:  eq.filter(e=>e.source==="live").slice(-500),
    fxRate:      db.fxRate,
    sameBot,
    paperUrl:    PAPER_BOT_URL||"no configurada",
    liveUrl:     LIVE_BOT_URL2||"no configurada",
  });
});

// ── BOT EQUITY ────────────────────────────────────────────────────────────────
app.post("/api/bot/equity",       botRL, (req,res)=>{ if(req.body.secret!==BOT_SECRET) return res.status(401).json({error:"No autorizado"}); if(isNaN(+req.body.value)) return res.status(400).json({error:"Inválido"}); db.pushEquityPoint(+req.body.value,"live"); if(Math.random()<0.08)db.saveEquity(); res.json({ok:true}); });
app.post("/api/bot/equity/paper", botRL, (req,res)=>{ if(req.body.secret!==BOT_SECRET) return res.status(401).json({error:"No autorizado"}); if(isNaN(+req.body.value)) return res.status(400).json({error:"Inválido"}); db.pushEquityPoint(+req.body.value,"paper"); if(Math.random()<0.08)db.saveEquity(); res.json({ok:true}); });
app.get("/api/bot/status", apiRL, requireAdmin, (_,res)=>{ const eq=db.db.botEquity||[]; res.json({paper:eq.filter(e=>e.source==="paper").slice(-200),live:eq.filter(e=>e.source==="live").slice(-200),fxRate:db.fxRate}); });

// ── CLIENT API ────────────────────────────────────────────────────────────────
app.get("/api/client/metrics", apiRL, requireClient, async (req,res)=>{
  const m=db.getClientMetrics(req.session.clientId);
  if(!m) return res.status(404).json({error:"No encontrado"});
  // Add binance connection status and copy trades
  const clientRaw = db.db.clients?.[req.session.clientId];
  m.binanceConnected = !!(clientRaw?.binanceApiKey && clientRaw?.binanceApiSecret);
  m.copyTrades = db.getClientCopyTrades ? db.getClientCopyTrades(req.session.clientId).slice(-20) : [];
  // Enrich with live bot state for real-time display
  try {
    const liveUrl = process.env.LIVE_BOT_URL||"";
    if(liveUrl) {
      const liveState = await fetchBotState(liveUrl);
      if(liveState) {
        const sells = (liveState.log||[]).filter(l=>l.type==="SELL").slice(0,10);
        m.botLive = {
          marketRegime: liveState.marketRegime,
          fearGreed: liveState.fearGreed,
          winRate: liveState.winRate,
          openPositions: Object.keys(liveState.portfolio||{}).length,
          recentTrades: sells.map(t=>({
            symbol:(t.symbol||"").replace("USDC",""),
            pnl:t.pnl, pnlAbs:t.pnlAbs,
            reason:t.reason, ts:t.ts, strategy:t.strategy,
          })),
          totalValue: liveState.totalValue,
          returnPct: liveState.returnPct,
        };
      }
    }
  } catch(e) {}
  res.json(m);
});

// ── HEALTH ────────────────────────────────────────────────────────────────────
// ── Depósitos pendientes de distribución ─────────────────────────────────────
app.get("/api/admin/deposits/pending", apiRL, requireAdmin, (_,res) => {
  res.json({ pending: depositDetector.getPending() });
});

// Forzar check manual de Binance
app.post("/api/admin/deposits/check", apiRL, requireAdmin, async (_,res) => {
  depositDetector._check().catch(()=>{});
  res.json({ ok:true, message:"Verificando Binance…" });
});

// Distribuir un depósito entre clientes y/o admin
// body: { depositId, distribution: [{ target: "client_ID" | "admin", amountUSD: 100 }] }
app.post("/api/admin/deposits/distribute", apiRL, requireAdmin,
  validateInput({ depositId:{required:true,type:"string"}, distribution:{required:true} }),
  (req,res) => {
    try {
      const { depositId, distribution } = req.body;
      const pending = depositDetector.getPending();
      const dep = pending.find(p => p.id === depositId);
      if (!dep) return res.status(404).json({ error:"Depósito no encontrado o ya distribuido" });

      // Validar que los montos cuadran (con margen del 1%)
      const totalDist = distribution.reduce((s,d) => s + (d.amountUSD||0), 0);
      if (Math.abs(totalDist - dep.amountUSD) > dep.amountUSD * 0.01 + 1) {
        return res.status(400).json({ error:`Suma distribuida ($${totalDist.toFixed(2)}) no coincide con depósito ($${dep.amountUSD.toFixed(2)})` });
      }

      const results = [];
      for (const item of distribution) {
        if (!item.amountUSD || item.amountUSD <= 0) continue;
        if (item.target === "admin" || item.target === "manager") {
          // Añadir al capital del gestor
          const mc = db.getManagerCapital();
          db.setManagerCapital((mc.amount||0) + item.amountUSD, "USD", `Depósito Binance ${dep.asset} ${new Date(dep.insertTime).toLocaleDateString()}`);
          results.push({ target:"admin", amount:item.amountUSD });
        } else {
          // Añadir a cliente
          const clientId = item.target;
          const client = db.getClient(clientId);
          if (!client) { results.push({ target:clientId, error:"Cliente no encontrado" }); continue; }
          db.addDeposit(clientId, {
            amount:    item.amountUSD,
            currency:  "USD",
            ts:        new Date(dep.insertTime).toISOString(),
            note:      `Ingreso Binance automático: ${dep.amount} ${dep.asset} (TxID: ${dep.txId||"—"})`,
          });
          // Registrar capital aportado para TWR
          const c = db.getClient(clientId);
          c.capitalAportado = (c.capitalAportado||0) + item.amountUSD;
          db.updateClient(clientId, { capitalAportado: c.capitalAportado });
          results.push({ target:clientId, name:client.name, amount:item.amountUSD });
        }
      }

      depositDetector.markDistributed(depositId);
      db.db.depositDetector = depositDetector.toJSON();
      db.saveEquity();

      auditLog("DEPOSIT_DISTRIBUTED", { depositId, dep, distribution, results }, req);
      res.json({ ok:true, results });
    } catch(e) {
      res.status(500).json({ error: e.message });
    }
  }
);

// Añadir depósito manual (sin detección automática)
app.post("/api/admin/deposits/manual", apiRL, requireAdmin,
  validateInput({ amountUSD:{required:true,type:"number",min:0.01}, asset:{required:true,type:"string"}, distribution:{required:true} }),
  (req,res) => {
    try {
      const { amountUSD, asset, note="", distribution } = req.body;
      const fakeId = `manual_${Date.now()}`;
      const results = [];
      for (const item of distribution) {
        if (!item.amountUSD || item.amountUSD <= 0) continue;
        if (item.target === "admin" || item.target === "manager") {
          const mc = db.getManagerCapital();
          db.setManagerCapital((mc.amount||0)+item.amountUSD,"USD",note||`Ingreso manual ${asset}`);
          results.push({target:"admin",amount:item.amountUSD});
        } else {
          const client=db.getClient(item.target);
          if(!client){results.push({target:item.target,error:"No encontrado"});continue;}
          db.addDeposit(item.target,{amount:item.amountUSD,currency:"USD",ts:new Date().toISOString(),note:note||`Ingreso manual ${asset}`});
          const c=db.getClient(item.target);
          c.capitalAportado=(c.capitalAportado||0)+item.amountUSD;
          db.updateClient(item.target,{capitalAportado:c.capitalAportado});
          results.push({target:item.target,name:client.name,amount:item.amountUSD});
        }
      }
      auditLog("DEPOSIT_MANUAL",{amountUSD,asset,distribution,results},req);
      res.json({ok:true,results});
    } catch(e) { res.status(500).json({error:e.message}); }
  }
);

app.get("/api/health",(_,res)=>res.json({ok:true,uptime:process.uptime()}));

// ── ROI sobre capital aportado (TWR) ──────────────────────────────────────────
app.get("/api/admin/clients/roi", apiRL, requireAdmin, (req,res) => {
  try {
    const clients = db.getClients ? db.getClients() : (db.db?.clients || []);
    const roiData = clients.filter(c=>c.active!==false).map(c => {
      const capitalAportado = c.capitalAportado || c.capital_aportado || c.totalDeposited || 0;
      const valorActual     = c.balance || c.totalValue || 0;
      const ganancia        = valorActual - capitalAportado;
      const roi             = capitalAportado > 0 ? ((valorActual - capitalAportado) / capitalAportado * 100).toFixed(2) : "0.00";
      const days            = c.createdAt ? Math.round((Date.now() - new Date(c.createdAt).getTime()) / 86400000) : 0;
      const annualized      = days > 0 ? (Math.pow(1 + parseFloat(roi)/100, 365/days) - 1) * 100 : null;
      return { id:c.id, name:c.name, capitalAportado:+capitalAportado.toFixed(2), valorActual:+valorActual.toFixed(2), ganancia:+ganancia.toFixed(2), roi:roi+"%", roiAnualizado:annualized?annualized.toFixed(2)+"%":null, dias:days };
    });
    const totalCapital = roiData.reduce((s,c)=>s+c.capitalAportado,0);
    const totalValue   = roiData.reduce((s,c)=>s+c.valorActual,0);
    res.json({ clients:roiData, global:{ totalCapital:totalCapital.toFixed(2), totalValue:totalValue.toFixed(2), globalROI:totalCapital>0?((totalValue-totalCapital)/totalCapital*100).toFixed(2)+"%":"0%" } });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Configurar alertas Telegram por cliente ───────────────────────────────────
app.post("/api/admin/clients/:id/alerts", apiRL, requireAdmin,
  validateInput({gainThreshold:{type:"number"},lossThreshold:{type:"number"}}),
  (req,res) => {
    const {gainThreshold=5, lossThreshold=-3, chatId, enabled=true} = req.body;
    telegramAlerts.configureClient(req.params.id, {gainThreshold, lossThreshold, chatId, enabled});
    auditLog("ALERT_CONFIG", {clientId:req.params.id, gainThreshold, lossThreshold}, req);
    res.json({ok:true});
  }
);

// ── Informe semanal manual ────────────────────────────────────────────────────
app.post("/api/admin/reports/weekly", apiRL, requireAdmin, (req,res) => {
  weeklyReporter.generateAndSend().catch(e=>console.error("[WeeklyReport]",e.message));
  res.json({ok:true, message:"Informe en proceso de envío"});
});

// ── Score de confianza de los bots (proxy desde sus endpoints) ────────────────
app.get("/api/bots/confidence", apiRL, requireAdmin, async (_,res) => {
  const LIVE_URL  = process.env.LIVE_BOT_URL  || "";
  const PAPER_URL = process.env.PAPER_BOT_URL || "";
  const fetchConf = async url => {
    if(!url) return null;
    try {
      const r = await new Promise((resolve,reject) => {
        const mod = url.startsWith("https") ? require("https") : require("http");
        mod.get(url+"/api/confidence", res => {
          let d=""; res.on("data",c=>d+=c); res.on("end",()=>{try{resolve(JSON.parse(d));}catch{reject();}});
        }).on("error",reject);
      });
      return r;
    } catch { return null; }
  };
  const [live, paper] = await Promise.all([fetchConf(LIVE_URL), fetchConf(PAPER_URL)]);
  res.json({live, paper});
});

// ── Bot live status: confidence + cryptopanic + momentum ──────────────────────
app.get("/api/bots/live-status", apiRL, requireAdmin, async (_,res) => {
  const LIVEBOT_URL  = process.env.LIVE_BOT_URL  || "";
  const PAPERBOT_URL = process.env.PAPER_BOT_URL || "";
  const fetchState = (url, timeout=5000) => new Promise((resolve) => {
    if (!url) return resolve(null);
    const mod = url.startsWith("https") ? require("https") : require("http");
    const timer = setTimeout(() => resolve(null), timeout);
    try {
      mod.get(url+"/api/summary", r => {  // /api/summary is lightweight vs /api/state
        let d=""; r.on("data",c=>d+=c);
        r.on("end",()=>{ clearTimeout(timer); try{ resolve(JSON.parse(d)); }catch{ resolve(null); } });
      }).on("error",()=>{ clearTimeout(timer); resolve(null); });
    } catch(e) { clearTimeout(timer); resolve(null); }
  });
  const [liveState, paperState] = await Promise.all([
    fetchState(LIVEBOT_URL), fetchState(PAPERBOT_URL)
  ]);
  // Always return something useful even if bots unreachable
  const eq = db.db.botEquity||[];
  const lastLiveEq  = eq.filter(e=>e.source==="live").slice(-1)[0];
  const lastPaperEq = eq.filter(e=>e.source==="paper").slice(-1)[0];
  res.json({
    live:  liveState  || { loading:false, offline:true, totalValue: lastLiveEq?.value||0,  instance:"LIVE",  tick:0 },
    paper: paperState || { loading:false, offline:true, totalValue: lastPaperEq?.value||0, instance:"PAPER", tick:0 },
    botsReachable: !!(liveState || paperState),
    liveUrl: LIVEBOT_URL||null, paperUrl: PAPERBOT_URL||null,
  });
});


// ── Risk Learning Stats ───────────────────────────────────────────────────────
app.get("/api/bots/risk-learning", apiRL, requireAdmin, async (_,res) => {
  const LIVE_URL = process.env.LIVE_BOT_URL || "";
  const PAPER_URL = process.env.PAPER_BOT_URL || "";
  const fetchState = url => new Promise(resolve => {
    if (!url) return resolve(null);
    const mod = url.startsWith("https") ? require("https") : require("http");
    mod.get(url+"/api/summary", r => {
      let d=""; r.on("data",c=>d+=c);
      r.on("end",()=>{ try{resolve(JSON.parse(d));}catch{resolve(null);} });
    }).on("error",()=>resolve(null));
  });
  const [liveState, paperState] = await Promise.all([fetchState(LIVE_URL), fetchState(PAPER_URL)]);
  res.json({
    live:  { stats:liveState?.riskLearningStats||{},  params:liveState?.riskLearningParams||{} },
    paper: { stats:paperState?.riskLearningStats||{}, params:paperState?.riskLearningParams||{} },
  });
});


// ── Reset equity data (admin only) ───────────────────────────────────────────
app.post("/api/admin/reset-equity", apiRL, requireAdmin, (req,res) => {
  db.db.botEquity = [];
  db.saveEquity();
  console.log("[BAFIR] Equity reseteada por admin");
  res.json({ok:true, message:"Equity reseteada. Los bots empezarán a enviar datos frescos."});
});


// ── Client login (email + password, no 2FA) ──────────────────────────────────
app.post("/api/auth/client-login", loginRL, (req, res) => {
  const { email, password } = req.body;
  if(!email || !password) return res.status(400).json({error:"Datos incompletos"});
  // Find client by email
  const client = Object.values(db.db.clients||{}).find(c => c.email===email && c.active);
  if(!client) return res.status(401).json({error:"Email no encontrado"});
  const { hashPw } = require("./security");
  if(hashPw(password) !== client.passwordHash) return res.status(401).json({error:"Contraseña incorrecta"});
  // Create session
  req.session.role = "client";
  req.session.clientId = client.id;
  req.session.clientName = client.name;
  const token = require("crypto").randomBytes(32).toString("hex");
  req.session.token = token;
  // Store token in client record for API auth
  db.db.clients[client.id].sessionToken = token;
  db.db.clients[client.id].sessionTs = Date.now();
  db.save();
  auditLog("CLIENT_LOGIN", {id:client.id, email}, req);
  res.json({token, clientId:client.id, name:client.name, role:"client"});
});

// ── Client: connect Binance API keys ─────────────────────────────────────────
app.post("/api/client/connect-binance", apiRL, requireClient, async (req, res) => {
  const { apiKey, apiSecret } = req.body;
  if(!apiKey || !apiSecret) return res.status(400).json({error:"Claves requeridas"});
  // Verify keys work by checking balance
  try {
    const crypto2 = require("crypto");
    const https2  = require("https");
    const ts = Date.now();
    const qs = `timestamp=${ts}`;
    const sig = crypto2.createHmac("sha256", apiSecret).update(qs).digest("hex");
    const data = await new Promise((resolve, reject) => {
      https2.get({
        hostname:"api.binance.com", path:`/api/v3/account?${qs}&signature=${sig}`,
        headers:{"X-MBX-APIKEY":apiKey}, timeout:8000,
      }, r => {
        let d=""; r.on("data",c=>d+=c);
        r.on("end",()=>{ try{resolve(JSON.parse(d));}catch(e){reject(e);} });
      }).on("error",reject).on("timeout",()=>reject(new Error("timeout")));
    });
    if(data.code) return res.json({ok:false, error:"Claves inválidas: "+data.msg});
    const usdc = parseFloat(data.balances?.find(b=>b.asset==="USDC")?.free||0);
    // Save encrypted keys
    db.updateClient(req.session.clientId, { binanceApiKey:apiKey, binanceApiSecret:apiSecret });
    auditLog("CLIENT_BINANCE_CONNECTED", {id:req.session.clientId, usdc}, req);
    res.json({ok:true, balance:usdc.toFixed(2)});
  } catch(e) {
    res.json({ok:false, error:"No se pudo verificar: "+e.message});
  }
});

// ── Internal API: copy-trading ─────────────────────────────────────────────
const internalAuth = (req, res, next) => {
  const sig = req.headers["x-signature"];
  const body = JSON.stringify(req.body);
  const expected = require("crypto").createHmac("sha256", process.env.SYNC_SECRET||"bafir_sync_secret_2024").update(body).digest("hex");
  try {
    if(!sig || !require("crypto").timingSafeEqual(Buffer.from(sig,"hex"), Buffer.from(expected,"hex")))
      return res.status(401).json({error:"Unauthorized"});
  } catch(e) { return res.status(401).json({error:"Unauthorized"}); }
  next();
};

app.post("/api/internal/client-keys", internalAuth, (req, res) => {
  const clients = db.getActiveClientsWithKeys ? db.getActiveClientsWithKeys() : [];
  res.json({ clients, ts: Date.now() });
});

app.post("/api/internal/trade-report", internalAuth, (req, res) => {
  const { clientId, symbol, investedUSDC, ts } = req.body;
  if(clientId && symbol && db.recordClientTrade) {
    db.recordClientTrade(clientId, { symbol, investedUSDC, ts, source:"copy_trading" });
  }
  res.json({ ok: true });
});

// ── Onboarding + Terms pages ──────────────────────────────────────────────────
app.get("/onboarding*", (_,res)=>res.sendFile(path.join(__dirname,"../public/shared/onboarding.html")));
app.get("/terms",        (_,res)=>res.sendFile(path.join(__dirname,"../public/shared/terms.html")));

// ── ERROR HANDLER ─────────────────────────────────────────────────────────────
app.use((err,req,res,next)=>{ console.error("[ERROR]",err.message); res.status(500).json({error:"Error interno"}); });

// ── PÁGINAS ───────────────────────────────────────────────────────────────────
app.get("/app*",   (_,res)=>res.sendFile(path.join(__dirname,"../public/app/index.html")));
app.get("/admin*", (_,res)=>res.sendFile(path.join(__dirname,"../public/admin/index.html")));
app.get("/client*",(_,res)=>res.sendFile(path.join(__dirname,"../public/client/index.html")));
app.get("/",       (_,res)=>res.sendFile(path.join(__dirname,"../public/shared/login.html")));
app.use((_,res)=>res.status(404).json({error:"No encontrado"}));

// ── Startup diagnostic ─────────────────────────────────────────────────────
const _LIVE_URL  = process.env.LIVE_BOT_URL  || "";
const _PAPER_URL = process.env.PAPER_BOT_URL || "";
if (!_LIVE_URL)  console.warn("[BAFIR] ⚠️  LIVE_BOT_URL no configurada — admin dashboard sin datos del live");
if (!_PAPER_URL) console.warn("[BAFIR] ⚠️  PAPER_BOT_URL no configurada — admin dashboard sin datos del paper");
if (_LIVE_URL)   console.log("[BAFIR] ✅ LIVE_BOT_URL =", _LIVE_URL);
if (_PAPER_URL)  console.log("[BAFIR] ✅ PAPER_BOT_URL =", _PAPER_URL);

httpServer.listen(PORT, ()=>console.log(`\n💼 BAFIR TRADING v5 SEGURO en http://localhost:${PORT}\n`));
module.exports={db};
