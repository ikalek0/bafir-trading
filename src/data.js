// ─── BAFIR TRADING v4 — DATA LAYER ───────────────────────────────────────────
"use strict";

const fs     = require("fs");
const path   = require("path");
const crypto = require("crypto");
const https  = require("https");
const { encrypt, decrypt } = require("./encryption");

const DATA_FILE = path.join(__dirname, "../data/bafir.json");

function hashPw(pw) { return crypto.createHash("sha256").update(pw + "bafir2024").digest("hex"); }
function genId()    { return Date.now().toString(36) + Math.random().toString(36).slice(2,6); }

// ── FX EUR/USD ────────────────────────────────────────────────────────────────
let fxCache = { rate:1.08, ts:0 };
function fetchFX() {
  return new Promise(resolve => {
    if (Date.now()-fxCache.ts < 3600000) { resolve(fxCache.rate); return; }
    const req = https.get("https://api.exchangerate-api.com/v4/latest/EUR", res => {
      let d=""; res.on("data",c=>d+=c);
      res.on("end",()=>{ try { fxCache={rate:JSON.parse(d).rates.USD||1.08,ts:Date.now()}; resolve(fxCache.rate); } catch{ resolve(fxCache.rate); }});
    });
    req.on("error",()=>resolve(fxCache.rate));
    req.setTimeout(4000,()=>{req.destroy();resolve(fxCache.rate);});
  });
}
function cvtToUSD(amount, currency, fx) {
  return currency==="EUR" ? amount*fx : amount;
}

// ── LOAD / SAVE ───────────────────────────────────────────────────────────────
function load() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE),{recursive:true});
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE,"utf8"));
  } catch(e) { console.warn("[DATA]",e.message); }
  return { clients:{}, botEquity:[],
           // BATCH-2 FIX #6 (#B6): no default password "bafir2024".
           // Si INITIAL_ADMIN_PASSWORD está en env → usar esa.
           // Si no → generar aleatoria y logearla UNA VEZ para que el admin la guarde.
           adminHash: (() => {
             const envPw = process.env.INITIAL_ADMIN_PASSWORD;
             if (envPw && envPw.length >= 12 && envPw !== "bafir2024") {
               console.log("[DATA] Admin password seteada desde INITIAL_ADMIN_PASSWORD");
               return hashPw(envPw);
             }
             if (envPw === "bafir2024") {
               console.warn("[DATA] ⚠️ INITIAL_ADMIN_PASSWORD=bafir2024 es predecible — generando aleatoria");
             }
             const generated = crypto.randomBytes(16).toString("hex");
             console.warn("=".repeat(70));
             console.warn("[DATA] ⚠️ INITIAL_ADMIN_PASSWORD no configurada o inválida (min 12 chars)");
             console.warn(`[DATA] Password admin generada: ${generated}`);
             console.warn("[DATA] ⚠️ GUARDA ESTE VALOR — no se mostrará de nuevo");
             console.warn("[DATA] Para cambiar: usa /api/admin/password tras login");
             console.warn("=".repeat(70));
             return hashPw(generated);
           })(),
           fxRate:1.08,
           twoFA:{ enabled:false, secret:"", backupCodes:[] },
           ipWhitelist:[], managerCapital:{ amount:0, currency:"EUR", note:"" } };
}
function save(db) {
  try { fs.mkdirSync(path.dirname(DATA_FILE),{recursive:true}); fs.writeFileSync(DATA_FILE,JSON.stringify(db,null,2)); }
  catch(e) { console.error("[DATA] Error guardando:",e.message); }
}

// ── TIPOS DE DESEMBOLSO ───────────────────────────────────────────────────────
// mgmt_fee          → Comisión de gestión (tuya, no afecta capital cliente)
// profit_interest   → Interés sobre ganancia del cliente (reduces su P&L)
// fixed_interest    → Interés fijo periódico sobre inversión inicial (reduces capital)
// client_withdrawal → El cliente retira dinero (reduce su capital)
// manager_withdrawal→ Tú retiras dinero de tu parte (no afecta capital cliente)

const DISBURSEMENT_TYPES = {
  mgmt_fee:           { label:"Comisión de gestión",        affectsClient:false, affectsCapital:false },
  profit_interest:    { label:"Interés sobre ganancia",     affectsClient:true,  affectsCapital:false },
  fixed_interest:     { label:"Interés fijo periódico",     affectsClient:true,  affectsCapital:true  },
  client_withdrawal:  { label:"Retirada del cliente",       affectsClient:true,  affectsCapital:true  },
  manager_withdrawal: { label:"Retirada del gestor",        affectsClient:false, affectsCapital:false },
};

// ── CÁLCULO DE DISTRIBUCIONES AUTOMÁTICAS ────────────────────────────────────
function getDistributionSchedule(client, botEquity, fx) {
  const dist = client.distribution;
  if (!dist?.enabled||!dist.pct||!botEquity.length) return { past:[], next:null, config:dist };

  const liveEquity = botEquity.filter(e=>e.source==="live"||!e.source);
  if (!liveEquity.length) return { past:[], next:null, config:dist };

  const firstDep = client.deposits[0];
  if (!firstDep) return { past:[], next:null, config:dist };

  const initialAmtUSD = cvtToUSD(firstDep.amount, firstDep.currency, fx);
  const startDate = new Date(firstDep.ts);
  const now = new Date();
  const distCur = dist.currency||client.currency||"USD";
  const schedule = [];

  let d = new Date(startDate);
  while (d <= now) {
    let nextD = new Date(d);
    if (dist.periodicity==="monthly")    nextD.setMonth(nextD.getMonth()+1);
    else if (dist.periodicity==="quarterly") nextD.setMonth(nextD.getMonth()+3);
    else if (dist.periodicity==="annual")    nextD.setFullYear(nextD.getFullYear()+1);
    if (nextD > now) break;

    let baseUSD;
    if (dist.baseType==="initial") {
      baseUSD = initialAmtUSD;
    } else {
      const eq = liveEquity.filter(e=>new Date(e.ts)<=nextD);
      baseUSD = eq.length ? eq[eq.length-1].value*(client.share||0)/100 : initialAmtUSD;
    }

    const amtUSD = baseUSD*(dist.pct/100);
    const amtDisplay = distCur==="EUR" ? amtUSD/fx : amtUSD;
    const periodKey = nextD.toISOString().slice(0,7);
    const paid = (client.distributionsPaid||[]).some(p=>p.periodDate===periodKey);

    schedule.push({ id:genId(), date:nextD.toISOString(), amtUSD:+amtUSD.toFixed(2), amtDisplay:+amtDisplay.toFixed(2), currency:distCur, baseUSD:+baseUSD.toFixed(2), paid, periodKey });
    d = nextD;
  }

  // Próxima
  let nextDate = new Date(d);
  if (dist.periodicity==="monthly")    nextDate.setMonth(nextDate.getMonth()+1);
  else if (dist.periodicity==="quarterly") nextDate.setMonth(nextDate.getMonth()+3);
  else if (dist.periodicity==="annual")    nextDate.setFullYear(nextDate.getFullYear()+1);

  const lastEqUSD = liveEquity.length?liveEquity[liveEquity.length-1].value:10000;
  const nextBaseUSD = dist.baseType==="initial"?initialAmtUSD:lastEqUSD*(client.share||0)/100;
  const nextAmtUSD  = nextBaseUSD*(dist.pct/100);

  return {
    past: schedule,
    next: { date:nextDate.toISOString(), amtUSD:+nextAmtUSD.toFixed(2), amtDisplay:+(distCur==="EUR"?nextAmtUSD/fx:nextAmtUSD).toFixed(2), currency:distCur },
    totalPaidUSD:      schedule.filter(s=>s.paid).reduce((s,i)=>s+i.amtUSD,0),
    totalScheduledUSD: schedule.reduce((s,i)=>s+i.amtUSD,0),
    config: dist,
  };
}

// ── EQUITY CURVES (doble: con y sin distribuciones) ───────────────────────────
function buildEquityCurves(botEquity, clientShare, distributions, fx, displayCurrency) {
  const liveEq = botEquity.filter(e=>e.source==="live"||!e.source);
  if (!liveEq.length) return { withDist:[], withoutDist:[] };
  const cvt = v => +(v*(displayCurrency==="EUR"?1/fx:1)).toFixed(2);

  const withoutDist = liveEq.map(e=>({ ts:e.ts, value:cvt(e.value*clientShare/100) }));
  const withDist = liveEq.map(e=>{
    const eTs = new Date(e.ts).getTime();
    const distPaid = (distributions?.past||[]).filter(d=>d.paid&&new Date(d.date).getTime()<=eTs).reduce((s,d)=>s+d.amtUSD,0);
    return { ts:e.ts, value:+Math.max(0,(e.value*clientShare/100-distPaid)*(displayCurrency==="EUR"?1/fx:1)).toFixed(2) };
  });

  return { withDist, withoutDist };
}

// ── MÉTRICAS POR PERÍODO ──────────────────────────────────────────────────────
function calcPeriod(botEquity, share, period, displayCur, fx) {
  // Solo usar equity del bot LIVE para métricas de rendimiento real
  const liveEq = botEquity.filter(e=>e.source==="live");
  if (!liveEq.length) return { pnl:0, pnlPct:0, start:0, end:0, currency:displayCur };
  const now=Date.now();
  let cutoff;
  switch(period){
    case "1D": cutoff=now-86400000;    break; case "1W": cutoff=now-604800000;   break;
    case "1M": cutoff=now-2592000000;  break; case "3M": cutoff=now-7776000000;  break;
    case "6M": cutoff=now-15552000000; break; case "1Y": cutoff=now-31536000000; break;
    case "YTD":cutoff=new Date(new Date().getFullYear(),0,1).getTime(); break;
    default:   cutoff=0;
  }
  const slice=liveEq.filter(e=>new Date(e.ts).getTime()>=cutoff);
  const raw=slice.length?slice:liveEq;
  const cvt=v=>+(v*share/100*(displayCur==="EUR"?1/fx:1)).toFixed(2);

  // Filtrar puntos de equity del paper bot que se colaron como "live"
  // Heurística: si la mediana de los últimos 20 puntos es < 5000, los puntos >10000 son del paper
  const recent20 = raw.slice(-20).map(e=>e.value);
  const median20 = recent20.sort((a,b)=>a-b)[Math.floor(recent20.length/2)] || 0;
  const isLiveScale = median20 < 5000; // live bot con $500 nunca llega a $5000 rápido
  const s = isLiveScale
    ? raw.filter(e => e.value < median20 * 10) // filtrar outliers extremos
    : raw; // si ya tiene escala de paper, mostrar todo

  if (!s.length) return { pnl:0, pnlPct:0, start:0, end:0, currency:displayCur };

  // Detectar resets: salto >5x entre puntos consecutivos al inicio
  let startIdx = 0;
  for (let i=1; i<Math.min(s.length,15); i++) {
    if (s[i].value > s[i-1].value * 5 || s[i].value < s[i-1].value * 0.15) {
      startIdx = i;
    }
  }

  const startVal = s[startIdx]?.value || s[0].value;
  const endVal   = s[s.length-1].value;
  const start=cvt(startVal), end=cvt(endVal), pnl=end-start;
  const rawPct = start>0?((pnl/start)*100):0;
  // Cap ±500% — suficiente para mostrar buen rendimiento sin absurdos
  const pnlPct = Math.max(-99, Math.min(500, rawPct));
  return { pnl:+pnl.toFixed(2), pnlPct:+pnlPct.toFixed(2), start, end, currency:displayCur };
}

function calcMonthly(botEquity, share, displayCur, fx) {
  const liveEq=botEquity.filter(e=>e.source==="live"||!e.source);
  if (!liveEq.length) return [];
  const months={};
  liveEq.forEach(e=>{ const d=new Date(e.ts); const k=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}`; if(!months[k])months[k]={first:e.value,last:e.value,key:k}; months[k].last=e.value; });
  const cvt=v=>+(v*share/100*(displayCur==="EUR"?1/fx:1)).toFixed(2);
  return Object.values(months).map(m=>({ key:m.key, label:new Date(m.key+"-01").toLocaleDateString("es-ES",{month:"short",year:"numeric"}), start:cvt(m.first),end:cvt(m.last),pnl:cvt(m.last)-cvt(m.first),pnlPct:m.first>0?+((m.last-m.first)/m.first*100).toFixed(2):0,currency:displayCur }));
}

// ── DB ────────────────────────────────────────────────────────────────────────
class BafirDB {
  constructor() {
    this.db=load();
    fetchFX().then(r=>{this.db.fxRate=r;});
    // Auto-limpiar equity corrupta: si el primer punto live es >50x la mediana reciente
    // (señal de que el paper bot envió datos como "live" erróneamente)
    try {
      const live = (this.db.botEquity||[]).filter(e=>e.source==="live");
      if (live.length >= 10) {
        const vals = live.slice(-20).map(e=>e.value).sort((a,b)=>a-b);
        const median = vals[Math.floor(vals.length/2)];
        const first  = live[0].value;
        if (first > median * 30) {
          console.log(`[BAFIR] Equity corrupta detectada (primer punto $${first.toFixed(0)} vs mediana $${median.toFixed(0)}) — limpiando`);
          this.db.botEquity = [];
          save(this.db);
        }
      }
    } catch(e) { console.warn("[BAFIR] Error limpiando equity:", e.message); }
  }
  get fxRate()   { return this.db.fxRate||1.08; }

  verifyAdmin(pw)     { return hashPw(pw)===this.db.adminHash; }
  setAdminPw(pw)      { this.db.adminHash=hashPw(pw); save(this.db); }
  verifyClient(id,pw) { const c=this.db.clients[id]; return c?.active&&hashPw(pw)===c.passwordHash; }

  // ── 2FA ──────────────────────────────────────────────────────────────────────
  get2FAStatus()   { return { enabled: this.db.twoFA?.enabled||false, hasSecret: !!(this.db.twoFA?.secret) }; }
  get2FASecret()   { return this.db.twoFA?.secret||""; }
  enable2FA(secret){ if(!this.db.twoFA) this.db.twoFA={}; this.db.twoFA.secret=secret; this.db.twoFA.enabled=true; save(this.db); }
  disable2FA()     { if(this.db.twoFA) { this.db.twoFA.enabled=false; this.db.twoFA.secret=""; } save(this.db); }
  is2FAEnabled()   { return this.db.twoFA?.enabled===true; }

  // ── IP WHITELIST ─────────────────────────────────────────────────────────────
  getIPWhitelist()      { return this.db.ipWhitelist||[]; }
  addIP(ip, label="")   { if(!this.db.ipWhitelist) this.db.ipWhitelist=[]; if(!this.db.ipWhitelist.find(e=>e.ip===ip)) { this.db.ipWhitelist.push({ip,label,addedAt:new Date().toISOString()}); save(this.db); } }
  removeIP(ip)          { this.db.ipWhitelist=(this.db.ipWhitelist||[]).filter(e=>e.ip!==ip); save(this.db); }
  isIPAllowed(ip)       { const wl=this.db.ipWhitelist||[]; if(!wl.length) return true; return wl.some(e=>e.ip===ip||ip.startsWith(e.ip)); }

  // ── CAPITAL PROPIO DEL GESTOR ─────────────────────────────────────────────
  getManagerCapital() { return this.db.managerCapital||{amount:0,currency:"EUR",note:""}; }
  setManagerCapital(amount,currency="EUR",note="") { this.db.managerCapital={amount:+amount,currency,note}; save(this.db); }

  createClient({name,email,password,notes="",currency="EUR",depositMode="managed",phone="",startDate=""}) {
    const id=genId();
    this.db.clients[id]={
      id,name,email,phone,passwordHash:hashPw(password),currency,
      share:0, // calculado automáticamente desde depósitos
      depositMode,
      binanceApiKey:"",binanceApiSecret:"",
      deposits:[],withdrawals:[],disbursements:[],distributionsPaid:[],
      distribution:{enabled:false,pct:0,baseType:"initial",periodicity:"monthly",currency},
      active:true,
      createdAt:new Date().toISOString(),
      startDate:startDate||new Date().toISOString(),
      notes,
    };
    save(this.db); return id;
  }

  // Recalcular % de participación de todos los clientes basado en depósitos reales
  recalcShares() {
    const fx = this.fxRate;
    const clients = Object.values(this.db.clients).filter(c=>c.active);

    // Total depositado en USD entre todos los clientes
    const totalUSD = clients.reduce((sum,c) => {
      return sum + c.deposits.reduce((s,d) => s+(d.currency==="EUR"?d.amount*fx:d.amount), 0)
                 - c.withdrawals.reduce((s,w) => s+(w.currency==="EUR"?w.amount*fx:w.amount), 0);
    }, 0);

    if (totalUSD <= 0) return;

    // Asignar % proporcional a cada cliente
    clients.forEach(c => {
      const clientUSD = c.deposits.reduce((s,d)=>s+(d.currency==="EUR"?d.amount*fx:d.amount),0)
                      - c.withdrawals.reduce((s,w)=>s+(w.currency==="EUR"?w.amount*fx:w.amount),0);
      this.db.clients[c.id].share = +Math.max(0,(clientUSD/totalUSD)*100).toFixed(4);
    });
    save(this.db);
  }

  updateClient(id,fields) {
    if(!this.db.clients[id]) return false;
    ["name","email","notes","active","share","currency","depositMode","distribution"].forEach(f=>{if(fields[f]!==undefined)this.db.clients[id][f]=fields[f];});
    // Cifrar API keys antes de guardar
    if(fields.binanceApiKey)    this.db.clients[id].binanceApiKey    = encrypt(fields.binanceApiKey);
    if(fields.binanceApiSecret) this.db.clients[id].binanceApiSecret = encrypt(fields.binanceApiSecret);
    if(fields.password) this.db.clients[id].passwordHash=hashPw(fields.password);
    save(this.db); return true;
  }

  getDecryptedKeys(clientId) {
    const c = this.db.clients[clientId];
    if (!c) return null;
    return { apiKey: decrypt(c.binanceApiKey||""), apiSecret: decrypt(c.binanceApiSecret||"") };
  }

  getClients()  { return Object.values(this.db.clients); }
  getClient(id) { return this.db.clients[id]||null; }

  addDeposit(clientId,{amount,currency,ts,note=""}) {
    if(!this.db.clients[clientId]) return false;
    this.db.clients[clientId].deposits.push({id:genId(),amount:+amount,currency:currency||this.db.clients[clientId].currency,ts:ts||new Date().toISOString(),note,mode:"managed"});
    save(this.db); this.recalcShares(); return true;
  }
  removeDeposit(clientId,depId) {
    if(!this.db.clients[clientId]) return false;
    this.db.clients[clientId].deposits=this.db.clients[clientId].deposits.filter(d=>d.id!==depId);
    save(this.db); this.recalcShares(); return true;
  }

  // ── DESEMBOLSOS UNIFICADOS ────────────────────────────────────────────────
  // type: mgmt_fee | profit_interest | fixed_interest | client_withdrawal | manager_withdrawal
  addDisbursement(clientId, {type, amount, currency, ts, note=""}) {
    const c=this.db.clients[clientId];
    if(!c||!DISBURSEMENT_TYPES[type]) return false;
    if(!c.disbursements) c.disbursements=[];

    const disb={id:genId(),type,amount:+amount,currency:currency||c.currency,ts:ts||new Date().toISOString(),note};
    c.disbursements.push(disb);

    // Si afecta al capital del cliente → también añadir a withdrawals para que impacte en TWR
    if (DISBURSEMENT_TYPES[type].affectsCapital) {
      c.withdrawals=c.withdrawals||[];
      c.withdrawals.push({id:genId(),amount:+amount,currency:disb.currency,ts:disb.ts,note:`[${DISBURSEMENT_TYPES[type].label}] ${note}`,disbId:disb.id});
    }

    save(this.db); return true;
  }

  removeDisbursement(clientId, disbId) {
    const c=this.db.clients[clientId];
    if(!c) return false;
    const disb=(c.disbursements||[]).find(d=>d.id===disbId);
    if(!disb) return false;
    // Si afectaba al capital, quitar también el withdrawal vinculado
    if(DISBURSEMENT_TYPES[disb.type]?.affectsCapital) {
      c.withdrawals=(c.withdrawals||[]).filter(w=>w.disbId!==disbId);
    }
    c.disbursements=(c.disbursements||[]).filter(d=>d.id!==disbId);
    save(this.db); return true;
  }

  markDistributionPaid(clientId, periodKey) {
    const c=this.db.clients[clientId];
    if(!c) return false;
    if(!c.distributionsPaid) c.distributionsPaid=[];
    if(!c.distributionsPaid.find(p=>p.periodDate===periodKey)) {
      c.distributionsPaid.push({periodDate:periodKey,paidAt:new Date().toISOString()});
      // También registrar como desembolso tipo fixed_interest
      this.addDisbursement(clientId,{type:"fixed_interest",amount:0,currency:c.currency,ts:new Date().toISOString(),note:`Distribución automática ${periodKey}`});
    }
    save(this.db); return true;
  }

  pushEquityPoint(v, source="live") {
    this.db.botEquity.push({ts:new Date().toISOString(),value:+v,source});
    this.db.botEquity=this.db.botEquity.slice(-4000);
  }
  saveEquity() { save(this.db); }

  // ── MÉTRICAS CLIENTE ──────────────────────────────────────────────────────
  getClientMetrics(clientId) {
    const c=this.db.clients[clientId]; if(!c) return null;
    const fx=this.fxRate, equity=this.db.botEquity, share=c.share||0, cur=c.currency||"USD";
    const liveEq=equity.filter(e=>e.source==="live"||!e.source);

    const totalDepUSD  = (c.deposits||[]).reduce((s,d)=>s+cvtToUSD(d.amount,d.currency,fx),0);
    const totalWithUSD = (c.withdrawals||[]).reduce((s,w)=>s+cvtToUSD(w.amount,w.currency,fx),0);
    const lastEqUSD    = liveEq.length?liveEq[liveEq.length-1].value:10000;
    const currentUSD   = lastEqUSD*share/100;
    const pnlUSD       = currentUSD-totalDepUSD+totalWithUSD;
    const pnlPct       = totalDepUSD>0?(pnlUSD/totalDepUSD)*100:0;
    const firstDep     = c.deposits[0];
    const firstDepUSD  = firstDep?cvtToUSD(firstDep.amount,firstDep.currency,fx):0;
    const roiInitial   = firstDepUSD>0?((currentUSD-firstDepUSD)/firstDepUSD)*100:0;

    // Desembolsos por tipo
    const disbs = c.disbursements||[];
    const byType = {};
    Object.keys(DISBURSEMENT_TYPES).forEach(t=>{ byType[t]=disbs.filter(d=>d.type===t); });
    const totalMgmtFeesUSD    = byType.mgmt_fee.reduce((s,d)=>s+cvtToUSD(d.amount,d.currency,fx),0);
    const totalProfitIntUSD   = byType.profit_interest.reduce((s,d)=>s+cvtToUSD(d.amount,d.currency,fx),0);
    const totalFixedIntUSD    = byType.fixed_interest.reduce((s,d)=>s+cvtToUSD(d.amount,d.currency,fx),0);
    const totalClientWithUSD  = byType.client_withdrawal.reduce((s,d)=>s+cvtToUSD(d.amount,d.currency,fx),0);
    const totalManagerWithUSD = byType.manager_withdrawal.reduce((s,d)=>s+cvtToUSD(d.amount,d.currency,fx),0);
    const totalDisbUSD        = totalMgmtFeesUSD+totalProfitIntUSD+totalFixedIntUSD+totalClientWithUSD+totalManagerWithUSD;

    const distSchedule = getDistributionSchedule(c,equity,fx);
    const totalDistPaidUSD = (distSchedule.past||[]).filter(d=>d.paid).reduce((s,d)=>s+d.amtUSD,0);
    const curves = buildEquityCurves(equity,share,distSchedule,fx,cur);

    const toCur = v=>+(v*(cur==="EUR"?1/fx:1)).toFixed(2);
    const twr = {
      totalDeposited:  toCur(totalDepUSD),
      totalWithdrawn:  toCur(totalWithUSD),
      currentValue:    toCur(currentUSD),
      pnlAbs:          toCur(pnlUSD),
      pnlPct:          +pnlPct.toFixed(2),
      roiInitial:      +roiInitial.toFixed(2),
      firstDeposit:    toCur(firstDepUSD),
      participation:   share,
      totalDistPaid:   toCur(totalDistPaidUSD),
      // Desembolsos
      totalMgmtFees:    toCur(totalMgmtFeesUSD),
      totalProfitInt:   toCur(totalProfitIntUSD),
      totalFixedInt:    toCur(totalFixedIntUSD),
      totalClientWith:  toCur(totalClientWithUSD),
      totalManagerWith: toCur(totalManagerWithUSD),
      totalDisbursed:   toCur(totalDisbUSD),
      currency: cur,
    };

    const altCur=cur==="EUR"?"USD":"EUR";
    const altValue=toCur(currentUSD)*(cur==="EUR"?fx:1/fx);
    const periods=["1D","1W","1M","3M","6M","1Y","YTD","ALL"].map(p=>({period:p,...calcPeriod(equity,share,p,cur,fx)}));
    const monthly=calcMonthly(equity,share,cur,fx);

    return {
      client:{id:c.id,name:c.name,email:c.email,createdAt:c.createdAt,notes:c.notes,share,currency:cur,depositMode:c.depositMode,distribution:c.distribution},
      twr, periods, monthly,
      altValue:+altValue.toFixed(2), altCurrency:altCur,
      deposits:c.deposits, withdrawals:c.withdrawals,
      disbursements:disbs, disbursementTypes:DISBURSEMENT_TYPES,
      distSchedule, curves, fxRate:fx,
    };
  }

  // ── MÉTRICAS GLOBALES ─────────────────────────────────────────────────────
  getGlobalMetrics() {
    const clients=Object.values(this.db.clients).filter(c=>c.active);
    const equity=this.db.botEquity, fx=this.fxRate;
    const liveEq=equity.filter(e=>e.source==="live"||!e.source);
    const paperEq=equity.filter(e=>e.source==="paper");
    const lastUSD=liveEq.length?liveEq[liveEq.length-1].value:10000;
    const aumUSD=clients.reduce((s,c)=>s+lastUSD*(c.share||0)/100,0);

    // Total desembolsos de gestión
    const totalMgmtFeesUSD=clients.reduce((s,c)=>{
      return s+(c.disbursements||[]).filter(d=>d.type==="mgmt_fee"||d.type==="manager_withdrawal").reduce((ss,d)=>ss+cvtToUSD(d.amount,d.currency,fx),0);
    },0);

    const periods=["1D","1W","1M","3M","6M","1Y","YTD","ALL"].map(p=>({period:p,...calcPeriod(equity,100,p,"USD",fx)}));
    const monthly=calcMonthly(equity,100,"USD",fx);
    const dist=clients.map(c=>({id:c.id,name:c.name,share:c.share||0,valueUSD:+(lastUSD*(c.share||0)/100).toFixed(2),valueEUR:+(lastUSD*(c.share||0)/100/fx).toFixed(2),currency:c.currency,distributionEnabled:c.distribution?.enabled||false}));
    const totalDistNext=clients.reduce((s,c)=>{const ds=getDistributionSchedule(c,equity,fx);return s+(ds.next?.amtUSD||0);},0);

    const mc = this.getManagerCapital();
    const mcUSD = mc.amount > 0 ? cvtToUSD(mc.amount, mc.currency, fx) : 0;

    return {
      nClients:clients.length, aumUSD:+aumUSD.toFixed(2), aumEUR:+(aumUSD/fx).toFixed(2),
      // Balance total = capital clientes + capital gestor
      balanceUSD:+(aumUSD+mcUSD).toFixed(2), balanceEUR:+((aumUSD+mcUSD)/fx).toFixed(2),
      managerCapital:mc, managerCapitalUSD:+mcUSD.toFixed(2),
      botEquityUSD:+lastUSD.toFixed(2), botEquityEUR:+(lastUSD/fx).toFixed(2),
      periods, monthly,
      equityCurve:liveEq.slice(-200),
      paperCurve:paperEq.slice(-200),
      distribution:dist,
      unallocatedPct:Math.max(0,100-clients.reduce((s,c)=>s+(c.share||0),0)),
      totalDistNextUSD:+totalDistNext.toFixed(2),
      totalMgmtFeesUSD:+totalMgmtFeesUSD.toFixed(2),
      totalMgmtFeesEUR:+(totalMgmtFeesUSD/fx).toFixed(2),
      fxRate:fx,
      disbursementTypes:DISBURSEMENT_TYPES,
    };
  }
}


// ── Copy-trading methods added to BafirDB prototype ──────────────────────────
BafirDB.prototype.getActiveClientsWithKeys = function() {
  const { decrypt } = require("./encryption");
  return Object.values(this.db.clients||{})
    .filter(c => c.active && c.binanceApiKey && c.binanceApiSecret)
    .map(c => ({
      id: c.id, name: c.name,
      apiKey:    decrypt(c.binanceApiKey),
      apiSecret: decrypt(c.binanceApiSecret),
      capital:   (c.deposits||[]).reduce((s,d)=>s+(d.amountUSD||d.amount||0),0)
               - (c.withdrawals||[]).reduce((s,w)=>s+(w.amountUSD||w.amount||0),0),
    }))
    .filter(c => c.apiKey && c.apiSecret && c.capital > 0);
};

BafirDB.prototype.recordClientTrade = function(clientId, trade) {
  if(!this.db.clients?.[clientId]) return false;
  if(!this.db.clients[clientId].copyTrades) this.db.clients[clientId].copyTrades = [];
  this.db.clients[clientId].copyTrades.push({ ...trade, ts: trade.ts||new Date().toISOString() });
  if(this.db.clients[clientId].copyTrades.length > 200)
    this.db.clients[clientId].copyTrades = this.db.clients[clientId].copyTrades.slice(-200);
  this.save();
  return true;
};

BafirDB.prototype.getClientCopyTrades = function(clientId) {
  return this.db.clients?.[clientId]?.copyTrades || [];
};

module.exports = { BafirDB, DISBURSEMENT_TYPES };
