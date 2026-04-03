// ─── AUDIT LOG ────────────────────────────────────────────────────────────────
// Registra todos los accesos, acciones importantes y eventos de seguridad
"use strict";

const fs   = require("fs");
const path = require("path");

const AUDIT_FILE = path.join(__dirname, "../data/audit.log");
const MAX_LINES  = 10000; // máximo 10k líneas antes de rotar

let buffer = []; // buffer en memoria para escritura eficiente

function log(type, details, req = null) {
  const entry = {
    ts:      new Date().toISOString(),
    type,    // "LOGIN_OK" | "LOGIN_FAIL" | "2FA_FAIL" | "ACTION" | "SECURITY" | "API_ACCESS"
    ip:      req ? (req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "unknown") : "system",
    ua:      req ? (req.headers["user-agent"] || "").slice(0, 100) : "system",
    ...details,
  };

  buffer.push(JSON.stringify(entry));

  // Escribir a disco cada 10 entradas o en eventos críticos
  if (buffer.length >= 10 || ["LOGIN_FAIL","2FA_FAIL","SECURITY","BLOCKED"].includes(type)) {
    flush();
  }
}

function flush() {
  if (!buffer.length) return;
  try {
    fs.mkdirSync(path.dirname(AUDIT_FILE), { recursive: true });
    fs.appendFileSync(AUDIT_FILE, buffer.join("\n") + "\n", "utf8");
    buffer = [];

    // Rotar si el archivo es demasiado grande
    const stats = fs.statSync(AUDIT_FILE);
    if (stats.size > 5 * 1024 * 1024) { // 5MB
      const backup = AUDIT_FILE.replace(".log", `-${Date.now()}.log`);
      fs.renameSync(AUDIT_FILE, backup);
    }
  } catch(e) { console.error("[AUDIT]", e.message); }
}

// Leer últimas N entradas para mostrar en el dashboard
function getRecent(n = 100) {
  try {
    if (!fs.existsSync(AUDIT_FILE)) return [];
    const lines = fs.readFileSync(AUDIT_FILE, "utf8").trim().split("\n").filter(Boolean);
    return lines.slice(-n).reverse().map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  } catch(e) { return []; }
}

// Guardar buffer al cerrar
process.on("SIGTERM", flush);
process.on("SIGINT",  flush);

// Middleware de Express para loguear accesos a la API
function auditMiddleware(req, res, next) {
  const start = Date.now();
  const orig  = res.end.bind(res);
  res.end = function(...args) {
    const ms = Date.now() - start;
    // Solo loguear rutas de API importantes
    if (req.path.startsWith("/api/auth") || (req.path.startsWith("/api/admin") && req.method !== "GET")) {
      log("API_ACCESS", {
        method:   req.method,
        path:     req.path,
        status:   res.statusCode,
        ms,
      }, req);
    }
    orig(...args);
  };
  next();
}

module.exports = { log, flush, getRecent, auditMiddleware };
