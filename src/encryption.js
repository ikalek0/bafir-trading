// ─── ENCRYPTION MODULE ────────────────────────────────────────────────────────
// Cifra las API keys de Binance en la base de datos
// Usa AES-256-GCM — simétrico, autenticado, seguro
//
// BATCH-2 FIX #1 (CRITICAL #B3): ENCRYPTION_KEY es OBLIGATORIA.
// Antes: fallback a `bafir_default_${hostname}` si no definida. Hostname es
// predecible (ej: "bafir-server") → atacante con backup de DB + hostname
// descifra todas las API keys de clientes.
// Ahora: throw si ENCRYPTION_KEY no definida o < 32 chars. Boot falla rápido.
"use strict";

const crypto = require("crypto");

const PREDICTABLE_PATTERNS = [
  /^bafir_default_/i,
  /^changeme$/i,
  /^default$/i,
  /^secret$/i,
  /^encryption_key$/i,
];

function getEncryptionKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      "ENCRYPTION_KEY required. Generate with: openssl rand -hex 32"
    );
  }
  if (raw.length < 32) {
    throw new Error(
      `ENCRYPTION_KEY too short (${raw.length} chars, min 32). Generate with: openssl rand -hex 32`
    );
  }
  for (const p of PREDICTABLE_PATTERNS) {
    if (p.test(raw)) {
      throw new Error("ENCRYPTION_KEY uses a predictable pattern — generate a random one");
    }
  }
  return crypto.createHash("sha256").update(raw).digest();
}

function encrypt(text) {
  if (!text) return "";
  const key   = getEncryptionKey();
  const iv    = crypto.randomBytes(16);
  const cipher= crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag   = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

function decrypt(ciphertext) {
  if (!ciphertext) return "";
  try {
    const key    = getEncryptionKey();
    const buf    = Buffer.from(ciphertext, "base64");
    const iv     = buf.slice(0, 16);
    const tag    = buf.slice(16, 32);
    const data   = buf.slice(32);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(data) + decipher.final("utf8");
  } catch(e) {
    if (e.message.includes("ENCRYPTION_KEY")) throw e;
    return ciphertext;
  }
}

function isEncrypted(text) {
  if (!text || text.length < 44) return false;
  try { return Buffer.from(text, "base64").length >= 32; } catch { return false; }
}

module.exports = { encrypt, decrypt, isEncrypted, getEncryptionKey };
