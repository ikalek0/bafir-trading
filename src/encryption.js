// ─── ENCRYPTION MODULE ────────────────────────────────────────────────────────
// Cifra las API keys de Binance en la base de datos
// Usa AES-256-GCM — simétrico, autenticado, seguro
"use strict";

const crypto = require("crypto");

// La clave de cifrado viene de variable de entorno
// Si no está definida, usa una clave derivada del hostname (menos seguro pero funcional)
function getEncryptionKey() {
  const raw = process.env.ENCRYPTION_KEY || `bafir_default_${require("os").hostname()}`;
  // Derivar clave de 32 bytes con SHA-256
  return crypto.createHash("sha256").update(raw).digest();
}

// Cifrar un string
function encrypt(text) {
  if (!text) return "";
  try {
    const key   = getEncryptionKey();
    const iv    = crypto.randomBytes(16);
    const cipher= crypto.createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
    const tag   = cipher.getAuthTag();
    // Formato: iv(16) + tag(16) + encrypted — todo en base64
    return Buffer.concat([iv, tag, encrypted]).toString("base64");
  } catch(e) {
    console.error("[ENCRYPT] Error cifrando:", e.message);
    return "";
  }
}

// Descifrar un string
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
    // Si falla el descifrado, podría ser que la key no estaba cifrada (migración)
    return ciphertext;
  }
}

// Verificar si un string parece estar cifrado (es base64 válido de >32 bytes)
function isEncrypted(text) {
  if (!text || text.length < 44) return false;
  try { return Buffer.from(text, "base64").length >= 32; } catch { return false; }
}

module.exports = { encrypt, decrypt, isEncrypted };
