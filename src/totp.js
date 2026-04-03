// ─── 2FA MODULE — TOTP compatible con Google Authenticator ───────────────────
"use strict";

const crypto = require("crypto");

// ── TOTP (Time-based One-Time Password — RFC 6238) ────────────────────────────
// Compatible con Google Authenticator sin dependencias externas

function base32Encode(buffer) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "", bits = 0, value = 0;
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}

function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  str = str.toUpperCase().replace(/=+$/, "");
  let bits = 0, value = 0;
  const output = [];
  for (const char of str) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(output);
}

function hotp(secret, counter) {
  const key  = base32Decode(secret);
  const buf  = Buffer.alloc(8);
  let c      = counter;
  for (let i = 7; i >= 0; i--) { buf[i] = c & 0xff; c >>= 8; }
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const off  = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[off] & 0x7f) << 24) |
               ((hmac[off+1] & 0xff) << 16) |
               ((hmac[off+2] & 0xff) << 8)  |
               (hmac[off+3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}

function totp(secret, window = 1) {
  const counter = Math.floor(Date.now() / 30000);
  // Acepta el código actual y los N anteriores/siguientes (margen de tiempo)
  for (let i = -window; i <= window; i++) {
    if (hotp(secret, counter + i)) {
      // devuelve todos los válidos
    }
  }
  return counter;
}

// ── API pública ───────────────────────────────────────────────────────────────

// Generar secreto nuevo para el admin
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

// Verificar código introducido por el usuario
function verifyToken(secret, token) {
  if (!secret || !token) return false;
  const counter = Math.floor(Date.now() / 30000);
  const clean   = String(token).replace(/\s/g, "");
  // Verificar ventana de ±1 (30s de margen)
  for (let i = -1; i <= 1; i++) {
    if (hotp(secret, counter + i) === clean) return true;
  }
  return false;
}

// URL para escanear con Google Authenticator
function getQRUrl(secret, issuer = "BAFIR Trading", account = "admin") {
  const otpauth = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  // Usar API de QR gratuita (sin dependencias)
  return `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauth)}`;
}

module.exports = { generateSecret, verifyToken, getQRUrl };
