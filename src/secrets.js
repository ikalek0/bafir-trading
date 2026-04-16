// ── BATCH-2: secrets validation (pattern from cryptobot-live) ───────────
"use strict";
const crypto = require("crypto");

const PREDICTABLE_SECRETS = new Set([
  "bafir_bot_secret", "bafir_sync_secret_2024", "changeme", "change_me",
  "secret", "password", "admin", "admin123", "default", "test", "test123",
  "letmein", "qwerty", "12345", "123456", "bot_secret", "api_key", "bafir2024",
]);

function timingSafeCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)); }
  catch { return false; }
}

function validateBootSecret(envValue) {
  if (!envValue) return { ok: false, reason: "empty" };
  if (PREDICTABLE_SECRETS.has(envValue.toLowerCase().trim())) return { ok: false, reason: "predictable" };
  if (envValue.length < 16) return { ok: false, reason: "too_short" };
  return { ok: true };
}

function makeBotSecretChecker(getEnvValue) {
  if (typeof getEnvValue !== "function") throw new TypeError("getEnvValue must be a function");
  return function checkBotSecret(provided) {
    if (typeof provided !== "string") return false;
    const envValue = getEnvValue();
    const v = validateBootSecret(envValue);
    if (!v.ok) return false;
    return timingSafeCompare(provided, envValue);
  };
}

module.exports = { PREDICTABLE_SECRETS, timingSafeCompare, validateBootSecret, makeBotSecretChecker };
