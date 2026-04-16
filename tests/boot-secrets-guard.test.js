"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const secrets = require("../src/secrets");

describe("BATCH-2 — secrets.js validation", () => {
  it("empty → not ok (empty)", () => {
    assert.deepEqual(secrets.validateBootSecret(""), { ok: false, reason: "empty" });
    assert.deepEqual(secrets.validateBootSecret(undefined), { ok: false, reason: "empty" });
  });
  it("bafir_bot_secret → not ok (predictable)", () => {
    assert.deepEqual(secrets.validateBootSecret("bafir_bot_secret"), { ok: false, reason: "predictable" });
  });
  it("bafir_sync_secret_2024 → not ok (predictable)", () => {
    assert.deepEqual(secrets.validateBootSecret("bafir_sync_secret_2024"), { ok: false, reason: "predictable" });
  });
  it("bafir2024 → not ok (predictable)", () => {
    assert.deepEqual(secrets.validateBootSecret("bafir2024"), { ok: false, reason: "predictable" });
  });
  it("short string → not ok (too_short)", () => {
    assert.deepEqual(secrets.validateBootSecret("abc123"), { ok: false, reason: "too_short" });
  });
  it("valid 32-char string → ok", () => {
    assert.deepEqual(secrets.validateBootSecret("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"), { ok: true });
  });
  it("makeBotSecretChecker timing-safe compare", () => {
    const checker = secrets.makeBotSecretChecker(() => "validSecretAtLeast16ch");
    assert.ok(checker("validSecretAtLeast16ch"));
    assert.ok(!checker("wrongSecret1234567890"));
    assert.ok(!checker(""));
    assert.ok(!checker(null));
  });
  it("makeBotSecretChecker fail-closed if env invalid", () => {
    const checker = secrets.makeBotSecretChecker(() => "short");
    assert.ok(!checker("short")); // fail-closed: env value too short
  });
});
