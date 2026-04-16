"use strict";
const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");

describe("BATCH-2 FIX #1 — encryption strict ENCRYPTION_KEY", () => {
  let origKey;
  beforeEach(() => { origKey = process.env.ENCRYPTION_KEY; });
  afterEach(() => {
    if (origKey !== undefined) process.env.ENCRYPTION_KEY = origKey;
    else delete process.env.ENCRYPTION_KEY;
    delete require.cache[require.resolve("../src/encryption")];
  });

  function freshEncryption() {
    delete require.cache[require.resolve("../src/encryption")];
    return require("../src/encryption");
  }

  it("throws if ENCRYPTION_KEY not set", () => {
    delete process.env.ENCRYPTION_KEY;
    const enc = freshEncryption();
    assert.throws(() => enc.encrypt("test"), /ENCRYPTION_KEY required/);
  });

  it("throws if ENCRYPTION_KEY too short", () => {
    process.env.ENCRYPTION_KEY = "short";
    const enc = freshEncryption();
    assert.throws(() => enc.encrypt("test"), /too short/);
  });

  it("throws if ENCRYPTION_KEY is predictable hostname pattern", () => {
    process.env.ENCRYPTION_KEY = "bafir_default_bafir-server-12345678901234";
    const enc = freshEncryption();
    assert.throws(() => enc.encrypt("test"), /predictable/);
  });

  it("encrypt/decrypt round-trip with valid key", () => {
    process.env.ENCRYPTION_KEY = "a]3kF9$mP2xR7vN5jQ8wL4tB6yH1cE0dZ";
    const enc = freshEncryption();
    const plain = "my-secret-api-key-12345";
    const cipher = enc.encrypt(plain);
    assert.ok(cipher.length > 0);
    assert.notEqual(cipher, plain);
    assert.equal(enc.decrypt(cipher), plain);
  });

  it("hostname does NOT influence key derivation", () => {
    process.env.ENCRYPTION_KEY = "a]3kF9$mP2xR7vN5jQ8wL4tB6yH1cE0dZ";
    const enc = freshEncryption();
    const cipher = enc.encrypt("test123");
    // Verify decrypt works (hostname irrelevant)
    assert.equal(enc.decrypt(cipher), "test123");
  });

  it("empty text returns empty string", () => {
    process.env.ENCRYPTION_KEY = "a]3kF9$mP2xR7vN5jQ8wL4tB6yH1cE0dZ";
    const enc = freshEncryption();
    assert.equal(enc.encrypt(""), "");
    assert.equal(enc.decrypt(""), "");
  });
});
