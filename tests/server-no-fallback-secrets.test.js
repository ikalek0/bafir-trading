"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

describe("BATCH-2 FIX #2+#3 — no hardcoded fallback secrets in server.js", () => {
  const serverSrc = fs.readFileSync(path.join(__dirname, "../src/server.js"), "utf8");

  it("bafir_bot_secret literal NOT in executable code", () => {
    // Split by lines, filter out comments
    const lines = serverSrc.split("\n").filter(l => !l.trim().startsWith("//"));
    const found = lines.filter(l => l.includes('"bafir_bot_secret"') || l.includes("'bafir_bot_secret'"));
    assert.equal(found.length, 0, `Found bafir_bot_secret in non-comment lines: ${found.join("\n")}`);
  });

  it("bafir_sync_secret_2024 literal NOT anywhere", () => {
    assert.ok(!serverSrc.includes("bafir_sync_secret_2024"),
      "bafir_sync_secret_2024 should be completely eliminated");
  });

  it("BOT_SECRET declaration has no fallback", () => {
    const decl = serverSrc.split("\n").find(l => l.includes("const BOT_SECRET") && !l.trim().startsWith("//"));
    assert.ok(decl, "BOT_SECRET const must exist");
    assert.ok(!decl.includes("bafir_bot_secret"), "must not have fallback literal");
  });

  it("checkBotSecret function exists", () => {
    assert.ok(serverSrc.includes("checkBotSecret"), "checkBotSecret must be used");
  });

  it("boot guard validates secrets and exits", () => {
    assert.ok(serverSrc.includes("validateBootSecrets") || serverSrc.includes("validateBootSecret"),
      "boot guard must validate secrets");
    assert.ok(serverSrc.includes("process.exit(1)"), "must exit on invalid secrets");
  });
});
