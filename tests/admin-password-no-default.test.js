"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

describe("BATCH-2 FIX #6 — admin password no default bafir2024", () => {
  const dataSrc = fs.readFileSync(path.join(__dirname, "../src/data.js"), "utf8");

  it("bafir2024 NOT used as default password in load()", () => {
    // The string "bafir2024" should only appear in the hashPw salt and the rejection check,
    // NOT as the argument to hashPw in the default return
    const lines = dataSrc.split("\n");
    const defaultLines = lines.filter(l =>
      l.includes('hashPw("bafir2024")') && !l.trim().startsWith("//") && !l.includes("!==")
    );
    // hashPw("bafir2024") should NOT appear as the direct default (only in salt definition and rejection)
    const inDefault = defaultLines.filter(l => !l.includes("INITIAL_ADMIN_PASSWORD"));
    assert.equal(inDefault.length, 0,
      `hashPw("bafir2024") as default should be gone. Found: ${inDefault.join("\n")}`);
  });

  it("INITIAL_ADMIN_PASSWORD is referenced", () => {
    assert.ok(dataSrc.includes("INITIAL_ADMIN_PASSWORD"),
      "should use INITIAL_ADMIN_PASSWORD env var");
  });

  it("random password generation exists as fallback", () => {
    assert.ok(dataSrc.includes("randomBytes") || dataSrc.includes("crypto.randomBytes"),
      "should generate random password if env not set");
  });
});
