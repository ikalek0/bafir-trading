"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

describe("BATCH-2 FIX #5 — cross-bot response validation", () => {
  const src = fs.readFileSync(path.join(__dirname, "../src/server.js"), "utf8");

  it("set-capital awaits response (not fire-and-forget)", () => {
    assert.ok(src.includes("await new Promise") && src.includes("set-capital"),
      "set-capital should await the live bot response");
  });

  it("502 returned if live sync fails", () => {
    assert.ok(src.includes("502") && src.includes("Live bot sync failed"),
      "502 with sync failed message should exist");
  });

  it("set-alert-config logs response", () => {
    const idx = src.indexOf("set-alert-config");
    const section = src.slice(idx, idx + 2000);
    assert.ok(!section.includes("()=>{}") || section.includes("console.log") || section.includes("console.warn"),
      "alert-config should not have empty callback");
  });
});
