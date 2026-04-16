"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

describe("BATCH-2 FIX #4 — tolerance 2% + sanity cap", () => {
  const src = fs.readFileSync(path.join(__dirname, "../src/server.js"), "utf8");

  it("tolerance is 0.02 (2%), not 0.90 (10%)", () => {
    assert.ok(src.includes("TOLERANCE = 0.02") || src.includes("TOLERANCE=0.02"),
      "TOLERANCE should be 0.02");
    assert.ok(!src.includes("amountUSD * 0.90"),
      "old 10% tolerance (0.90) should be gone");
  });

  it("sanity cap $1M exists", () => {
    assert.ok(src.includes("1_000_000") || src.includes("1000000"),
      "$1M sanity cap should exist");
  });
});
