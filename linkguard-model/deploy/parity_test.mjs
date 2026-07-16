/*
 * parity_test.mjs — proves the JavaScript engine matches Python EXACTLY.
 * ----------------------------------------------------------------------
 * Python wrote 100 URLs with the exact probability the sklearn model
 * gives them (model/golden_vectors.json). Here we run the SAME URLs
 * through model.js and demand every probability match within 0.000001.
 *
 * If even one differs, the JS port has a bug and must NOT ship.
 * This is how real teams prove two implementations of one model agree.
 *
 * Run from the repo root or anywhere:  node linkguard-model/deploy/parity_test.mjs
 */

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

const require = createRequire(import.meta.url);

// model.js is a classic script; in Node it exposes module.exports
const LinkGuardModel = require("../../model.js");

const modelJsonPath = new URL("../../model/linkguard_model_v1.json", import.meta.url);
const goldenPath = new URL("../../model/golden_vectors.json", import.meta.url);

// ---- load the model (time it — this is the one-time startup cost) ----
const initStart = performance.now();
LinkGuardModel.init(JSON.parse(readFileSync(modelJsonPath, "utf8")));
const initMs = performance.now() - initStart;
console.log(`model loaded in ${initMs.toFixed(0)} ms ` +
            `(one-time cost when the extension starts)`);

const goldenVectors = JSON.parse(readFileSync(goldenPath, "utf8"));
console.log(`checking ${goldenVectors.length} golden vectors...\n`);

// ---- the parity check -------------------------------------------------
const TOLERANCE = 1e-6;
let failures = 0;
let worstDiff = 0;
let worstUrl = "";

for (const vector of goldenVectors) {
  // 1. scheme stripping must match Python
  const strippedText = LinkGuardModel.stripScheme(vector.url);
  if (strippedText !== vector.text) {
    failures++;
    console.log(`STRIP MISMATCH  ${vector.url}`);
    console.log(`   python: "${vector.text}"`);
    console.log(`   js    : "${strippedText}"`);
    continue;
  }

  // 2. probability must match Python within tolerance
  const jsProbability = LinkGuardModel.predictProba(strippedText);
  const diff = Math.abs(jsProbability - vector.p);
  if (diff > worstDiff) { worstDiff = diff; worstUrl = vector.url; }
  if (diff > TOLERANCE) {
    failures++;
    const shortUrl = vector.url.length > 70 ? vector.url.slice(0, 67) + "..." : vector.url;
    console.log(`PROB MISMATCH   ${shortUrl}`);
    console.log(`   python: ${vector.p}`);
    console.log(`   js    : ${jsProbability}   (diff ${diff.toExponential(2)})`);
  }
}

console.log(`\nresult: ${goldenVectors.length - failures}/${goldenVectors.length} passed`);
console.log(`worst difference: ${worstDiff.toExponential(2)}  (${worstUrl.slice(0, 60)})`);
console.log(`tolerance       : ${TOLERANCE.toExponential(0)}`);

// ---- speed benchmark ---------------------------------------------------
// scan every golden URL 10x = 1000 classifications, measure the average
const benchStart = performance.now();
let benchRuns = 0;
for (let round = 0; round < 10; round++) {
  for (const vector of goldenVectors) {
    LinkGuardModel.classify(vector.url);
    benchRuns++;
  }
}
const totalMs = performance.now() - benchStart;
const meanMs = totalMs / benchRuns;
console.log(`\nspeed: ${benchRuns} classifications in ${totalMs.toFixed(0)} ms` +
            `  ->  ${(meanMs * 1000).toFixed(0)} microseconds per URL`);

const speedOk = meanMs < 5;
if (!speedOk) console.log("SPEED FAIL: mean per-URL time exceeds 5 ms budget");

if (failures > 0 || !speedOk) {
  console.log("\nPARITY GATE: FAILED — do NOT integrate into the extension");
  process.exit(1);
}
console.log("\nPARITY GATE: PASSED — safe to integrate into the extension");
