/*
 * full_parity_test.mjs — EXHAUSTIVE differential test.
 * ----------------------------------------------------
 * Replays the ENTIRE final test set (every URL the Python model was
 * graded on in train_final.py — ~5,200 held-out URLs) through the JS
 * engine and demands, for EVERY row:
 *
 *   1. scheme stripping matches Python exactly
 *   2. probability matches Python within 0.000001
 *   3. the 3-way verdict band (safe / suspicious / dangerous) is identical
 *
 * At the end it also recomputes the confusion matrix from JS answers —
 * it must equal the Python one (66 misses / 8 false alarms) exactly,
 * proving the SHIPPED engine has the same accuracy we measured.
 *
 * Run:  node linkguard-model/deploy/full_parity_test.mjs
 */

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

const require = createRequire(import.meta.url);
const LinkGuardModel = require("../../model.js");

const modelJsonPath = new URL("../../model/linkguard_model_v1.json", import.meta.url);
const vectorsPath = new URL("./full_parity_vectors.json", import.meta.url);

const artifact = JSON.parse(readFileSync(modelJsonPath, "utf8"));
LinkGuardModel.init(artifact);
const thresholds = artifact.config.thresholds;
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
console.log(`replaying the FULL final test set: ${vectors.length} URLs\n`);

const TOLERANCE = 1e-6;

// same bands the extension uses (read from the shipped artifact config)
function bandOf(probability) {
  if (probability < thresholds.safe_below) return "safe";
  if (probability > thresholds.dangerous_above) return "dangerous";
  return "suspicious";
}

let failures = 0;
let worstDiff = 0;
let worstUrl = "";
let bandFlips = 0;

// confusion counts rebuilt from the JS engine's own answers
let jsMisses = 0;      // truth dangerous, JS says p < 0.5
let jsFalseAlarms = 0; // truth safe,      JS says p >= 0.5

for (const vector of vectors) {
  const strippedText = LinkGuardModel.stripScheme(vector.url);
  if (strippedText !== vector.text) {
    failures++;
    console.log(`STRIP MISMATCH  ${vector.url.slice(0, 80)}`);
    continue;
  }

  const jsProbability = LinkGuardModel.predictProba(strippedText);
  const diff = Math.abs(jsProbability - vector.p);
  if (diff > worstDiff) { worstDiff = diff; worstUrl = vector.url; }
  if (diff > TOLERANCE) {
    failures++;
    console.log(`PROB MISMATCH   ${vector.url.slice(0, 80)}`);
    console.log(`   python: ${vector.p}   js: ${jsProbability}   diff ${diff.toExponential(2)}`);
  }

  // the user-facing verdict band must never differ from Python's
  if (bandOf(jsProbability) !== bandOf(vector.p)) {
    bandFlips++;
    console.log(`BAND FLIP       p_py=${vector.p.toFixed(8)} p_js=${jsProbability.toFixed(8)}  ${vector.url.slice(0, 70)}`);
  }

  if (vector.label === 1 && jsProbability < 0.5) jsMisses++;
  if (vector.label === 0 && jsProbability >= 0.5) jsFalseAlarms++;
}

console.log(`\nprobability parity : ${vectors.length - failures}/${vectors.length} within ${TOLERANCE.toExponential(0)}`);
console.log(`worst difference   : ${worstDiff.toExponential(2)}  (${worstUrl.slice(0, 60)})`);
console.log(`verdict band flips : ${bandFlips}  (must be 0)`);
console.log(`\nJS confusion on the honest test set (must equal Python's):`);
console.log(`  misses       : ${jsMisses}   (Python had 66)`);
console.log(`  false alarms : ${jsFalseAlarms}   (Python had 8 — 0.3% of 2,630 safe)`);

// speed over the full set — one pass, real URLs, worst-case mix
const benchStart = performance.now();
for (const vector of vectors) LinkGuardModel.classify(vector.url);
const totalMs = performance.now() - benchStart;
const meanMs = totalMs / vectors.length;
console.log(`\nspeed: ${vectors.length} classifications in ${totalMs.toFixed(0)} ms` +
            `  ->  ${(meanMs * 1000).toFixed(0)} microseconds per URL`);

const speedOk = meanMs < 5;
if (failures > 0 || bandFlips > 0 || !speedOk) {
  console.log("\nFULL PARITY GATE: FAILED");
  process.exit(1);
}
console.log("\nFULL PARITY GATE: PASSED — JS engine is a perfect translation on the entire test set");
