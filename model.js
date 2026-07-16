/*
 * model.js — LinkGuard on-device URL classifier (inference engine)
 * ----------------------------------------------------------------
 * Pure JavaScript re-implementation of the trained Python model:
 *   TfidfVectorizer(char_wb, 3-5 grams) + LogisticRegression.
 *
 * The model itself is just numbers, loaded from model/linkguard_model_v1.json:
 *   chunk -> [idf, weight], plus one intercept.
 *
 * How a prediction works (same 4 steps as sklearn, in order):
 *   1. break the URL into character chunks (3, 4 and 5 letters long)
 *   2. count each known chunk, multiply count by its idf  (tf * idf)
 *   3. divide by the vector's length (L2 norm) so long URLs aren't louder
 *   4. weighted sum + intercept -> sigmoid -> probability of "dangerous"
 *
 * This file has ZERO input/output: init() receives already-parsed JSON.
 * That makes it runnable both inside the extension's service worker
 * (importScripts) and in Node.js (for the parity test).
 *
 * Parity with sklearn is exact by design. The subtle parts:
 *   - slice by CODE POINTS (Array.from), not UTF-16 units — an emoji is
 *     ONE character to Python and must be one character to us too
 *   - Python's idea of "whitespace" differs slightly from JS \s,
 *     so we spell out Python's whitespace characters explicitly
 *   - a word shorter than the chunk size emits ONE truncated chunk and
 *     then SKIPS all bigger sizes (sklearn's `if offset == 0: break`)
 */

"use strict";

(function (globalScope) {

  // ---- model state (filled by init) ----------------------------------
  let chunkTable = null;      // Map: chunk string -> [idf, weight]
  let intercept = 0;          // the model's starting bias
  let thresholds = { safe_below: 0.30, dangerous_above: 0.70 };
  let modelMeta = null;       // version info, for logging/debugging

  // ---- Python-compatible whitespace handling -------------------------
  // Python str.split() / \s treat these as whitespace (JS \s differs
  // slightly, e.g. on \x1c-\x1f and ﻿), so we list them explicitly.
  const PYTHON_WHITESPACE =
    "\\t\\n\\x0B\\f\\r\\x1C\\x1D\\x1E\\x1F \\x85\\xA0\\u1680\\u2000-\\u200A" +
    "\\u2028\\u2029\\u202F\\u205F\\u3000";
  // runs of 2+ whitespace collapse to a single space (sklearn does this first)
  const WHITESPACE_RUN = new RegExp(
    "[" + PYTHON_WHITESPACE + "][" + PYTHON_WHITESPACE + "]+", "g");
  // splitting into words: any whitespace is a separator
  const WHITESPACE_SPLIT = new RegExp("[" + PYTHON_WHITESPACE + "]+");

  const NGRAM_MIN = 3;
  const NGRAM_MAX = 5;

  // ---- step 0: scheme stripping (must mirror training exactly) -------
  // Training used Python's url.split("://", 1)[1] — everything after the
  // FIRST "://". JS String.split works differently, so use indexOf.
  function stripScheme(url) {
    const schemeEnd = url.indexOf("://");
    return schemeEnd >= 0 ? url.slice(schemeEnd + 3) : url;
  }

  // ---- step 1: break text into character chunks ----------------------
  // Exact port of sklearn's _char_wb_ngrams.
  function charWbNgrams(text) {
    text = text.replace(WHITESPACE_RUN, " ");
    const chunks = [];

    for (const word of text.split(WHITESPACE_SPLIT)) {
      if (!word) continue;                        // split() drops empty pieces

      // pad the word with one space each side, as CODE POINTS
      const codePoints = Array.from(" " + word + " ");
      const paddedLength = codePoints.length;

      for (let size = NGRAM_MIN; size <= NGRAM_MAX; size++) {
        let offset = 0;
        // first window is ALWAYS emitted, even if the word is shorter
        chunks.push(codePoints.slice(0, size).join(""));
        while (offset + size < paddedLength) {
          offset += 1;
          chunks.push(codePoints.slice(offset, offset + size).join(""));
        }
        // word never slid -> word fits inside one window ->
        // sklearn skips all BIGGER sizes for this word
        if (offset === 0) break;
      }
    }
    return chunks;
  }

  // ---- steps 2-4: counts -> tf*idf -> L2 norm -> sigmoid --------------
  function predictProba(text) {
    if (!chunkTable) throw new Error("LinkGuardModel: init() not called yet");

    // count how many times each KNOWN chunk appears (unknown chunks:
    // the model has no weight for them, so they are silently ignored)
    const chunkCounts = new Map();
    for (const chunk of charWbNgrams(text.toLowerCase())) {
      if (chunkTable.has(chunk)) {
        chunkCounts.set(chunk, (chunkCounts.get(chunk) || 0) + 1);
      }
    }

    // tf*idf for each chunk, accumulating:
    //   sumOfSquares -> for the L2 norm (the vector's length)
    //   weightedSum  -> tfidf value * danger weight
    let sumOfSquares = 0;
    let weightedSum = 0;
    for (const [chunk, count] of chunkCounts) {
      const [idf, weight] = chunkTable.get(chunk);
      const tfidfValue = count * idf;
      sumOfSquares += tfidfValue * tfidfValue;
      weightedSum += tfidfValue * weight;
    }

    // dividing every tfidf value by the norm THEN summing is the same as
    // summing first and dividing once (both are linear) — sklearn skips
    // the division entirely for all-zero vectors, and so do we
    const norm = Math.sqrt(sumOfSquares);
    const score = (sumOfSquares > 0 ? weightedSum / norm : 0) + intercept;

    // sigmoid: squash the raw score into a 0..1 probability
    return 1 / (1 + Math.exp(-score));
  }

  // ---- public API -----------------------------------------------------
  function init(parsedModelJson) {
    if (parsedModelJson.meta.format !== "linkguard-tfidf-logreg-v1") {
      throw new Error("LinkGuardModel: unknown model format " +
                      parsedModelJson.meta.format);
    }
    chunkTable = new Map(Object.entries(parsedModelJson.ngrams));
    intercept = parsedModelJson.intercept;
    thresholds = parsedModelJson.config.thresholds;
    modelMeta = parsedModelJson.meta;
    return true;
  }

  function isReady() {
    return chunkTable !== null;
  }

  function getMeta() {
    return modelMeta;
  }

  // classify: the full URL -> verdict object used by the extension
  function classify(url) {
    const probability = predictProba(stripScheme(url));

    // three-way verdict: the "suspicious" band is a THRESHOLD decision
    // applied AFTER the model — never a training label
    let verdict;
    if (probability < thresholds.safe_below) verdict = "safe";
    else if (probability > thresholds.dangerous_above) verdict = "dangerous";
    else verdict = "suspicious";

    return {
      p: probability,
      confidence: Math.max(probability, 1 - probability),
      verdict: verdict,
    };
  }

  const LinkGuardModel = {
    init, isReady, getMeta, stripScheme, charWbNgrams, predictProba, classify,
  };

  // Node.js (parity test) gets module.exports;
  // the service worker (importScripts) gets a global.
  if (typeof module !== "undefined" && module.exports) {
    module.exports = LinkGuardModel;
  } else {
    globalScope.LinkGuardModel = LinkGuardModel;
  }

})(typeof self !== "undefined" ? self : globalThis);
