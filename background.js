console.log("LinkGuard background service worker started");

// ═══════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════
const DEFAULT_MODEL = "gemini-2.0-flash";
const CACHE_TTL_MS = 60 * 60 * 1000;           // 1 hour
const LIST_REFRESH_MS = 24 * 60 * 60 * 1000;   // 24 hours
const VT_BASE = "https://www.virustotal.com/api/v3";

// In-memory URL verdict cache: url → { verdict, reason, ts }
const urlCache = new Map();

// In-memory blocklists (loaded from IndexedDB on startup/wake)
let urlhausSet = new Set();
let openphishSet = new Set();
let threatfoxSet = new Set();
let communitySet = new Set();   // Phase 2: Supabase community blocklist
let listsLoaded = false;
let listsLoadingPromise = null;

// Per-tab stats: tabId → { total, scanned, safe, suspicious, dangerous, unknown }
const tabStats = new Map();

// ═══════════════════════════════════════════════════════
// INDEXEDDB
// ═══════════════════════════════════════════════════════
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("linkguard", 2);  // v2 adds "community" store
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      ["urlhaus", "openphish", "threatfox", "meta", "community"].forEach((name) => {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name);
      });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGetAllKeys(storeName) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(storeName, "readonly").objectStore(storeName).getAllKeys();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(storeName, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(storeName, "readonly").objectStore(storeName).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbPut(storeName, key, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put(value, key);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

async function dbPutBatch(storeName, urls) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    store.clear();
    for (const url of urls) store.put(1, url);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

// ═══════════════════════════════════════════════════════
// BLOCKLIST MANAGEMENT
// ═══════════════════════════════════════════════════════
async function loadListsFromDB() {
  try {
    const [urlhaus, openphish, threatfox, community] = await Promise.all([
      dbGetAllKeys("urlhaus"),
      dbGetAllKeys("openphish"),
      dbGetAllKeys("threatfox"),
      dbGetAllKeys("community"),
    ]);
    urlhausSet = new Set(urlhaus);
    openphishSet = new Set(openphish);
    threatfoxSet = new Set(threatfox);
    communitySet = new Set(community);
    listsLoaded = true;
    console.log(`LinkGuard lists: URLhaus=${urlhausSet.size}, OpenPhish=${openphishSet.size}, ThreatFox=${threatfoxSet.size}, Community=${communitySet.size}`);
  } catch (e) {
    console.error("LinkGuard: failed to load lists from IndexedDB", e);
  }
}

async function ensureListsLoaded() {
  if (listsLoaded) return;
  if (!listsLoadingPromise) listsLoadingPromise = loadListsFromDB();
  await listsLoadingPromise;
}

async function fetchURLhaus() {
  try {
    const resp = await fetch("https://urlhaus.abuse.ch/downloads/text_recent/");
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    const urls = text.split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#") && l.startsWith("http"));
    await dbPutBatch("urlhaus", urls);
    urlhausSet = new Set(urls);
    console.log(`LinkGuard: URLhaus updated — ${urls.length} URLs`);
  } catch (e) {
    console.error("LinkGuard: URLhaus fetch failed", e.message);
  }
}

async function fetchOpenPhish() {
  try {
    const resp = await fetch("https://openphish.com/feed.txt");
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    const urls = text.split("\n")
      .map((l) => l.trim())
      .filter((l) => l.startsWith("http"));
    await dbPutBatch("openphish", urls);
    openphishSet = new Set(urls);
    console.log(`LinkGuard: OpenPhish updated — ${urls.length} URLs`);
  } catch (e) {
    console.error("LinkGuard: OpenPhish fetch failed", e.message);
  }
}

async function fetchThreatFox() {
  try {
    const resp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 7 }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const urls = [];
    if (data.data) {
      for (const ioc of data.data) {
        if (ioc.ioc_type === "url" && ioc.ioc) urls.push(ioc.ioc);
      }
    }
    await dbPutBatch("threatfox", urls);
    threatfoxSet = new Set(urls);
    console.log(`LinkGuard: ThreatFox updated — ${urls.length} URLs`);
  } catch (e) {
    console.error("LinkGuard: ThreatFox fetch failed", e.message);
  }
}

// ═══════════════════════════════════════════════════════
// SUPABASE INTEGRATION (Phase 2)
// ═══════════════════════════════════════════════════════
async function getSupabaseConfig() {
  const { supabaseUrl, supabaseAnonKey } = await chrome.storage.local.get(["supabaseUrl", "supabaseAnonKey"]);
  if (!supabaseUrl || !supabaseAnonKey) return null;
  return { supabaseUrl: supabaseUrl.replace(/\/$/, ""), supabaseAnonKey };
}

function supabaseHeaders(anonKey) {
  return {
    "apikey": anonKey,
    "Authorization": `Bearer ${anonKey}`,
    "Content-Type": "application/json",
  };
}

async function fetchCommunityBlocklist() {
  const cfg = await getSupabaseConfig();
  if (!cfg) return;
  try {
    const resp = await fetch(
      `${cfg.supabaseUrl}/rest/v1/urls?select=url&verdict=in.(dangerous,suspicious)&limit=50000`,
      { headers: supabaseHeaders(cfg.supabaseAnonKey) }
    );
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const rows = await resp.json();
    const urls = rows.map((r) => r.url).filter(Boolean);
    await dbPutBatch("community", urls);
    communitySet = new Set(urls);
    console.log(`LinkGuard: Community blocklist updated — ${urls.length} URLs`);
  } catch (e) {
    console.error("LinkGuard: Community blocklist fetch failed", e.message);
  }
}

// Fire-and-forget: silently report a URL to Supabase reports table
async function reportUrlToSupabase(url, verdictAtTime) {
  const cfg = await getSupabaseConfig();
  if (!cfg) return;
  try {
    await fetch(`${cfg.supabaseUrl}/rest/v1/reports`, {
      method: "POST",
      headers: supabaseHeaders(cfg.supabaseAnonKey),
      body: JSON.stringify({ url, verdict_at_time: verdictAtTime }),
    });
  } catch (e) {
    console.error("LinkGuard: report submission failed", e.message);
  }
}

// Silently log dangerous/suspicious verdicts for ML training data
// Never logs safe or unknown verdicts (privacy)
async function logScanToSupabase(url, verdict, reason) {
  if (verdict === "safe" || verdict === "unknown") return;
  const cfg = await getSupabaseConfig();
  if (!cfg) return;
  fetch(`${cfg.supabaseUrl}/rest/v1/scan_logs`, {
    method: "POST",
    headers: supabaseHeaders(cfg.supabaseAnonKey),
    body: JSON.stringify({ url, verdict, source: reason || "extension", device: "chrome-extension" }),
  }).catch(() => {});
}

async function refreshLists() {
  console.log("LinkGuard: Refreshing blocklists...");
  await Promise.all([fetchURLhaus(), fetchOpenPhish(), fetchThreatFox(), fetchCommunityBlocklist()]);
  await dbPut("meta", "lastRefresh", Date.now());
}

async function initLists() {
  await loadListsFromDB();
  const lastRefresh = await dbGet("meta", "lastRefresh");
  if (!lastRefresh || Date.now() - lastRefresh > LIST_REFRESH_MS) {
    refreshLists(); // fire and forget — don't block startup
  }
}

// ═══════════════════════════════════════════════════════
// SCAN PIPELINE
// ═══════════════════════════════════════════════════════
function normalizeUrl(url) {
  try {
    return new URL(url).href.replace(/\/$/, "");
  } catch {
    return url;
  }
}

function checkLocalLists(url) {
  const norm = normalizeUrl(url);
  if (urlhausSet.has(url) || urlhausSet.has(norm))
    return { verdict: "dangerous", reason: "Found in URLhaus malware database" };
  if (openphishSet.has(url) || openphishSet.has(norm))
    return { verdict: "dangerous", reason: "Found in OpenPhish phishing database" };
  if (threatfoxSet.has(url) || threatfoxSet.has(norm))
    return { verdict: "dangerous", reason: "Found in ThreatFox threat database" };
  if (communitySet.has(url) || communitySet.has(norm))
    return { verdict: "dangerous", reason: "Reported by the LinkGuard community" };
  return null;
}

function runHeuristics(url) {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();

    const suspiciousPatterns = [
      /kyc[\-.]?update/i,
      /pan[\-.]?verify/i,
      /aadhaar[\-.]?link/i,
      /sbi[\-.]?secure/i,
      /paytm[\-.]?reward/i,
      /phonepe[\-.]?cash/i,
      /gpay[\-.]?prize/i,
      /lottery[\-.]?winner/i,
      /free[\-.]?recharge/i,
      /otp[\-.]?verify/i,
    ];
    for (const pat of suspiciousPatterns) {
      if (pat.test(host) || pat.test(u.pathname))
        return { verdict: "suspicious", reason: "Matches known India scam pattern" };
    }

    const sketchyTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".click"];
    if (sketchyTLDs.some((tld) => host.endsWith(tld)))
      return { verdict: "suspicious", reason: "High-risk domain extension" };

    if (host.split(".").length > 4)
      return { verdict: "suspicious", reason: "Unusually deep subdomain" };

    return { verdict: "safe", reason: null };
  } catch {
    return { verdict: "safe", reason: null };
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function urlToVTId(url) {
  // base64url without padding
  return btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function interpretVTStats(stats) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  if (malicious >= 2)
    return { verdict: "dangerous", reason: `Flagged by ${malicious} security engines on VirusTotal` };
  if (malicious === 1)
    return { verdict: "suspicious", reason: "Flagged by 1 security engine on VirusTotal" };
  if (suspicious > 0)
    return { verdict: "suspicious", reason: `Marked suspicious by ${suspicious} engine${suspicious > 1 ? "s" : ""} on VirusTotal` };
  return { verdict: "safe", reason: null };
}

async function checkVirusTotal(url, apiKey) {
  try {
    // Try cached report first (no new scan quota used if URL was seen before)
    const urlId = urlToVTId(url);
    const cacheResp = await fetch(`${VT_BASE}/urls/${urlId}`, {
      headers: { "x-apikey": apiKey },
    });
    if (cacheResp.status === 429) return { verdict: "unknown", reason: "Rate limit reached — could not verify this link" };
    if (cacheResp.ok) {
      const data = await cacheResp.json();
      const stats = data?.data?.attributes?.last_analysis_stats;
      if (stats) return interpretVTStats(stats);
    }

    // No cached report — submit for fresh scan
    const body = new URLSearchParams();
    body.append("url", url);
    const submitResp = await fetch(`${VT_BASE}/urls`, {
      method: "POST",
      headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (submitResp.status === 429) return { verdict: "unknown", reason: "Rate limit reached — could not verify this link" };
    if (!submitResp.ok) return { verdict: "unknown", reason: `VirusTotal error (${submitResp.status})` };

    const submitData = await submitResp.json();
    const analysisId = submitData?.data?.id;
    if (!analysisId) return { verdict: "unknown", reason: "VirusTotal did not return an analysis ID" };

    // Poll for completed analysis (max 3 tries, 2s apart)
    for (let i = 0; i < 3; i++) {
      await sleep(2000);
      const pollResp = await fetch(`${VT_BASE}/analyses/${analysisId}`, {
        headers: { "x-apikey": apiKey },
      });
      if (pollResp.status === 429) return { verdict: "unknown", reason: "Rate limit reached — could not verify this link" };
      if (!pollResp.ok) continue;
      const result = await pollResp.json();
      if (result?.data?.attributes?.status === "completed") {
        return interpretVTStats(result.data.attributes.stats || {});
      }
    }

    return { verdict: "unknown", reason: "Scan timed out — could not fully verify this link" };
  } catch (e) {
    return { verdict: "unknown", reason: "Could not reach VirusTotal" };
  }
}

async function scanUrl(url, includeVT) {
  await ensureListsLoaded();

  // 1. Cache
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return { verdict: cached.verdict, reason: cached.reason };
  }

  // 2. Local blocklists
  const listResult = checkLocalLists(url);
  if (listResult) {
    urlCache.set(url, { ...listResult, ts: Date.now() });
    return listResult;
  }

  // 3. India heuristics
  const heuristic = runHeuristics(url);
  if (heuristic.verdict !== "safe") {
    urlCache.set(url, { ...heuristic, ts: Date.now() });
    return heuristic;
  }

  // 4. AI Model — Phase 4 placeholder (not yet active)
  // Uncomment and implement checkWithAIModel() once the HuggingFace model is published.
  // Runs between heuristics and VirusTotal — expected to cut VT calls by ~80-90%.
  //
  // const { hfApiKey } = await chrome.storage.local.get("hfApiKey");
  // if (hfApiKey && includeVT) {
  //   const aiResult = await checkWithAIModel(url, hfApiKey);
  //   if (aiResult && aiResult.score >= 0.90) {
  //     const r = { verdict: aiResult.label, reason: `LinkGuard AI model (${(aiResult.score * 100).toFixed(0)}% confidence)` };
  //     urlCache.set(url, { ...r, ts: Date.now() });
  //     return r;
  //   }
  //   // score < 0.90 → uncertain → fall through to VirusTotal
  // }

  // 5. VirusTotal (click-time scans only)
  if (includeVT) {
    const { vtApiKey } = await chrome.storage.local.get("vtApiKey");
    if (vtApiKey) {
      const vtResult = await checkVirusTotal(url, vtApiKey);
      urlCache.set(url, { ...vtResult, ts: Date.now() });
      return vtResult;
    }
    return { verdict: "unknown", reason: "No VirusTotal API key configured — add it in Settings" };
  }

  // Pre-scan: return heuristic result (safe)
  urlCache.set(url, { ...heuristic, ts: Date.now() });
  return heuristic;
}

// ═══════════════════════════════════════════════════════
// INJECTION (kept from Gexplain)
// ═══════════════════════════════════════════════════════
async function ensureInjectedAllFrames(tabId) {
  try { await chrome.tabs.sendMessage(tabId, { action: "ping" }); } catch (_) {}
  try {
    await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ["content.js"] });
    await chrome.scripting.insertCSS({ target: { tabId, allFrames: true }, files: ["content.css"] });
  } catch (e) {
    console.log("Injection failed:", e.message);
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  // Only set defaults for keys that don't exist yet — never overwrite user's saved settings
  const DEFAULTS = {
    vtApiKey: "",
    textExplainerEnabled: false,
    customApiKey: "",
    modelName: DEFAULT_MODEL,
    supabaseUrl: "",
    supabaseAnonKey: "",
  };
  const existing = await chrome.storage.local.get(Object.keys(DEFAULTS));
  const toSet = {};
  for (const [k, v] of Object.entries(DEFAULTS)) {
    if (!(k in existing)) toSet[k] = v;
  }
  if (Object.keys(toSet).length) await chrome.storage.local.set(toSet);
  await initLists();
  const tabs = await chrome.tabs.query({ status: "complete" });
  for (const tab of tabs) {
    if (tab.id && tab.url?.startsWith("http")) await ensureInjectedAllFrames(tab.id);
  }
});

chrome.runtime.onStartup.addListener(() => {
  initLists();
});

// Daily list refresh alarm
chrome.alarms.create("refreshLists", { periodInMinutes: 60 * 24 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "refreshLists") refreshLists();
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url?.startsWith("http")) {
    await ensureInjectedAllFrames(tabId);
  }
});

chrome.webNavigation.onHistoryStateUpdated.addListener(async (details) => {
  if (details.frameId === 0) await ensureInjectedAllFrames(details.tabId);
});

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId: details.tabId, frameIds: [details.frameId] },
        files: ["content.js"],
      });
    } catch (_) {}
  }
});

// ═══════════════════════════════════════════════════════
// MESSAGE HANDLER
// ═══════════════════════════════════════════════════════
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "ping") {
    sendResponse({ pong: true });
    return;
  }

  if (request.action === "getSettings") {
    chrome.storage.local.get(
      ["vtApiKey", "textExplainerEnabled", "customApiKey", "modelName", "supabaseUrl", "supabaseAnonKey"],
      (res) => sendResponse(res)
    );
    return true;
  }

  if (request.action === "saveSettings") {
    const { vtApiKey, textExplainerEnabled, customApiKey, modelName, supabaseUrl, supabaseAnonKey } = request;
    chrome.storage.local.set(
      { vtApiKey, textExplainerEnabled, customApiKey, modelName, supabaseUrl, supabaseAnonKey },
      () => sendResponse({ ok: true })
    );
    return true;
  }

  // Pre-scan on hover: local lists + heuristics only, no VT, fire-and-forget
  if (request.action === "preScanUrl" && sender.tab) {
    scanUrl(request.url, false).catch(() => {});
    return false;
  }

  // Host safety check: local lists + heuristics only (no VT), responds with verdict
  if (request.action === "checkHost") {
    scanUrl(request.url, false)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ verdict: "unknown", reason: "Host check failed" }));
    return true;
  }

  // Full scan on click: includes VT
  if (request.action === "scanUrl" && sender.tab) {
    const tabId = sender.tab.id;
    scanUrl(request.url, true).then((result) => {
      // Update tab stats
      const stats = tabStats.get(tabId) || { total: 0, scanned: 0, safe: 0, suspicious: 0, dangerous: 0, unknown: 0 };
      stats.scanned++;
      stats[result.verdict] = (stats[result.verdict] || 0) + 1;
      tabStats.set(tabId, stats);
      // Log threats to Supabase (fire-and-forget, never blocks scan)
      logScanToSupabase(request.url, result.verdict, result.reason);
      sendResponse(result);
    }).catch((e) => {
      sendResponse({ verdict: "unknown", reason: "Scan error: " + e.message });
    });
    return true;
  }

  // User-initiated report: immediately protect locally + send to Supabase
  if (request.action === "reportUrl") {
    const rawUrl  = request.url;
    const normUrl = normalizeUrl(rawUrl);

    // 1. Bust the verdict cache so the next scan doesn't return stale "safe"
    urlCache.delete(rawUrl);
    urlCache.delete(normUrl);

    // 2. Add to the in-memory community set immediately
    communitySet.add(rawUrl);
    communitySet.add(normUrl);

    // 3. Persist both forms to IndexedDB so protection survives service worker restart
    dbPut("community", rawUrl,  1).catch(() => {});
    dbPut("community", normUrl, 1).catch(() => {});

    // 4. Send to Supabase (trigger will promote to urls table)
    reportUrlToSupabase(rawUrl, request.verdict).catch(() => {});

    sendResponse({ ok: true });
    return true;
  }

  // Report total links on page (called at page load)
  if (request.action === "reportPageLinks" && sender.tab) {
    const tabId = sender.tab.id;
    const existing = tabStats.get(tabId) || {};
    tabStats.set(tabId, { total: request.count, scanned: 0, safe: 0, suspicious: 0, dangerous: 0, unknown: 0, ...existing });
    return false;
  }

  if (request.action === "getTabStats") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) sendResponse(tabStats.get(tabs[0].id) || null);
      else sendResponse(null);
    });
    return true;
  }

  // Gemini text explain
  if (request.action === "explain") {
    handleExplain(request.text, sendResponse);
    return true;
  }

  if (request.action === "testCall") {
    testCall(sendResponse);
    return true;
  }

  if (request.action === "refreshLists") {
    refreshLists().then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (request.action === "getListStats") {
    sendResponse({
      urlhaus:   urlhausSet.size,
      openphish: openphishSet.size,
      threatfox: threatfoxSet.size,
      community: communitySet.size,
    });
    return true;
  }
});

// ═══════════════════════════════════════════════════════
// GEMINI EXPLAIN (kept from Gexplain — gated by setting)
// ═══════════════════════════════════════════════════════
async function handleExplain(text, sendResponse) {
  try {
    const { customApiKey, modelName } = await chrome.storage.local.get(["customApiKey", "modelName"]);
    if (!customApiKey) return sendResponse({ error: true, message: "Add your Gemini API key in the Text Explainer tab." });
    const model = modelName || DEFAULT_MODEL;
    const url = `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${customApiKey}`;
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: `Briefly explain: ${text}` }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 256 },
      }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      return sendResponse({ error: true, message: err.error?.message || `HTTP ${r.status}` });
    }
    const data = await r.json();
    const explanation = data?.candidates?.[0]?.content?.parts?.[0]?.text || "";
    if (!explanation) return sendResponse({ error: true, message: `No output. Finish: ${data?.candidates?.[0]?.finishReason || "UNKNOWN"}` });
    sendResponse({ error: false, explanation });
  } catch (e) {
    sendResponse({ error: true, message: e.message || "Unknown error" });
  }
}

async function testCall(sendResponse) {
  try {
    const { customApiKey, modelName } = await chrome.storage.local.get(["customApiKey", "modelName"]);
    if (!customApiKey) return sendResponse({ ok: false, message: "No Gemini API key set." });
    const model = modelName || DEFAULT_MODEL;
    const url = `https://generativelanguage.googleapis.com/v1/models/${model}:generateContent?key=${customApiKey}`;
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: "ping" }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 8 },
      }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      return sendResponse({ ok: false, message: err.error?.message || `HTTP ${r.status}` });
    }
    const data = await r.json();
    sendResponse({ ok: true, message: data?.candidates?.[0]?.content?.parts?.[0]?.text || "OK" });
  } catch (e) {
    sendResponse({ ok: false, message: e.message || "Error" });
  }
}
