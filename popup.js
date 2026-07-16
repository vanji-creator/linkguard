const $ = (id) => document.getElementById(id);

// Version badge comes from the manifest — never hardcoded in HTML
$("version-badge").textContent = "v" + chrome.runtime.getManifest().version;

// ═══════════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════════
const tabs = {
  dashboard: { btn: $("tab-dashboard"), panel: $("panel-dashboard") },
  settings:  { btn: $("tab-settings"),  panel: $("panel-settings")  },
  help:      { btn: $("tab-help"),      panel: $("panel-help")      },
};

function switchTab(name) {
  Object.entries(tabs).forEach(([key, val]) => {
    const active = key === name;
    val.btn.classList.toggle("active", active);
    val.panel.style.display = active ? "" : "none";
  });
}

Object.keys(tabs).forEach((name) => {
  tabs[name].btn.onclick = () => switchTab(name);
});

// ═══════════════════════════════════════════════════════
// DASHBOARD — per-tab scan stats
// ═══════════════════════════════════════════════════════
chrome.runtime.sendMessage({ action: "getTabStats" }, (stats) => {
  const el = $("stats-content");
  if (!stats || (!stats.scanned && !stats.total)) {
    el.innerHTML = '<div class="no-scan">Click any link on a page<br>to start scanning</div>';
    return;
  }

  el.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-num">${stats.total || 0}</div>
        <div class="stat-label">Links</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">${stats.scanned || 0}</div>
        <div class="stat-label">Scanned</div>
      </div>
      <div class="stat-card stat-safe">
        <div class="stat-num">${stats.safe || 0}</div>
        <div class="stat-label">Safe</div>
      </div>
      <div class="stat-card stat-suspicious">
        <div class="stat-num">${stats.suspicious || 0}</div>
        <div class="stat-label">Suspicious</div>
      </div>
      <div class="stat-card stat-dangerous">
        <div class="stat-num">${stats.dangerous || 0}</div>
        <div class="stat-label">Dangerous</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">${stats.unknown || 0}</div>
        <div class="stat-label">Unknown</div>
      </div>
    </div>
  `;
  el.className = "";
});

// ═══════════════════════════════════════════════════════
// DASHBOARD — on-device model status card
// ═══════════════════════════════════════════════════════
chrome.runtime.sendMessage({ action: "getModelStatus" }, (res) => {
  const dot = $("model-status").querySelector(".model-dot");
  const sub = $("model-status").querySelector(".model-sub");
  if (!res || !res.ready) {
    dot.className = "model-dot off";
    sub.textContent = "Model unavailable";
    return;
  }
  const meta = res.meta || {};
  const vocab = meta.vocab_size ? (meta.vocab_size / 1000).toFixed(1) + "k features" : "";
  const version = meta.version ? "v" + meta.version : "";
  const state = res.enabled ? "Active" : "Disabled in Settings";
  dot.className = "model-dot " + (res.enabled ? "on" : "off");
  sub.textContent = [version, vocab, state].filter(Boolean).join(" · ");
});

// ═══════════════════════════════════════════════════════
// DASHBOARD — protection summary
// ═══════════════════════════════════════════════════════
function renderProtectionSummary(settings, listStats) {
  if (listStats) {
    const total = (listStats.urlhaus || 0) + (listStats.openphish || 0)
                + (listStats.threatfox || 0) + (listStats.community || 0);
    const el = $("sum-lists");
    el.textContent = total >= 1000 ? (total / 1000).toFixed(1) + "k" : String(total);
    el.className = "summary-val";
  }
  if (settings) {
    const vt = $("sum-vt");
    vt.textContent = settings.vtApiKey ? "Configured" : "Not set";
    vt.className = settings.vtApiKey ? "summary-val" : "summary-val dim";
  }
}

// ═══════════════════════════════════════════════════════
// SETTINGS — load
// ═══════════════════════════════════════════════════════
chrome.runtime.sendMessage({ action: "getSettings" }, (res) => {
  $("vtKey").value          = res?.vtApiKey || "";
  $("model-toggle").checked = res?.modelEnabled !== false;   // default ON
  renderProtectionSummary(res, null);
});

// ═══════════════════════════════════════════════════════
// SETTINGS — save
// ═══════════════════════════════════════════════════════
$("save-settings").onclick = () => {
  const vtApiKey = $("vtKey").value.trim();
  chrome.runtime.sendMessage(
    {
      action: "saveSettings",
      vtApiKey,
      modelEnabled: $("model-toggle").checked,
    },
    (r) => {
      showStatus("settings-status", r?.ok ? "✓ Saved" : "Save failed", r?.ok);
      renderProtectionSummary({ vtApiKey }, null);
    }
  );
};

// Populate blocklist sizes (settings pill + dashboard summary)
function loadListStats() {
  chrome.runtime.sendMessage({ action: "getListStats" }, (stats) => {
    const el = $("lists-status");
    if (!stats) { el.textContent = "Lists not loaded yet."; return; }
    const fmt = (n) => n >= 1000 ? (n / 1000).toFixed(0) + "k" : n || "0";
    el.innerHTML =
      `URLhaus <span>${fmt(stats.urlhaus)}</span> · ` +
      `OpenPhish <span>${fmt(stats.openphish)}</span> · ` +
      `ThreatFox <span>${fmt(stats.threatfox)}</span>` +
      (stats.community > 0 ? ` · Community <span>${fmt(stats.community)}</span>` : "");
    renderProtectionSummary(null, stats);
  });
}
loadListStats();

// Refresh blocklists manually
$("refresh-lists").onclick = () => {
  $("settings-status").textContent = "Refreshing…";
  $("settings-status").className   = "status";
  chrome.runtime.sendMessage({ action: "refreshLists" }, () => {
    showStatus("settings-status", "✓ Lists refreshed", true);
    loadListStats();
  });
};

// ═══════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════
function showStatus(id, msg, ok) {
  const el = $(id);
  el.textContent = msg;
  el.className   = ok ? "status ok" : "status err";
  setTimeout(() => { el.textContent = ""; el.className = "status"; }, 3000);
}
