const $ = (id) => document.getElementById(id);

// ═══════════════════════════════════════════════════════
// TAB SWITCHING
// ═══════════════════════════════════════════════════════
const tabs = {
  dashboard: { btn: $("tab-dashboard"), panel: $("panel-dashboard") },
  settings:  { btn: $("tab-settings"),  panel: $("panel-settings")  },
  explainer: { btn: $("tab-explainer"), panel: $("panel-explainer") },
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
// DASHBOARD
// ═══════════════════════════════════════════════════════
chrome.runtime.sendMessage({ action: "getTabStats" }, (stats) => {
  const el = $("stats-content");
  if (!stats || (!stats.scanned && !stats.total)) {
    el.innerHTML = '<div class="no-scan">Click any link on a page<br>to start scanning</div>';
    return;
  }

  el.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card stat-total">
        <div class="stat-num">${stats.total || 0}</div>
        <div class="stat-label">Links</div>
      </div>
      <div class="stat-card stat-scanned">
        <div class="stat-num">${stats.scanned || 0}</div>
        <div class="stat-label">Scanned</div>
      </div>
      <div class="stat-card stat-safe">
        <div class="stat-num">${stats.safe || 0}</div>
        <div class="stat-label">Safe</div>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat-card stat-suspicious">
        <div class="stat-num">${stats.suspicious || 0}</div>
        <div class="stat-label">Suspicious</div>
      </div>
      <div class="stat-card stat-dangerous">
        <div class="stat-num">${stats.dangerous || 0}</div>
        <div class="stat-label">Dangerous</div>
      </div>
      <div class="stat-card stat-unknown">
        <div class="stat-num">${stats.unknown || 0}</div>
        <div class="stat-label">Unknown</div>
      </div>
    </div>
  `;
  el.className = "";
});

// ═══════════════════════════════════════════════════════
// SETTINGS — load
// ═══════════════════════════════════════════════════════
chrome.runtime.sendMessage({ action: "getSettings" }, (res) => {
  $("vtKey").value           = res?.vtApiKey       || "";
  $("supabaseUrl").value     = res?.supabaseUrl    || "";
  $("supabaseAnonKey").value = res?.supabaseAnonKey || "";
  $("geminiKey").value       = res?.customApiKey   || "";
  $("explainer-toggle").checked = res?.textExplainerEnabled || false;

  // Show Supabase connection status
  updateSupabaseStatus(res?.supabaseUrl || "", res?.supabaseAnonKey || "");
});

// Update the Supabase status pill whenever inputs change
$("supabaseUrl").addEventListener("input", () =>
  updateSupabaseStatus($("supabaseUrl").value.trim(), $("supabaseAnonKey").value.trim())
);
$("supabaseAnonKey").addEventListener("input", () =>
  updateSupabaseStatus($("supabaseUrl").value.trim(), $("supabaseAnonKey").value.trim())
);

function updateSupabaseStatus(url, key) {
  const el    = $("supabase-status");
  const label = $("supabase-status-text");
  const hasUrl = url.length > 0;
  const hasKey = key.length > 0;

  if (hasUrl && hasKey) {
    el.className    = "supabase-status connected";
    label.textContent = "Connected — community blocklist active";
  } else if (hasUrl || hasKey) {
    el.className    = "supabase-status partial";
    label.textContent = hasUrl
      ? "URL saved — paste anon key and Save"
      : "Key saved — paste project URL and Save";
  } else {
    el.className    = "supabase-status";
    label.textContent = "Not configured — community blocklist disabled";
  }
}

// ═══════════════════════════════════════════════════════
// SETTINGS — save
// ═══════════════════════════════════════════════════════
$("save-settings").onclick = () => {
  const vtApiKey       = $("vtKey").value.trim();
  const supabaseUrl    = $("supabaseUrl").value.trim();
  const supabaseAnonKey = $("supabaseAnonKey").value.trim();
  chrome.runtime.sendMessage(
    {
      action: "saveSettings",
      vtApiKey,
      supabaseUrl,
      supabaseAnonKey,
      textExplainerEnabled: $("explainer-toggle").checked,
      customApiKey: $("geminiKey").value.trim(),
      modelName: "gemini-2.0-flash",
    },
    (r) => {
      showStatus("settings-status", r?.ok ? "✓ Saved" : "Save failed", r?.ok);
      updateSupabaseStatus(supabaseUrl, supabaseAnonKey);
      if (r?.ok && supabaseUrl && supabaseAnonKey) {
        // Immediately pull the community blocklist so it's active without waiting for daily refresh
        chrome.runtime.sendMessage({ action: "refreshLists" }, () => loadListStats());
      }
    }
  );
};

// Populate blocklist sizes
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
// TEXT EXPLAINER — save + test
// ═══════════════════════════════════════════════════════
$("save-explainer").onclick = () => {
  chrome.runtime.sendMessage(
    {
      action: "saveSettings",
      vtApiKey:             $("vtKey").value.trim(),
      supabaseUrl:          $("supabaseUrl").value.trim(),
      supabaseAnonKey:      $("supabaseAnonKey").value.trim(),
      textExplainerEnabled: $("explainer-toggle").checked,
      customApiKey:         $("geminiKey").value.trim(),
      modelName:            "gemini-2.0-flash",
    },
    (r) => showStatus("explainer-status", r?.ok ? "✓ Saved" : "Save failed", r?.ok)
  );
};

$("test-gemini").onclick = () => {
  $("explainer-status").textContent = "Testing…";
  $("explainer-status").className   = "status";
  chrome.runtime.sendMessage({ action: "testCall" }, (r) => {
    if (!r) return showStatus("explainer-status", "No response", false);
    showStatus("explainer-status", r.ok ? "✓ Gemini connected" : r.message || "Failed", r.ok);
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
