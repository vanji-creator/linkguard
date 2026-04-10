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
  if (!stats) {
    el.innerHTML = '<div class="no-scan">Click a link on any page to scan it</div>';
    return;
  }

  el.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card stat-total">
        <div class="stat-num">${stats.total || 0}</div>
        <div class="stat-label">Links on Page</div>
      </div>
      <div class="stat-card stat-scanned">
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
        <div class="stat-num" style="color:#636366">${stats.unknown || 0}</div>
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
  $("vtKey").value = res?.vtApiKey || "";
  $("geminiKey").value = res?.customApiKey || "";
  $("explainer-toggle").checked = res?.textExplainerEnabled || false;
});

// ═══════════════════════════════════════════════════════
// SETTINGS — save
// ═══════════════════════════════════════════════════════
$("save-settings").onclick = () => {
  const vtApiKey = $("vtKey").value.trim();
  chrome.runtime.sendMessage(
    { action: "saveSettings", vtApiKey, textExplainerEnabled: $("explainer-toggle").checked, customApiKey: $("geminiKey").value.trim(), modelName: "gemini-2.0-flash" },
    (r) => showStatus("settings-status", r?.ok ? "✓ Saved" : "Save failed", r?.ok)
  );
};

// Refresh blocklists manually
$("refresh-lists").onclick = () => {
  $("settings-status").textContent = "Refreshing lists…";
  $("settings-status").className = "status";
  // Trigger refresh via alarm or direct background call
  chrome.runtime.sendMessage({ action: "refreshLists" }, () => {
    showStatus("settings-status", "✓ Lists refreshed", true);
  });
};

// ═══════════════════════════════════════════════════════
// TEXT EXPLAINER — save + test
// ═══════════════════════════════════════════════════════
$("save-explainer").onclick = () => {
  chrome.runtime.sendMessage(
    {
      action: "saveSettings",
      vtApiKey: $("vtKey").value.trim(),
      textExplainerEnabled: $("explainer-toggle").checked,
      customApiKey: $("geminiKey").value.trim(),
      modelName: "gemini-2.0-flash",
    },
    (r) => showStatus("explainer-status", r?.ok ? "✓ Saved" : "Save failed", r?.ok)
  );
};

$("test-gemini").onclick = () => {
  $("explainer-status").textContent = "Testing…";
  $("explainer-status").className = "status";
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
  el.className = ok ? "status ok" : "status err";
  setTimeout(() => { el.textContent = ""; el.className = "status"; }, 3000);
}
