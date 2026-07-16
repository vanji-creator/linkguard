(() => {
  if (window.__LINKGUARD_LOADED__) return;
  window.__LINKGUARD_LOADED__ = true;

  // ═══════════════════════════════════════════════════════
  // PING
  // ═══════════════════════════════════════════════════════
  chrome.runtime.onMessage.addListener((req, _s, sendResponse) => {
    if (req?.action === "ping") sendResponse({ pong: true });
  });

  // ═══════════════════════════════════════════════════════
  // SETTINGS (cached at load)
  // ═══════════════════════════════════════════════════════
  let textExplainerEnabled = false;
  chrome.runtime.sendMessage({ action: "getSettings" }, (res) => {
    textExplainerEnabled = res?.textExplainerEnabled || false;
  });

  // ═══════════════════════════════════════════════════════
  // TRUSTED DOMAINS
  // ═══════════════════════════════════════════════════════
  const TRUSTED_DOMAINS = [
    // Google family
    "google.com", "google.co.in", "google.co.uk", "google.de", "google.fr",
    "youtube.com", "youtu.be", "googleapis.com", "gmail.com", "goo.gl",
    // Microsoft
    "microsoft.com", "office.com", "live.com", "outlook.com", "bing.com",
    // Apple
    "apple.com", "icloud.com",
    // Dev / knowledge
    "github.com", "githubusercontent.com", "stackoverflow.com",
    "mozilla.org", "wikipedia.org", "wikimedia.org",
    // India — government & regulators
    "gov.in", "nic.in", "rbi.org.in", "npci.org.in",
    "uidai.gov.in", "incometax.gov.in", "irctc.co.in", "india.gov.in",
    // India — banks
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "netbanking.hdfc.com",
    "icicibank.com",
    "axisbank.com",
    "kotak.com", "kotakbank.com",
    "pnbindia.in", "bob.co.in", "canarabank.com",
    // India — payments & fintech
    "paytm.com", "phonepe.com", "razorpay.com", "cashfree.com",
    "billdesk.com", "ccavenue.com",
    // Social
    "linkedin.com", "twitter.com", "x.com", "reddit.com",
    "facebook.com", "instagram.com",
    // Commerce
    "amazon.com", "amazon.in", "flipkart.com", "myntra.com", "meesho.com",
    // Other
    "cloudflare.com", "jsdelivr.net", "cdnjs.cloudflare.com",
  ];

  // Match hostname or any subdomain of a trusted domain
  function isTrusted(hostname) {
    const h = hostname.toLowerCase();
    return TRUSTED_DOMAINS.some((t) => h === t || h.endsWith("." + t));
  }

  // ═══════════════════════════════════════════════════════
  // UTILS
  // ═══════════════════════════════════════════════════════
  function escapeHtml(str) {
    const d = document.createElement("div");
    d.textContent = str;
    return d.innerHTML;
  }

  function truncate(str, len) {
    return str.length > len ? str.slice(0, len) + "…" : str;
  }

  // Verdict source → display label. This is a WHITELIST: the source
  // string from the background is never put into HTML directly — only
  // these fixed labels are. Unknown/missing sources render no chip.
  const SOURCE_LABELS = {
    urlhaus: "URLhaus",
    openphish: "OpenPhish",
    threatfox: "ThreatFox",
    community: "Community",
    heuristic: "Heuristics",
    model: "On-device AI",
    "remote-ai": "LinkGuard AI",
    virustotal: "VirusTotal",
    trusted: "Trusted domain",
  };

  function sourceChipHtml(source) {
    const label = SOURCE_LABELS[source];
    return label ? `<div class="lg-source-chip">${label}</div>` : "";
  }

  function resolveHref(a) {
    try {
      const href = new URL(a.href, location.href).href;
      return href.startsWith("http") ? href : null;
    } catch {
      return null;
    }
  }

  // ═══════════════════════════════════════════════════════
  // BADGE MANAGEMENT
  // ═══════════════════════════════════════════════════════
  function getBadge(a) {
    return a.querySelector(".lg-badge");
  }

  function setBadgeVerdict(a, verdict) {
    const badge = getBadge(a);
    if (!badge) return;
    badge.className = `lg-badge lg-badge-${verdict}`;
    badge.title = verdict.charAt(0).toUpperCase() + verdict.slice(1);
    a.classList.remove("lg-safe", "lg-suspicious", "lg-dangerous", "lg-unknown");
    a.classList.add(`lg-${verdict}`);
    a.__lg_verdict = verdict; // persist verdict on element for session
  }

  // ═══════════════════════════════════════════════════════
  // HOST SAFETY STATE
  // Resolved once at page load before any link handlers attach.
  // 'trusted' | 'safe' → same-origin links skipped
  // 'suspicious' | 'dangerous' | 'unknown' → same-origin links scanned too
  // ═══════════════════════════════════════════════════════
  let currentHostStatus = "checking";

  // ═══════════════════════════════════════════════════════
  // LINK HANDLER ATTACHMENT
  // ═══════════════════════════════════════════════════════
  function attachLinkHandlers(a) {
    if (a.__lg_attached) return;
    const href = resolveHref(a);
    if (!href) return;
    a.__lg_attached = true;
    // Remove any stale badge that may have been copied via cloneNode()
    a.querySelector(".lg-badge")?.remove();

    let destHost;
    try { destHost = new URL(href).hostname.toLowerCase(); } catch { return; }

    const currentHost = window.location.hostname.toLowerCase();
    const isSameOrigin = destHost === currentHost;

    // Filter 1: same-origin — behaviour depends on host safety
    if (isSameOrigin) {
      if (currentHostStatus === "trusted" || currentHostStatus === "safe") {
        return; // clean host, internal navigation is safe — leave link alone
      }
      // Host is suspicious / dangerous / unknown → scan same-origin links too
      // fall through to intercept logic below (no early return)
    }

    // Filter 2: trusted destination (cross-origin only) → green badge, no intercept
    if (!isSameOrigin && isTrusted(destHost)) {
      const badge = document.createElement("span");
      badge.className = "lg-badge lg-badge-safe";
      badge.title = "Trusted domain";
      a.appendChild(badge);
      a.classList.add("lg-safe");
      return;
    }

    // Filter 3: unknown cross-origin OR same-origin on bad host → neutral badge + scan on click
    const badge = document.createElement("span");
    badge.className = "lg-badge lg-badge-neutral";
    badge.title = a.target === "_blank"
      ? "LinkGuard: click to scan (opens in new tab)"
      : "LinkGuard: click to scan";
    a.appendChild(badge);

    a.addEventListener("mouseover", () => {
      chrome.runtime.sendMessage({ action: "preScanUrl", url: href }, (result) => {
        if (chrome.runtime.lastError || !result) return;
        // Local pre-scan is only authoritative when it FLAGS something
        // (blocklist/heuristic hit) — a local "safe" is not a full scan.
        if (result.verdict === "suspicious" || result.verdict === "dangerous") {
          a.__lg_result = result;
          setBadgeVerdict(a, result.verdict);
        }
      });
    });

    a.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const isNewTab = a.target === "_blank" || e.ctrlKey || e.metaKey || e.shiftKey;
      // Already confirmed safe this session — navigate directly, no overlay
      if (a.__lg_verdict === "safe") {
        navigate(href, isNewTab);
        return;
      }
      // Already scanned and flagged — skip the "Scan?" prompt, show the
      // verdict straight away (with a Scan-again button on the card)
      if (a.__lg_result && a.__lg_result.verdict !== "safe") {
        const overlay = buildOverlay();
        showVerdict(overlay, href, isNewTab, a, a.__lg_result);
        return;
      }
      showScanOverlay(href, isNewTab, a);
    }, { capture: true });
  }

  // Batch pre-scan: right after interception attaches, ask the background
  // to check every unscanned link locally (blocklists + heuristics, no
  // VT, no model) — so dangerous links turn red BEFORE any hover/click.
  function preScanNewLinks() {
    const hrefToAnchors = new Map();
    document.querySelectorAll("a[href]").forEach((a) => {
      if (!a.__lg_attached || a.__lg_prescanned) return;
      if (a.__lg_verdict || a.__lg_result) return;       // already judged
      if (!getBadge(a)) return;                          // not an intercepted link
      const href = resolveHref(a);
      if (!href) return;
      a.__lg_prescanned = true;
      if (!hrefToAnchors.has(href)) hrefToAnchors.set(href, []);
      hrefToAnchors.get(href).push(a);
    });
    if (!hrefToAnchors.size) return;

    chrome.runtime.sendMessage(
      { action: "preScanBatch", urls: [...hrefToAnchors.keys()] },
      (flagged) => {
        if (chrome.runtime.lastError || !flagged) return;
        for (const [href, result] of Object.entries(flagged)) {
          for (const a of hrefToAnchors.get(href) || []) {
            a.__lg_result = result;
            setBadgeVerdict(a, result.verdict);
          }
        }
      }
    );
  }

  function attachAllLinks() {
    document.querySelectorAll("a[href]").forEach(attachLinkHandlers);
    preScanNewLinks();
    chrome.runtime.sendMessage({
      action: "reportPageLinks",
      count: document.querySelectorAll("a[href]").length,
    });
  }

  function startGuarding() {
    setTimeout(attachAllLinks, 300);
    const observer = new MutationObserver(() => {
      clearTimeout(observer._t);
      observer._t = setTimeout(() => {
        document.querySelectorAll("a[href]").forEach(attachLinkHandlers);
        preScanNewLinks();
      }, 600);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Check current page host before attaching any handlers.
  // Trusted → instant. Otherwise ask background (local lists + heuristics, no VT).
  if (isTrusted(window.location.hostname.toLowerCase())) {
    currentHostStatus = "trusted";
    startGuarding();
  } else {
    chrome.runtime.sendMessage({ action: "checkHost", url: window.location.href }, (result) => {
      currentHostStatus = result?.verdict || "unknown";
      startGuarding();
      if (result) maybeShowHostBanner(result);
    });
  }

  // ═══════════════════════════════════════════════════════
  // HOST SAFETY BANNER
  // Warns about the SITE the user is already on (links get
  // badges; the page itself gets this). Top frame only, once
  // per host per session.
  // ═══════════════════════════════════════════════════════
  function maybeShowHostBanner(result) {
    if (window !== window.top) return;                    // no banners inside iframes
    if (result.verdict !== "suspicious" && result.verdict !== "dangerous") return;

    const dismissKey = "lg-host-dismissed:" + location.hostname;
    try {
      if (sessionStorage.getItem(dismissKey)) return;     // already dismissed this session
    } catch { /* sessionStorage can be blocked — banner just shows again */ }

    const attach = () => {
      if (!document.body || document.getElementById("lg-host-banner")) return;
      const banner = document.createElement("div");
      banner.id = "lg-host-banner";
      if (result.verdict === "dangerous") banner.classList.add("lg-banner-dangerous");
      banner.innerHTML = `
        <span class="lg-banner-dot"></span>
        <div class="lg-banner-body">
          <div class="lg-banner-title">${result.verdict === "dangerous"
            ? "This site is flagged as dangerous"
            : "This site looks suspicious"}</div>
          ${result.reason ? `<div class="lg-banner-reason">${escapeHtml(result.reason)}</div>` : ""}
          ${sourceChipHtml(result.source)}
        </div>
        <button class="lg-banner-dismiss" id="lg-banner-dismiss">Dismiss</button>
      `;
      document.body.appendChild(banner);
      banner.querySelector("#lg-banner-dismiss").onclick = () => {
        banner.remove();
        try { sessionStorage.setItem(dismissKey, "1"); } catch {}
      };
    };

    if (document.body) attach();
    else document.addEventListener("DOMContentLoaded", attach, { once: true });
  }

  // ═══════════════════════════════════════════════════════
  // SCAN OVERLAY
  // ═══════════════════════════════════════════════════════
  function removeScanOverlay() {
    document.getElementById("lg-scan-overlay")?.remove();
  }

  // Shared overlay shell: backdrop + empty card. Every state
  // (prompt / scanning / verdict) just fills the card.
  function buildOverlay() {
    removeScanOverlay();
    const overlay = document.createElement("div");
    overlay.id = "lg-scan-overlay";
    overlay.innerHTML = `
      <div class="lg-backdrop"></div>
      <div class="lg-card"></div>
    `;
    document.body.appendChild(overlay);
    overlay.querySelector(".lg-backdrop").onclick = removeScanOverlay;
    return overlay;
  }

  function showScanOverlay(url, isNewTab, linkEl) {
    const overlay = buildOverlay();
    overlay.querySelector(".lg-card").innerHTML = `
      <div class="lg-card-title">Scan this link?</div>
      <div class="lg-card-reason">LinkGuard can check it before you go — instantly, on your device.</div>
      <div class="lg-card-url">${escapeHtml(truncate(url, 72))}</div>
      <div class="lg-card-actions">
        <button class="lg-btn lg-btn-primary" id="lg-do-scan">Scan</button>
        <button class="lg-btn lg-btn-ghost" id="lg-do-skip">Skip</button>
      </div>
    `;

    overlay.querySelector("#lg-do-skip").onclick = () => {
      removeScanOverlay();
      navigate(url, isNewTab);
    };

    overlay.querySelector("#lg-do-scan").onclick = () => {
      showScanning(overlay, url, isNewTab, linkEl);
    };
  }

  function showScanning(overlay, url, isNewTab, linkEl, force) {
    overlay.querySelector(".lg-card").innerHTML = `
      <div class="lg-spinner"></div>
      <div class="lg-card-title">Scanning…</div>
      <div class="lg-card-url">${escapeHtml(truncate(url, 72))}</div>
    `;

    chrome.runtime.sendMessage({ action: "scanUrl", url, force: force === true }, (result) => {
      if (chrome.runtime.lastError || !result) {
        result = { verdict: "unknown", reason: "No response from scanner" };
      }
      showVerdict(overlay, url, isNewTab, linkEl, result);
    });
  }

  function showVerdict(overlay, url, isNewTab, linkEl, result) {
    const { verdict, reason, source } = result;

    const glyphs = { safe: "✓", suspicious: "!", dangerous: "✕", unknown: "?" };
    const titles = {
      safe: "Link appears safe",
      suspicious: "Suspicious link",
      dangerous: "Dangerous link detected",
      unknown: "Could not verify",
    };
    const proceedLabels = {
      safe: "Proceed",
      suspicious: "Proceed with caution",
      dangerous: "Proceed anyway",
      unknown: "Proceed anyway",
    };

    // Confidence meter — only when the scanner sent a real number.
    // Clamp + round BEFORE templating so only a computed number is used.
    let meterHtml = "";
    if (typeof result.confidence === "number" && isFinite(result.confidence)) {
      const percent = Math.round(Math.min(1, Math.max(0, result.confidence)) * 100);
      meterHtml = `
        <div class="lg-meter"><div class="lg-meter-fill lg-meter-${verdict}" style="width:${percent}%"></div></div>
        <div class="lg-meter-label">${percent}% model confidence</div>
      `;
    }

    const card = overlay.querySelector(".lg-card");
    card.innerHTML = `
      <div class="lg-verdict-disc lg-disc-${verdict}">${glyphs[verdict] || "?"}</div>
      <div class="lg-card-title lg-verdict-${verdict}">${titles[verdict] || "Unknown"}</div>
      ${reason ? `<div class="lg-card-reason">${escapeHtml(reason)}</div>` : ""}
      ${sourceChipHtml(source)}
      ${meterHtml}
      <div class="lg-card-url">${escapeHtml(truncate(url, 72))}</div>
      <div class="lg-card-actions">
        <button class="lg-btn lg-btn-cancel" id="lg-do-cancel">Cancel</button>
        <button class="lg-btn lg-btn-proceed lg-proceed-${verdict}" id="lg-do-proceed">${proceedLabels[verdict]}</button>
      </div>
      <div class="lg-report-row">
        ${verdict !== "safe" ? `
        <button class="lg-btn-rescan" id="lg-do-rescan">
          <span class="lg-report-icon">↻</span>Scan again
        </button>` : ""}
        <button class="lg-btn-report" id="lg-do-report">
          <span class="lg-report-icon">⚑</span>Report this link
        </button>
      </div>
    `;

    // Remember the full result on the link element: next click skips the
    // "Scan?" prompt and shows this verdict card directly
    if (linkEl) {
      setBadgeVerdict(linkEl, verdict);
      linkEl.__lg_result = result;
    }

    // Scan again — force a FRESH full scan (bypasses the 1hr cache)
    const rescanBtn = overlay.querySelector("#lg-do-rescan");
    if (rescanBtn) {
      rescanBtn.onclick = () => showScanning(overlay, url, isNewTab, linkEl, true);
    }

    overlay.querySelector(".lg-backdrop").onclick = removeScanOverlay;
    overlay.querySelector("#lg-do-cancel").onclick = removeScanOverlay;
    overlay.querySelector("#lg-do-proceed").onclick = () => {
      removeScanOverlay();
      navigate(url, isNewTab);
    };
    overlay.querySelector("#lg-do-report").onclick = () => {
      const btn = overlay.querySelector("#lg-do-report");
      btn.innerHTML = '<span class="lg-report-icon">…</span>Reporting…';
      btn.disabled = true;
      chrome.runtime.sendMessage({ action: "reportUrl", url, verdict }, (res) => {
        if (res?.ok) {
          btn.innerHTML = '<span class="lg-report-icon">✓</span>Reported — thanks';
        } else {
          btn.innerHTML = '<span class="lg-report-icon">⚠</span>Failed — try again';
          btn.disabled = false;
        }
      });
    };
  }

  function navigate(url, isNewTab) {
    if (isNewTab) window.open(url, "_blank", "noopener,noreferrer");
    else window.location.href = url;
  }

  // ═══════════════════════════════════════════════════════
  // TEXT EXPLAINER (kept from Gexplain — gated by setting)
  // ═══════════════════════════════════════════════════════
  let explainButton = null;
  let selectedText = "";
  let lastMouse = { x: 0, y: 0 };

  document.addEventListener("mousemove", (e) => { lastMouse = { x: e.clientX, y: e.clientY }; }, { passive: true });
  document.addEventListener("selectionchange", () => { setTimeout(handleSelection, 5); });
  document.addEventListener("mouseup", () => { setTimeout(handleSelection, 5); });
  document.addEventListener("mousedown", (e) => {
    if (explainButton && !explainButton.contains(e.target)) removeExplainButton();
  });

  function handleSelection() {
    if (!textExplainerEnabled) return;
    try {
      const sel = window.getSelection();
      if (!sel) return removeExplainButton();
      const txt = sel.toString().trim();
      if (sel.anchorNode) {
        const anchor = sel.anchorNode.nodeType === 1 ? sel.anchorNode : sel.anchorNode.parentElement;
        if (anchor?.closest?.("#text-explainer-modal, #text-explainer-btn, #lg-scan-overlay")) return;
      }
      if (txt.length > 5 && txt.length < 2000) {
        selectedText = txt;
        showExplainButton(sel);
      } else {
        removeExplainButton();
      }
    } catch {
      removeExplainButton();
    }
  }

  function showExplainButton(sel) {
    let vx = lastMouse.x, vy = lastMouse.y + 10;
    if (sel?.rangeCount > 0) {
      try {
        const rect = sel.getRangeAt(0).getBoundingClientRect();
        if (rect && (rect.width || rect.height)) { vx = rect.left; vy = rect.bottom + 8; }
      } catch {}
    }
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    vx = Math.max(8, Math.min(vx, vw - 128));
    vy = Math.max(8, Math.min(vy, vh - 48));

    const theme = getThemeAt(vx, vy);
    if (!explainButton) {
      explainButton = document.createElement("button");
      explainButton.id = "text-explainer-btn";
      explainButton.textContent = "Explain";
      Object.assign(explainButton.style, {
        position: "fixed", zIndex: "2147483647",
        padding: "10px 16px", borderRadius: "10px",
        backdropFilter: "blur(12px) saturate(140%)",
        WebkitBackdropFilter: "blur(12px) saturate(140%)",
        boxShadow: "0 10px 30px rgba(0,0,0,0.25)",
        cursor: "pointer", userSelect: "none",
        letterSpacing: "0.3px", fontSize: "13px", fontWeight: "600",
        border: `1px solid ${theme.btnBorder}`,
        color: theme.btnColor, background: theme.btnBg,
        left: `${vx}px`, top: `${vy}px`,
      });
      explainButton.onmousedown = (e) => {
        e.stopPropagation();
        explainButton.textContent = "Thinking…";
        explainButton.style.cursor = "wait";
        const sx = vx, sy = vy;
        chrome.runtime.sendMessage({ action: "explain", text: selectedText }, (res) => {
          removeExplainButton();
          if (!res) return showExplainModal("No response from background.", false, sx, sy);
          if (res.error) return showExplainModal(res.message || "Error", false, sx, sy);
          showExplainModal(res.explanation, true, sx, sy);
        });
      };
      document.body.appendChild(explainButton);
    } else {
      explainButton.style.left = `${vx}px`;
      explainButton.style.top = `${vy}px`;
    }
  }

  function removeExplainButton() {
    if (explainButton) { explainButton.remove(); explainButton = null; }
  }

  function getThemeAt(x, y) {
    const el = document.elementFromPoint(x, y) || document.body;
    const cs = getComputedStyle(el);
    let bg = cs.backgroundColor;
    if (!bg || bg === "transparent" || bg.startsWith("rgba(0, 0, 0, 0")) {
      bg = getComputedStyle(document.body).backgroundColor || "rgb(255,255,255)";
    }
    const m = bg.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
    let r = 255, g = 255, b = 255;
    if (m) { r = +m[1]; g = +m[2]; b = +m[3]; }
    const lum = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
    const dark = lum < 0.5;
    return {
      btnBg: dark ? "linear-gradient(180deg,rgba(255,255,255,0.15),rgba(255,255,255,0.06))" : "linear-gradient(180deg,rgba(0,0,0,0.10),rgba(0,0,0,0.04))",
      btnBorder: dark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.20)",
      btnColor: dark ? "#fff" : "#111",
      modalBg: dark ? "linear-gradient(180deg,rgba(255,255,255,0.16),rgba(255,255,255,0.08))" : "linear-gradient(180deg,rgba(0,0,0,0.08),rgba(0,0,0,0.04))",
      modalBorder: dark ? "rgba(255,255,255,0.25)" : "rgba(0,0,0,0.20)",
      modalColor: dark ? "#fff" : "#111",
      shadow: dark ? "0 20px 50px rgba(0,0,0,0.35)" : "0 20px 50px rgba(0,0,0,0.15)",
    };
  }

  function showExplainModal(message, success, sx = innerWidth / 2, sy = 40) {
    document.getElementById("text-explainer-modal")?.remove();
    const modal = document.createElement("div");
    modal.id = "text-explainer-modal";
    const theme = getThemeAt(sx, sy);
    Object.assign(modal.style, {
      position: "fixed", zIndex: "2147483647",
      left: "50%", top: "20px", transform: "translateX(-50%)",
      maxWidth: "560px", width: "calc(100% - 32px)",
      padding: "18px 20px", borderRadius: "16px",
      color: theme.modalColor, border: `1px solid ${theme.modalBorder}`,
      background: theme.modalBg,
      backdropFilter: "blur(14px) saturate(160%)",
      WebkitBackdropFilter: "blur(14px) saturate(160%)",
      boxShadow: theme.shadow,
    });

    const title = document.createElement("div");
    title.textContent = success ? "Explanation" : "Notice";
    Object.assign(title.style, { fontWeight: "600", fontSize: "14px", marginBottom: "8px", opacity: "0.95" });

    const text = document.createElement("div");
    text.textContent = message;
    Object.assign(text.style, { fontSize: "14px", lineHeight: "1.6", whiteSpace: "pre-wrap" });

    const close = document.createElement("button");
    close.textContent = "Close";
    Object.assign(close.style, {
      marginTop: "12px", padding: "8px 12px", borderRadius: "10px",
      border: `1px solid ${theme.modalBorder}`, color: theme.modalColor,
      background: theme.btnBg, cursor: "pointer",
    });
    close.onclick = () => modal.remove();

    modal.appendChild(title);
    modal.appendChild(text);
    modal.appendChild(close);
    document.body.appendChild(modal);
    if (!success) setTimeout(() => modal.remove(), 8000);
  }
})();
