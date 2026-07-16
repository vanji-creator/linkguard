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
  // SAFE MESSAGING
  // When the extension is reloaded/updated, old content scripts keep
  // running in open tabs with a DEAD chrome.runtime — any sendMessage
  // would throw "Extension context invalidated". This wrapper checks
  // the bridge first and swallows the race instead of throwing.
  // ═══════════════════════════════════════════════════════
  const rawSendMessage = chrome.runtime.sendMessage.bind(chrome.runtime);
  function sendToBackground(message, callback) {
    try {
      if (!chrome.runtime?.id) { if (callback) callback(null); return; }
      rawSendMessage(message, (response) => {
        // Reading lastError marks it handled (stops "Unchecked runtime.lastError")
        const failed = chrome.runtime.lastError;
        if (callback) callback(failed ? null : response);
      });
    } catch {
      if (callback) callback(null);
    }
  }

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
    "remote-ai": "Clikk AI",
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
  // CLICK INTERCEPTION — one delegated listener, active from the
  // first instant this script runs.
  //
  // Why not per-link listeners? Two protection gaps:
  //   1. per-link handlers attach 300-600ms after load — a fast click
  //      (or a link the page just injected) slipped through unguarded
  //   2. sites navigate from their own JS click handlers, which can
  //      run before a per-anchor listener ever sees the event
  // A window-level CAPTURE listener sees every click first, and
  // stopImmediatePropagation() keeps the page's own handlers from
  // navigating while our overlay is deciding.
  // ═══════════════════════════════════════════════════════
  function findAnchorInEvent(e) {
    if (e.composedPath) {
      for (const node of e.composedPath()) {
        if (node && node.tagName === "A" && typeof node.href === "string" && node.href) return node;
      }
    }
    return e.target?.closest ? e.target.closest("a[href]") : null;
  }

  window.addEventListener("click", (e) => {
    const a = findAnchorInEvent(e);
    if (!a) return;
    const href = resolveHref(a);
    if (!href) return;                                   // not http(s) — mailto, js:, etc.

    let destHost;
    try { destHost = new URL(href).hostname.toLowerCase(); } catch { return; }
    const isSameOrigin = destHost === window.location.hostname.toLowerCase();

    // Same-origin on a clean (or still-being-checked) host → internal navigation, allow
    if (isSameOrigin && currentHostStatus !== "suspicious" &&
        currentHostStatus !== "dangerous" && currentHostStatus !== "unknown") return;
    // Trusted destination → allow
    if (!isSameOrigin && isTrusted(destHost)) return;
    // Confirmed safe this session → let the browser navigate naturally
    if (a.__lg_verdict === "safe") return;

    // Everything else: block the navigation AND the page's own handlers
    e.preventDefault();
    e.stopImmediatePropagation();
    e.stopPropagation();

    const isNewTab = a.target === "_blank" || e.ctrlKey || e.metaKey || e.shiftKey;

    // Already scanned and flagged — skip the "Scan?" prompt, show the
    // verdict straight away (with a Scan-again button on the card)
    if (a.__lg_result && a.__lg_result.verdict !== "safe") {
      const overlay = buildOverlay();
      showVerdict(overlay, href, isNewTab, a, a.__lg_result);
      return;
    }
    showScanOverlay(href, isNewTab, a);
  }, true);

  // ═══════════════════════════════════════════════════════
  // LINK BADGES + HOVER PRE-SCAN (cosmetic layer — the click
  // interceptor above protects even before badges attach)
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
      ? "Clikk: click to scan (opens in new tab)"
      : "Clikk: click to scan";
    a.appendChild(badge);

    a.addEventListener("mouseover", () => {
      sendToBackground({ action: "preScanUrl", url: href }, (result) => {
        if (!result) return;
        // Local pre-scan is only authoritative when it FLAGS something
        // (blocklist/heuristic hit) — a local "safe" is not a full scan.
        if (result.verdict === "suspicious" || result.verdict === "dangerous") {
          a.__lg_result = result;
          setBadgeVerdict(a, result.verdict);
        }
      });
    });
    // NOTE: no per-anchor click listener — the window-level capture
    // interceptor at the top of this file guards every click.
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

    sendToBackground(
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
    sendToBackground({
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
    sendToBackground({ action: "checkHost", url: window.location.href }, (result) => {
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
      <div class="lg-card-reason">Clikk can check it before you go — instantly, on your device.</div>
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

    sendToBackground({ action: "scanUrl", url, force: force === true }, (result) => {
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
      sendToBackground({ action: "reportUrl", url, verdict }, (res) => {
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

})();
