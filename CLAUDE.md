# LinkGuard — Claude Code Context

## What is this?
A Chrome extension (Manifest V3) that scans every link on a page for safety. Forked from "Gexplain" text explainer — that feature is still intact.

## Architecture
- **manifest.json** — MV3, content script injected at document_idle on all URLs
- **background.js** — Service worker handling:
  - Google Safe Browsing API batch lookups (up to 500 URLs/batch)
  - India-specific heuristic URL checks (KYC scams, fake UPI, sketchy TLDs)
  - In-memory URL verdict cache (1hr TTL)
  - Gemini API for text explain (legacy feature)
  - Per-tab scan stats
- **content.js** — Collects all `<a href>` on page, sends to background, receives verdicts, applies CSS badges and click-intercept on dangerous links
- **content.css** — Badge styles, warning modal styles
- **popup.html/js** — Dashboard (scan stats), Settings (Safe Browsing + Gemini keys), Help

## Key APIs
- Google Safe Browsing v4 `threatMatches:find` — primary URL checker
- Google Gemini `generateContent` — text explain feature
- VirusTotal v3 — planned for Phase 2 detailed reports

## Verdicts
- `safe` — not flagged by Safe Browsing or heuristics
- `suspicious` — heuristic match (India scam patterns, sketchy TLDs, deep subdomains)
- `dangerous` — flagged by Google Safe Browsing
- `unknown` — no API key configured

## Dev Setup
1. Go to `chrome://extensions` → Enable Developer Mode → Load Unpacked → select this folder
2. Add API keys in the popup Settings tab
3. Navigate to any page — links auto-scanned

## Roadmap (from project brief)
- [ ] Week 1-2: Chrome extension with Safe Browsing (← we are here)
- [ ] Week 2: Firebase backend + central scam URL database
- [ ] Week 3-4: Android overlay app (Kotlin)
- [ ] Month 2: VirusTotal integration, screenshot scan via Vision AI
- [ ] Month 3: Family protection layer — alerts, dashboard, auto-block
- [ ] Month 4+: Hindi/regional UI, Play Store launch, monetization
