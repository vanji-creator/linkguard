# LinkGuard — Claude Code Context

## What is this?
A Chrome extension (Manifest V3) that scans links for safety before the user visits them.
Forked from "Gexplain" (text explainer) — that feature is preserved but off by default.
GitHub: https://github.com/vanji-creator/linkguard

---

## Current State (v0.6.0) — Application layer redesigned (monochrome), AI model deployed on-device

### v0.6.0 application-layer redesign (2026-07-16)
- **Monochrome Apple-sleek design system** across popup + in-page UI: black/white/gray only; the ONLY color is verdict semantics (green/amber/red). Shared tokens (`--lg-*` in content.css, `:root` in popup.html). Icons regenerated white-on-dark (`tools/gen_icons.py`).
- **Structured scan responses**: `scanUrl`/`checkHost` return `{verdict, reason, source, confidence?}`. `source` ∈ urlhaus|openphish|threatfox|community|heuristic|model|remote-ai|virustotal|none. UI renders source chip via `SOURCE_LABELS` whitelist (never raw) + confidence meter when `confidence` is a number.
- **Shallow-cache fix**: hover pre-scan cache entries carry `shallow: true`; click-time scans skip them (previously hover poisoned the 1hr cache so model/VT never ran on click).
- **Host safety banner**: `#lg-host-banner` fixed top-center when the current site is suspicious/dangerous. Top frame only, per-host sessionStorage dismissal.
- **Popup**: 3 tabs (Dashboard/Settings/Help). Explainer tab REMOVED from UI (background explain/testCall + content.js explainer code kept dormant; storage keys preserved — `saveSettings` now writes only keys present in the request). Dashboard adds model-status card (`getModelStatus` → LinkGuardModel.getMeta()) + protection summary. Version badge from `chrome.runtime.getManifest()`.
- **Verdict-aware interception** (post-0.6.0 polish): page-load batch pre-scan (`preScanBatch`, local-only, cap 300 URLs) badges known-bad links red/yellow before any hover; hover pre-scan (`preScanUrl`) now responds and badges flagged links; links with a remembered result (`a.__lg_result`) skip the "Scan?" prompt on click and open the verdict card directly; verdict card has a "Scan again" button (non-safe verdicts) that forces a fresh full scan (`scanUrl` force flag bypasses 1hr cache). Icons are now crest-only full-bleed (no box/outline; `tools/gen_icons.py` classic heater geometry).

### Architecture
- **manifest.json** — MV3, host_permissions for VT + URLhaus + OpenPhish + ThreatFox + Supabase
- **background.js** — Service worker:
  - IndexedDB v2 blocklist manager (URLhaus + OpenPhish + ThreatFox + Community, refreshed daily)
  - Scan pipeline: cache → URLhaus → OpenPhish → ThreatFox → Community → India heuristics → **on-device AI model** → VirusTotal
  - VirusTotal v3 API (click-time only, free key, tries cached report first then submits)
  - In-memory URL verdict cache (1hr TTL)
  - Host safety check (`checkHost`) — local only, no VT, runs on every page load
  - Supabase integration: community blocklist sync, user report submission, scan log telemetry
  - Gemini text explain (gated by `textExplainerEnabled` setting)
  - Per-tab scan stats
- **content.js** — Click-time interception:
  - Host safety check on page load BEFORE attaching any link handlers
  - 3-filter system on every `<a href>`:
    1. Same-origin: skip IF host is safe/trusted, scan IF host is suspicious/dangerous/unknown
    2. Trusted destination: green badge instantly, no intercept
    3. Unknown cross-origin: neutral badge + hover pre-scan (local only) + click intercept
  - In-page scan overlay: "Scan?" → spinner → verdict → Proceed/Cancel + Report button
  - `target="_blank"` and Ctrl/Meta/Shift+click all handled correctly
  - Safe links remembered per session (`a.__lg_verdict`) — no re-scan on repeat clicks
  - Duplicate badge guard — strips stale badges copied via `cloneNode()` before attaching new one
  - Text explainer only active when `textExplainerEnabled` setting is true
- **content.css** — 6px dot badges (neutral/green/yellow/red), scan overlay card, spinner, report button
- **popup.html/js** — 3 tabs: Dashboard (model card + stats + protection summary) | Settings (model toggle, VT key, Supabase credentials) | Help
- **supabase/schema.sql** — PostgreSQL schema: `urls`, `reports`, `scan_logs` tables with RLS
- **supabase/functions/sync-blocklists/index.ts** — Deno edge function: fetches URLhaus/OpenPhish/ThreatFox → upserts into `urls` table. Schedule: `0 2 * * *` in Supabase dashboard.
- **tools/gen_icons.py** — Icon generator (PIL). Produces heraldic heater-shield icons for all 3 sizes.

### Scan Pipeline Detail
```
Click → cache (1hr TTL)
      → URLhaus IndexedDB (malware URLs)
      → OpenPhish IndexedDB (phishing)
      → ThreatFox IndexedDB (threat IOCs)
      → Community IndexedDB (user-reported + Supabase-synced)
      → India heuristics (KYC scams, fake UPI, sketchy TLDs, deep subdomains)
      → LinkGuard AI model — ON-DEVICE (model.js + model/linkguard_model_v1.json)
           → confidence ≥90% (p ≤0.10 or ≥0.90) → return safe/dangerous, SKIP VirusTotal
           → unsure → hold 3-way verdict, fall through to VT
      → VirusTotal API (free key, 4 req/min, 500/day) — only when AI is unsure
           → no VT key → AI 3-way fallback verdict (suspicious band asks user to add VT key)
           → rate limit hit → "could not verify" verdict
```

### On-Device AI Model (Phase 3, deployed in v0.5.0)
- **model/linkguard_model_v1.json** (~1.7MB) — exported TF-IDF char n-gram (3-5) + LogisticRegression weights: 57,750 chunks → [idf, coef], intercept, thresholds. Versioned artifact with sha256 fingerprint + metrics. Exported by `linkguard-model/train/export_model_json.py` (asserts all fitted params so a divergent retrain fails loudly).
- **model.js** — pure-JS inference engine (zero deps, zero I/O), loaded via `importScripts` in the service worker; dual-environment (also loads in Node for tests). Exact sklearn parity: code-point slicing, Python whitespace class, char_wb short-word break, L2-norm folding, sigmoid.
- **Parity gate**: `node linkguard-model/deploy/parity_test.mjs` — 100 golden vectors from Python must match within 1e-6 (actual worst diff 2e-8), plus latency benchmark (~200µs/URL; model init ~250ms one-time lazy load).
- Training/eval pipeline in `linkguard-model/` (98.6% honest domain-grouped accuracy, 0.3% false alarms). "Suspicious" is a probability band (0.30–0.70) applied AFTER the model, never a training label. All-out-of-vocab input → p≈0.559 → suspicious (safe failsafe).
- `modelEnabled` setting (default true) toggles it; remote API path (`LG_MODEL_URL`/`checkWithAIModel`) kept as disabled secondary channel for future Android app.

### Hover Pre-scan
`mouseover` triggers local-only scan (cache + blocklists + heuristics, NO VirusTotal).
By the time user clicks, result is often already cached.

### Host Safety Logic
Every page load: check current hostname against trusted list (instant) or run local scan.
- Host trusted/safe → same-origin links skipped (internal navigation)
- Host suspicious/dangerous/unknown → same-origin links also intercepted and scanned

### Trusted Domain List (built-in, ~40 domains)
Google family, Microsoft, Apple, GitHub, Wikipedia, StackOverflow, Mozilla,
India govt (gov.in, nic.in, rbi.org.in, uidai.gov.in, irctc.co.in, incometax.gov.in, npci.org.in),
India banks (sbi.co.in, hdfcbank.com, icicibank.com, axisbank.com, kotak.com, pnb, bob, canara),
India payments (paytm.com, phonepe.com, razorpay.com, cashfree.com, billdesk.com, ccavenue.com),
Social (linkedin, twitter/x, reddit, facebook, instagram),
Commerce (amazon.com, amazon.in, flipkart.com, myntra.com, meesho.com)

### Verdicts
- `safe` — passed all checks
- `suspicious` — heuristic match (India scam pattern, sketchy TLD, deep subdomain)
- `dangerous` — found in URLhaus / OpenPhish / ThreatFox / Community / VirusTotal (2+ engines)
- `unknown` — VT rate limited, timeout, or no API key

### Settings Storage Keys
- `vtApiKey` — VirusTotal API key
- `modelEnabled` — boolean, default true — on-device AI model toggle
- `supabaseUrl` — Supabase project URL
- `supabaseAnonKey` — Supabase anon key
- `textExplainerEnabled` — boolean, default false
- `customApiKey` — Gemini API key
- `modelName` — Gemini model, default gemini-2.0-flash

### Supabase Schema
```sql
urls       — central blocklist (url, verdict, source, reported_at, region, confirmed)
reports    — user submissions (url, reporter_id, context, verdict_at_time, ts)
scan_logs  — telemetry (url, verdict, source, user_id, device, ts) — ML training dataset
```
- RLS: public read `urls`, public insert `reports`/`scan_logs`, service-role write `urls`
- Trigger: `promote_report_to_blocklist()` — SECURITY DEFINER, auto-promotes every new report into `urls`
- Only dangerous/suspicious verdicts logged to scan_logs (safe/unknown skipped — privacy)

### Blocklist Sources
- URLhaus: https://urlhaus.abuse.ch/downloads/text_recent/ (malware, no key needed)
- OpenPhish: https://openphish.com/feed.txt (phishing, no key needed, every 12h)
- ThreatFox: https://threatfox-api.abuse.ch/api/v1/ POST {query: get_iocs, days: 7} (no key needed)
- Community: Supabase `urls` table (synced on startup + daily refresh)

---

## Key Design Decisions (permanent)

1. **No Google Safe Browsing** — removed due to payment restrictions
2. **Click-time scanning only** — no page-load batch scan. User always in control.
3. **VT on click only, never on hover** — preserves free tier quota (4 req/min, 500/day)
4. **Local lists first, VT last** — optimization: cuts VT calls significantly
5. **IndexedDB for blocklists** — ~20MB local storage, works offline, fast O(1) lookup
6. **Same-origin trust is conditional** — depends on whether the host itself is safe
7. **Safe links remembered per session** — `a.__lg_verdict` on DOM element, no re-scan
8. **Text explainer off by default** — separate tab in popup, requires Gemini key
9. **Trusted domain list pre-marks green** — no intercept, navigates instantly
10. **VirusTotal: try cached report (GET) first, then submit (POST) + poll** — saves quota
11. **No login in extension** — auth/accounts belong on the website, not the extension
12. **Report confirmed before UI update** — report button waits for background response before showing "Reported"
13. **Duplicate badge prevention** — `cloneNode()` copies badge DOM children but not `__lg_attached`; fix strips stale badge before attaching

---

## Roadmap

### Phase 1 — Chrome Extension ✅ DONE
Click-time scanning, VirusTotal + local blocklists, trusted domain filtering,
host safety check, same-session safe-link memory, text explainer toggle.

### Phase 2 — Backend + Data ✅ DONE
Supabase backend, community blocklist, user reporting ("Report this link"),
scan logs as ML training dataset, daily feed sync edge function, heraldic shield icons.

**One manual step remaining**: Supabase dashboard → Edge Functions → sync-blocklists → Schedules → add `0 2 * * *` cron. Run once manually first: `supabase functions invoke sync-blocklists --no-verify-jwt`

### Phase 3 — AI Model (URL Classifier) ✅ DEPLOYED (v0.5.0)
**What shipped (differs from original SecureBERT plan — deliberately):** simple 2-class
TF-IDF char n-gram (3-5) + LogisticRegression, trained on 26k engineered URLs
(930 safe domains / 6,380 danger domains, per-domain capped, domain-grouped honest eval:
98.6% accuracy, 0.3% false alarms). Deployed ON-DEVICE (not as API): weights exported to
`model/linkguard_model_v1.json`, inference reimplemented in pure JS (`model.js`),
Python↔JS parity proven by golden-vector test (worst diff 2e-8), ~200µs per URL.
The original SecureBERT attempt failed via shortcut learning and is archived in
`linkguard-model/archive/`.

Deferred within Phase 3: PhishTank data to close the phishing-miss gap → retrain → export v2;
HuggingFace publish + remote API (for Android app, Phase 4); remote model-update channel.

### Phase 4 — Android App (Kotlin)
- Overlay app that intercepts links opened from SMS, WhatsApp, browsers
- Connects to same Supabase backend
- Push alerts via Firebase Cloud Messaging (FCM) — ONLY reason to use Firebase
  (FCM API called from Supabase Edge Functions, no Firebase SDK in backend)
- Offline-first: local blocklists cached on device

### Phase 5 — Family Protection
- Family dashboard (web + Android)
- Real-time alerts when family member clicks dangerous link
- Auto-block for child profiles
- Alert delivery: Supabase Edge Function → FCM API → parent Android app
- Row-level security in Supabase isolates each family's data automatically

### Phase 6 — Scale + Monetization
- Hindi/regional UI
- Play Store launch
- Subscription tiers (Supabase `subscription_status` column + Stripe)
- Self-host Supabase on own servers to cut costs at scale (Supabase is open source PostgreSQL)
- Website for user accounts, login, cross-device sync, family dashboard

---

## Why Supabase over Firebase

| Need | Supabase wins because |
|---|---|
| India latency | Mumbai region (AWS ap-south-1), 20-50ms. Firebase nearest = Singapore, 150ms |
| Family profiles | Native PostgreSQL Row-Level Security — isolation built into DB, not patched on |
| ML training data | Full SQL → direct export to training pipeline. Firebase has no SQL |
| AI model (pgvector) | Store/query URL embeddings in same DB |
| Cost at 10K DAU | $25-50/month vs Firebase $50-200/month |
| Self-hosting | Open source PostgreSQL — can migrate off when scaling. Firebase has no exit |
| URL blocklist | B-tree index on URL hash = O(1) exact match on millions of rows |

FCM (Firebase) used ONLY for Android push notifications — free, called via HTTP API
from Supabase Edge Functions. No Firebase SDK in backend.

---

## Future Vision (long-term)
- Own link scanner model replacing all third-party APIs
- Central India threat intelligence database (crowdsourced, community-reported)
- Family safety OS layer: SMS, WhatsApp, browser, app-level protection
- Regional language UI for broader India reach
- B2B: enterprise/school network protection

---

## Dev Setup
1. Go to `chrome://extensions` → Enable Developer Mode → Load Unpacked → select this folder
2. Settings tab → paste VirusTotal API key → Save
3. Settings tab → paste Supabase URL + Anon Key → Save (community blocklist auto-fetches)
4. Text Explainer tab → toggle on → paste Gemini key (optional)
5. Navigate to any page — links get badges, click any link to scan it

## Repo
https://github.com/vanji-creator/linkguard
Branch: main
