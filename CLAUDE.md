# LinkGuard — Claude Code Context

## What is this?
A Chrome extension (Manifest V3) that scans links for safety before the user visits them.
Forked from "Gexplain" (text explainer) — that feature is preserved but off by default.
GitHub: https://github.com/vanji-creator/linkguard

---

## Current State (v0.3.0) — Phase 2 COMPLETE

### Architecture
- **manifest.json** — MV3, host_permissions for VT + URLhaus + OpenPhish + ThreatFox + Supabase
- **background.js** — Service worker:
  - IndexedDB v2 blocklist manager (URLhaus + OpenPhish + ThreatFox + Community, refreshed daily)
  - Scan pipeline: cache → URLhaus → OpenPhish → ThreatFox → Community → India heuristics → [AI Model placeholder] → VirusTotal
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
- **popup.html/js** — 4 tabs: Dashboard | Settings (VT key + Supabase credentials) | Text Explainer | Help
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
      → [AI Model — Phase 4 placeholder, commented out in background.js]
      → VirusTotal API (free key, 4 req/min, 500/day)
           → rate limit hit → "could not verify" verdict
```

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

### Phase 3 — AI Model (URL Classifier) ← NEXT
**Goal:** Fine-tune SecureBERT/DistilBERT on 3-5M labeled URLs. Publish on HuggingFace as
`linkguard/url-safety-classifier`. Deploy as API. Plug into extension scan pipeline at the
commented-out Phase 4 placeholder in `background.js` (`scanUrl` function, step 4).

Model training pipeline lives in a separate repo/directory: `linkguard-model/`

Training data: URLhaus + PhishTank + OpenPhish + ThreatFox dumps + Tranco top-1M (safe negatives) + Supabase scan_logs

Integration: extension calls HuggingFace Inference API → high confidence (≥90%) → return verdict, skip VT.

Full training guide documented in conversation history (data collection → preprocessing → fine-tuning → evaluation → ONNX export → HuggingFace publish → extension integration).

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
