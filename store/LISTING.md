# Clikk — Chrome Web Store Submission Kit

Everything to copy-paste into the developer dashboard. Field names match the dashboard.

---

## Store listing tab

**Name**: Clikk

**Summary (132 chars max)**:
> Checks links for safety before you visit them. On-device AI — private, instant, works offline.

**Description**:
```
Clikk checks every link BEFORE you visit it — so a wrong click never becomes a disaster.

HOW IT WORKS
Click any link and Clikk intercepts it, scans it, and shows you a verdict in under a second: Safe, Suspicious, or Dangerous — with the reason and the source of the verdict. You decide whether to proceed. Links on dangerous blocklists are flagged in red the moment the page loads, before you touch anything.

PRIVATE BY DESIGN
Clikk's AI model runs entirely ON YOUR DEVICE. The links you click are not sent to any server — analysis takes about 200 microseconds, works offline, and needs no account. Nothing to sign up for, nothing tracking you.

WHAT'S INSIDE
• On-device AI URL classifier — trained on tens of thousands of real phishing and malware URLs, 98.6% accuracy in honest domain-separated testing
• Live threat blocklists — URLhaus (malware), OpenPhish (phishing), ThreatFox (threat intel), refreshed daily and stored locally
• Scam pattern heuristics — including patterns targeting Indian users: fake KYC updates, UPI cashback bait, lottery scams, sketchy domain extensions
• Optional VirusTotal second opinion — add your own free VirusTotal API key and Clikk consults 70+ antivirus engines, but only for links the AI is unsure about
• Trusted domains — major sites (Google, Wikipedia, government portals, major banks) get a green badge and zero friction
• Hover pre-scan — point at a link and the verdict is often ready before you click
• Site safety banner — if the page you are ON is itself flagged, Clikk tells you

WHO IT'S FOR
Anyone who clicks links from email, WhatsApp, Telegram, SMS or social media — and especially the people in your family who forward everything.

PERMISSIONS, HONESTLY
Clikk needs access to pages so it can badge and intercept links on any site you browse — that is the product. It sends nothing anywhere by default. The only outbound traffic is downloading public blocklists, plus VirusTotal lookups if you choose to add your own key.

Privacy policy: https://github.com/vanji-creator/linkguard/blob/main/PRIVACY.md
```

**Category**: Privacy & Security (fallback: Tools / Productivity if unavailable)

**Language**: English

---

## Privacy tab

**Single purpose description**:
> Clikk has a single purpose: checking the safety of links before the user visits them. It intercepts link clicks, evaluates the URL using an on-device AI model and locally stored threat blocklists, and shows the user a safety verdict so they can decide whether to proceed.

**Permission justifications** (one per field):

- `host_permissions: <all_urls>` —
  > Clikk's single purpose is checking link safety on any website the user browses. The content script must run on all pages to badge links, intercept clicks, and show the scan verdict overlay. Malicious links appear on any site (webmail, social media, forums), so the protection cannot be limited to a fixed domain list.

- `host_permissions: virustotal.com` —
  > If (and only if) the user supplies their own VirusTotal API key in Settings, URLs the on-device model is unsure about are submitted to the VirusTotal API for a second opinion.

- `host_permissions: urlhaus.abuse.ch / openphish.com / threatfox-api.abuse.ch` —
  > Clikk downloads these public threat blocklists (malware URLs, phishing URLs, threat IOCs) once daily and stores them locally, so link checks run on-device. These are download-only requests carrying no user data.

- `storage` —
  > Stores the user's settings (AI model on/off, optional VirusTotal API key) and downloaded blocklists locally.

- `scripting` —
  > Injects the content script into already-open tabs when the extension is installed or updated, so protection starts without requiring the user to reload every tab.

- `tabs` —
  > Reads the active tab ID to show that tab's scan statistics (links scanned / safe / dangerous) in the popup dashboard.

- `webNavigation` —
  > Re-injects the content script after single-page-app navigations (history state updates) and into late-loading frames, so dynamically navigated pages stay protected.

- `alarms` —
  > Schedules the once-daily blocklist refresh.

**Remote code**: No, I am not using remote code. (The AI model ships inside the package as a JSON weights file evaluated by bundled JavaScript — no external scripts, no eval, no CDN.)

**Data usage form** — check ONLY:
- ☑ **Website content** → specifically: URLs of links, processed **locally on the device**; transmitted to VirusTotal only when the user has configured their own API key.

Leave everything else unchecked (no personally identifiable info, no health, no financial, no authentication, no personal communications, no location, no web history collection, no user activity, no keystroke logging).

**Certify all three data-use statements** (they are true for Clikk):
- ☑ I do not sell or transfer user data to third parties, outside of the approved use cases
- ☑ I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- ☑ I do not use or transfer user data to determine creditworthiness or for lending purposes

**Privacy policy URL**:
> https://github.com/vanji-creator/linkguard/blob/main/PRIVACY.md

---

## Distribution tab

- **Visibility**: Public
- **Regions**: All regions (or start with India + your test countries)
- **Pricing**: Free

---

## Assets checklist

| Asset | Spec | Status |
|---|---|---|
| Icon 128×128 | PNG, shown in store | ✅ `icons/icon128.png` (crest) |
| Screenshots (1-5) | 1280×800 or 640×400 PNG/JPG | stage with `store/screenshot_guide.md` |
| Small promo tile | 440×280 PNG/JPG | ✅ `store/assets/promo_small_440x280.png` |
| Marquee promo (optional) | 1400×560 | ✅ `store/assets/promo_marquee_1400x560.png` |

## Review expectations

`<all_urls>` puts Clikk in the in-depth review queue: expect several days up to ~2-3 weeks for first review. The strongest factors in our favor: no remote code, on-device processing, minimal data transmission, tight single-purpose statement, working privacy policy URL. Don't re-submit or edit while a review is pending — it restarts the queue.
