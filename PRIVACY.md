# Clikk — Privacy Policy

**Effective date: 16 July 2026**

Clikk is a browser extension that checks links for safety before you visit them. This policy explains exactly what data Clikk handles, where it goes, and what never leaves your device.

## The short version

- **By default, the links you click are analyzed entirely on your device.** Clikk ships with a built-in AI model and local threat blocklists. No account, no server, no tracking.
- Clikk sends a URL to an external service in only one case: **if you add your own VirusTotal API key**, links the on-device AI is unsure about are sent to VirusTotal for a second opinion.
- Clikk has **no analytics, no ads, no trackers**, and does not collect your browsing history.

## What Clikk processes on your device

- **URLs of links on pages you visit** — checked locally against downloaded blocklists (URLhaus, OpenPhish, ThreatFox) and scored by the built-in AI model. This happens in your browser's memory and is not transmitted.
- **Scan results cache** — verdicts are cached in memory for up to 1 hour to avoid re-scanning, and cleared when the browser closes the extension's background process.
- **Per-tab statistics** — counts of scanned/safe/suspicious/dangerous links shown in the popup. Kept in memory only.
- **Settings** — your preferences (and VirusTotal API key, if you add one) are stored in Chrome's local extension storage on your device. Your VirusTotal key is never sent anywhere except to VirusTotal itself as part of your own API requests.

## What leaves your device, and when

| Data | Sent to | When | Can you prevent it? |
|---|---|---|---|
| A clicked link's URL | VirusTotal (virustotal.com) | Only if YOU added a VirusTotal API key, and only when the on-device AI is not confident | Yes — don't add a key (default), or remove it in Settings |
| Nothing else | — | — | — |

**Blocklist downloads**: Clikk periodically downloads public threat lists *from* URLhaus, OpenPhish, and ThreatFox. These are downloads only — no data about you or your browsing is included in these requests.

**VirusTotal**: when you use your own key, VirusTotal receives the URL you clicked and your API key. VirusTotal's own privacy policy applies to that processing: https://docs.virustotal.com/docs/privacy-policy

## Planned features and consent

A future version may offer an optional **community protection** feature (sharing links that were flagged as dangerous, so other users are protected faster). This will be **off by default and strictly opt-in**: no link will ever be shared unless you explicitly enable it in Settings or press the "Report this link" button yourself. The current version does not transmit reports anywhere.

## What Clikk never does

- Never sells or shares any data with third parties
- Never collects browsing history, page content, form input, or personal information
- Never uses cookies, fingerprinting, analytics, or advertising SDKs
- Never transmits data for any purpose unrelated to the single purpose of link safety

## Data retention

Clikk keeps no data on any server, because Clikk has no server. Everything is on your device: settings in Chrome local storage, blocklists in the browser's IndexedDB, caches in memory. Uninstalling the extension removes all of it.

## Changes to this policy

Updates to this policy will be published at this URL with a new effective date. Material changes will be noted in the extension's release notes.

## Contact

Questions about this policy: open an issue at https://github.com/vanji-creator/linkguard/issues or email vikashvanchi@gmail.com.
