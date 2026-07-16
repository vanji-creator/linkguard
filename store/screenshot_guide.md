# Clikk — Store Screenshot Guide

The store wants 1280×800 PNGs (1-5 of them). Real UI screenshots convert best.
Plan: 3 screenshots, captured from the actual extension.

## Setup once

1. `chrome://extensions` → reload Clikk (make sure it's the freshly packaged 0.7.0 code)
2. Open a test page with mixed links (a news site or blog works well)
3. On Linux: `gnome-screenshot -a` (area select) or `PrtSc`; capture at any size ≥1280×800,
   then crop/resize to exactly 1280×800 with: `python3 -c "from PIL import Image; im=Image.open('shot.png'); im.crop((0,0,1280,800)).save('shot_1280.png')"`
   (or just set the browser window to ~1280×800 first: `wmctrl -r :ACTIVE: -e 0,0,0,1280,800`)

## Shot 1 — The verdict card (hero shot)

1. Find/click a link that the AI judges (any unknown blog/site link)
2. Click → Scan → wait for the verdict card with the source chip + confidence meter
3. Capture with the card centered, page dimmed behind it
   - Best case: a red "Dangerous link detected" card. Use a known URLhaus sample URL
     on a test page you make yourself (an .html file with `<a href="...">` works —
     file:// pages need "Allow access to file URLs" enabled, or host it on localhost)

## Shot 2 — The popup dashboard

1. Scan a few links first so the stats tiles have numbers
2. Click the toolbar crest → Dashboard tab (model card should say "Active")
3. Capture the popup against the browser corner; crop to 1280×800 with page context around it

## Shot 3 — Red badges at page load

1. Make a local test page with 2-3 URLhaus sample links + a few normal links
2. Reload — flagged links get red badges + halo automatically, trusted get green dots
3. Capture the page showing the badge contrast

Optional Shot 4: Settings tab (shows the AI toggle + "links never leave your device" copy — the privacy story).

## Rules

- No device frames needed; plain UI screenshots are fine
- Don't show real personal info (bookmarks bar, other tabs' titles) — use a clean profile
- Don't fabricate UI that doesn't exist — reviewers compare screenshots against the real product
