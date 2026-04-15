# Plan: Migrate LinkGuard popup → Chrome Side Panel

## Context
The user wants clicking the extension icon to open a persistent right-side panel (like Claude's Chrome extension) instead of a small fixed popup. The side panel stays open as the user browses, making it more usable — no more popup closing when focus is lost.

Chrome's Side Panel API (available MV3, Chrome 114+) makes this straightforward. The main differences vs. popup:
1. Panel stays open across tab switches → Dashboard must auto-refresh on tab change
2. Panel fills full browser height → layout should be fluid width, not fixed 380px
3. Icon click behaviour must be explicitly wired via `setPanelBehavior`

---

## Files to modify

### 1. `manifest.json`
Three changes:
- Add `"sidePanel"` to `permissions` array
- Add top-level key: `"side_panel": { "default_path": "sidepanel.html" }`
- Remove `"default_popup": "popup.html"` from `action` (keep `default_title` and icons)

### 2. `background.js`
Add one line in both `onInstalled` and `onStartup` listeners:
```js
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
```
No other logic changes.

---

## Files to create

### 3. `sidepanel.html`  (copy of `popup.html` + 3 edits)
- `html, body`: change `width: 380px` → `width: 100%`, `min-height: 360px` → `min-height: 100vh`, add `min-width: 300px`
- `.panel`: bump margin `12px→14px` and padding `16px→18px` for side-panel breathing room
- Script src: `popup.js` → `sidepanel.js`
- Everything else (CSS variables, all 4 tab panels, all IDs) identical

### 4. `sidepanel.js`  (copy of `popup.js` + 3 edits)
- Wrap the dashboard `sendMessage` block in a named `loadDashboard()` function and call it immediately
- Add `chrome.tabs.onActivated.addListener(() => loadDashboard())` — auto-refreshes stats when user switches browser tabs
- Add `window.addEventListener('focus', loadDashboard)` — fallback refresh on panel focus
- All other code (settings, explainer, help, Supabase status) copied unchanged

---

## What does NOT change
- `content.js`, `content.css` — zero changes
- All background.js scan/list/Supabase logic — zero changes
- `popup.html`, `popup.js` — kept as-is (no longer used but no need to delete)
- All 4 tab panels and their content — identical
- The dark/orange theme

---

## Implementation order
1. `manifest.json` — permission + side_panel declaration
2. `background.js` — `setPanelBehavior` in onInstalled + onStartup  
3. `sidepanel.html` — new file
4. `sidepanel.js` — new file

---

## Verification
1. Go to `chrome://extensions` → click Reload on LinkGuard
2. Click the toolbar icon → a right-side panel should slide open (not a popup)
3. Navigate to any HTTP page → links should get badges normally
4. Click a link → scan overlay should appear as normal
5. Scan a link, then switch to a different browser tab and back → Dashboard stat counts should update automatically (tests `onActivated` listener)
6. Open Settings tab → Supabase status, VT key, list counts all load correctly
