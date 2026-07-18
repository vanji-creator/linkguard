#!/usr/bin/env python3
"""
Rename raw screenshots descriptively and produce the 5 store screenshots
at exactly 1280x800 in store/assets/screenshots/.
Run from repo root: python3 store/crop_screenshots.py
"""

from PIL import Image
import os

RAW = "screenshots"
OUT = "store/assets/screenshots"

# raw file -> descriptive name (kept in screenshots/)
RENAMES = {
    "Screenshot from 2026-07-16 12-45-00.png": "dev_errors_context_invalidated.png",
    "Screenshot from 2026-07-16 15-53-14.png": "urlhaus_browse_sameorigin_case.png",
    "Screenshot from 2026-07-16 15-59-53.png": "raw_badges_google_results.png",
    "Screenshot from 2026-07-16 16-00-21.png": "raw_popup_dashboard_open.png",
    "Screenshot from 2026-07-16 16-00-41.png": "raw_popup_dashboard_closeup.png",
    "Screenshot from 2026-07-16 16-00-52.png": "raw_popup_settings_closeup.png",
    "Screenshot from 2026-07-16 16-01-18.png": "raw_popup_help_closeup.png",
    "Screenshot from 2026-07-16 16-01-45.png": "raw_scan_prompt.png",
    "Screenshot from 2026-07-16 16-01-57.png": "raw_verdict_safe.png",
    "Screenshot from 2026-07-16 16-02-03.png": "raw_verdict_suspicious.png",
}

W, H = 1280, 800
BG = (10, 10, 10)


def crop_center(img, cx, cy):
    """1280x800 crop centered on (cx, cy), clamped to image bounds."""
    left = max(0, min(img.width - W, int(cx - W / 2)))
    top = max(0, min(img.height - H, int(cy - H / 2)))
    return img.crop((left, top, left + W, top + H))


def save(img, name):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    img.convert("RGB").save(path, "PNG")
    print(f"  {path}  ({img.width}x{img.height})")


def main():
    # 1. rename raws
    for old, new in RENAMES.items():
        src = os.path.join(RAW, old)
        dst = os.path.join(RAW, new)
        if os.path.exists(src):
            os.rename(src, dst)
            print(f"renamed: {new}")

    p = lambda n: Image.open(os.path.join(RAW, n))

    # 2. store crops — verdict cards sit centered around x≈950, y≈540
    save(crop_center(p("raw_verdict_safe.png"), 950, 540),
         "clikk_1_verdict_safe_1280x800.png")
    save(crop_center(p("raw_verdict_suspicious.png"), 950, 540),
         "clikk_2_verdict_suspicious_1280x800.png")

    # 3. popup composite: dashboard + settings + help on brand background
    canvas = Image.new("RGB", (W, H), BG)
    shots = [p("raw_popup_dashboard_closeup.png"),
             p("raw_popup_settings_closeup.png"),
             p("raw_popup_help_closeup.png")]
    # trim the window scrollbar sliver off the right edge of each capture
    shots = [s.crop((0, 0, s.width - 10, s.height)) for s in shots]
    target_h = 640
    scaled = []
    for s in shots:
        w = int(s.width * target_h / s.height)
        scaled.append(s.resize((w, target_h), Image.LANCZOS))
    gap = 40
    total_w = sum(s.width for s in scaled) + gap * (len(scaled) - 1)
    if total_w > W - 40:                      # shrink to fit with margins
        factor = (W - 40) / total_w
        scaled = [s.resize((int(s.width * factor), int(target_h * factor)),
                           Image.LANCZOS) for s in scaled]
        total_w = sum(s.width for s in scaled) + gap * (len(scaled) - 1)
    x = (W - total_w) // 2
    for s in scaled:
        canvas.paste(s, (x, (H - s.height) // 2))
        x += s.width + gap
    save(canvas, "clikk_3_popup_tabs_1280x800.png")

    # 4. badges on live search results — keep left content column
    save(crop_center(p("raw_badges_google_results.png"), 700, 420),
         "clikk_4_badges_on_page_1280x800.png")

    # 5. the scan prompt (interception moment)
    save(crop_center(p("raw_scan_prompt.png"), 950, 540),
         "clikk_5_scan_prompt_1280x800.png")

    print("Done.")


if __name__ == "__main__":
    main()
