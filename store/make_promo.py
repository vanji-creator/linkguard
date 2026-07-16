#!/usr/bin/env python3
"""
Generate Chrome Web Store promo tiles for Clikk.
  store/assets/promo_small_440x280.png   (required)
  store/assets/promo_marquee_1400x560.png (optional marquee)
Monochrome brand: near-black canvas, crest, white wordmark, gray tagline,
one thin verdict-color strip as the only color accent.
Run from repo root: python3 store/make_promo.py
"""

from PIL import Image, ImageDraw, ImageFont
import os

BG      = (10, 10, 10, 255)
WHITE   = (245, 245, 247, 255)
GRAY    = (255, 255, 255, 153)     # 60% white
GREEN   = (48, 209, 88, 255)
AMBER   = (255, 214, 10, 255)
RED     = (255, 69, 58, 255)

FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_REG  = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def load_crest(size):
    crest = Image.open("icons/icon128.png").convert("RGBA")
    return crest.resize((size, size), Image.LANCZOS)


def verdict_strip(draw, x, y, width, height=4):
    """One thin three-color strip: the only color in the design."""
    third = width // 3
    draw.rectangle([x, y, x + third, y + height], fill=GREEN)
    draw.rectangle([x + third, y, x + 2 * third, y + height], fill=AMBER)
    draw.rectangle([x + 2 * third, y, x + width, y + height], fill=RED)


def make_tile(width, height, out_path, crest_px, title_px, tag_px):
    img = Image.new("RGBA", (width, height), BG)
    draw = ImageDraw.Draw(img)

    title_font = ImageFont.truetype(FONT_BOLD, title_px)
    tag_font = ImageFont.truetype(FONT_REG, tag_px)

    crest = load_crest(crest_px)
    title = "Clikk"
    tagline = "Links checked before you click"

    gap = crest_px // 4
    title_w = draw.textlength(title, font=title_font)
    block_w = crest_px + gap + title_w
    x0 = (width - block_w) // 2
    crest_y = (height - crest_px) // 2 - height // 12

    img.paste(crest, (int(x0), int(crest_y)), crest)

    title_bbox = title_font.getbbox(title)
    title_h = title_bbox[3] - title_bbox[1]
    title_y = crest_y + (crest_px - title_h) // 2 - title_bbox[1]
    draw.text((x0 + crest_px + gap, title_y), title, font=title_font, fill=WHITE)

    tag_w = draw.textlength(tagline, font=tag_font)
    tag_y = crest_y + crest_px + height // 14
    draw.text(((width - tag_w) // 2, tag_y), tagline, font=tag_font, fill=GRAY)

    strip_w = int(tag_w)
    verdict_strip(draw, (width - strip_w) // 2, tag_y + tag_px + height // 20, strip_w)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    img.convert("RGB").save(out_path, "PNG")
    print(f"  {out_path}  ({width}x{height})")


if __name__ == "__main__":
    make_tile(440, 280, "store/assets/promo_small_440x280.png",
              crest_px=96, title_px=64, tag_px=20)
    make_tile(1400, 560, "store/assets/promo_marquee_1400x560.png",
              crest_px=200, title_px=140, tag_px=42)
    print("Done.")
