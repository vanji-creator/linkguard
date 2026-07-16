#!/usr/bin/env python3
"""
Generate LinkGuard icons — heraldic heater shield matching reference exactly.

Reference shape (heater shield):
  - TOP:    circular arch, shoulders ~14% from sides, peak ~6% from top
            Solved circle: cx=0.50, cy=0.465, r=0.405  (normalised 0-1 space)
  - SIDES:  nearly straight, very slightly concave, tangent-matched at shoulder
  - BOTTOM: two cubic beziers converging cleanly to a single centre bottom point
"""

from PIL import Image, ImageDraw
import math, os

DARK   = ( 10,  10,  10, 255)
LIGHT  = (245, 245, 247, 255)   # Apple-white — monochrome brand (v0.6)
BORDER = (245, 245, 247, 255)   # white outline — crisp against dark background
TRANS  = (  0,   0,   0,   0)


# ── Curve helpers ──────────────────────────────────────

def arc_pts(cx, cy, r, a0_deg, a1_deg, n=40):
    """Points on a circle arc from a0_deg to a1_deg (counter-clockwise)."""
    pts = []
    for i in range(n + 1):
        a = math.radians(a0_deg + (a1_deg - a0_deg) * i / n)
        pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return pts


def cbez(p0, p1, p2, p3, n=20):
    """Cubic Bézier from p0 to p3 via controls p1, p2."""
    pts = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        x = mt**3*p0[0] + 3*mt**2*t*p1[0] + 3*mt*t**2*p2[0] + t**3*p3[0]
        y = mt**3*p0[1] + 3*mt**2*t*p1[1] + 3*mt*t**2*p2[1] + t**3*p3[1]
        pts.append((x, y))
    return pts


# ── Shield polygon ─────────────────────────────────────

def shield_pts(S):
    """
    Classic heater shield (crest) for an S×S canvas — the shape everyone
    reads as "security badge":

      - TOP:    flat horizontal edge with wide, slightly-rounded shoulders
      - UPPER SIDES: straight, vertical
      - LOWER SIDES: sweeping cubic curves converging to a bottom point

    Normalised coordinates (0-1) are mapped into the padded work area
    [pad .. S-pad] on both axes. Tiny pad (2%) so the crest fills the
    canvas edge-to-edge without anti-alias clipping.
    """
    pad = 0.02 * S
    SS  = S - 2 * pad          # working span

    def p(nx, ny):
        """Normalised [0-1] → canvas pixel."""
        return (pad + nx * SS, pad + ny * SS)

    # Key stations — full-width crest (no surrounding box anymore)
    top_y     = 0.020          # flat top edge height
    shoulder  = 0.020          # x inset of left/right edges
    waist_y   = 0.480          # where straight sides end and the curve begins
    corner_r  = 0.060          # shoulder rounding radius

    bp = p(0.500, 0.955)       # bottom point

    # ── Flat top edge with rounded shoulders ───────────────────────────
    # left shoulder corner arc: from left-side vertical up onto the top edge
    lc_cx, lc_cy = p(shoulder + corner_r, top_y + corner_r)
    rc_cx, rc_cy = p(1 - shoulder - corner_r, top_y + corner_r)
    r_px = corner_r * SS
    left_corner  = arc_pts(lc_cx, lc_cy, r_px, 180, 270, n=8)   # west → north
    right_corner = arc_pts(rc_cx, rc_cy, r_px, 270, 360, n=8)   # north → east

    # ── Straight vertical sides down to the waist ──────────────────────
    right_top    = (rc_cx + r_px, rc_cy)               # east point of corner
    right_waist  = p(1 - shoulder, waist_y)
    left_waist   = p(shoulder, waist_y)
    left_top     = (lc_cx - r_px, lc_cy)               # west point of corner

    # ── Lower curves: waist → bottom point (the heater sweep) ──────────
    right_sweep = cbez(right_waist,
                       p(1 - shoulder - 0.010, 0.700),
                       p(0.740, 0.870),
                       bp, n=36)
    left_sweep  = cbez(bp,
                       p(0.260, 0.870),
                       p(shoulder + 0.010, 0.700),
                       left_waist, n=36)

    # Assemble clockwise (skip duplicate junction points)
    return (left_corner
            + right_corner[1:]
            + [right_top, right_waist]
            + right_sweep[1:]
            + left_sweep[1:]
            + [left_waist, left_top])


# ── Mask and composite helpers ─────────────────────────

def make_mask(S, pts):
    m = Image.new('L', (S, S), 0)
    ImageDraw.Draw(m).polygon(pts, fill=255)
    return m


def shrink(pts, margin):
    """Pull each point inward toward bounding-box centre by `margin` px."""
    xs = [pt[0] for pt in pts]; ys = [pt[1] for pt in pts]
    cx = (min(xs) + max(xs)) / 2
    cy = (min(ys) + max(ys)) / 2
    out = []
    for px, py in pts:
        dx, dy = px - cx, py - cy
        d = math.hypot(dx, dy)
        f = max(0.0, (d - margin) / d) if d > 0 else 1.0
        out.append((cx + dx * f, cy + dy * f))
    return out


def rrect(draw, x0, y0, x1, y1, r, fill):
    draw.rectangle([x0+r, y0,   x1-r, y1  ], fill=fill)
    draw.rectangle([x0,   y0+r, x1,   y1-r], fill=fill)
    draw.ellipse  ([x0,        y0,        x0+2*r, y0+2*r], fill=fill)
    draw.ellipse  ([x1-2*r,    y0,        x1,     y0+2*r], fill=fill)
    draw.ellipse  ([x0,        y1-2*r,    x0+2*r, y1    ], fill=fill)
    draw.ellipse  ([x1-2*r,    y1-2*r,    x1,     y1    ], fill=fill)


# ── Icon builder ───────────────────────────────────────

def make_icon(final_size):
    SC = 4
    S  = final_size * SC

    # Crest only: transparent background, no box, no outline ring —
    # the quartered shield IS the whole logo, edge to edge.
    img = Image.new('RGBA', (S, S), TRANS)

    outer = shield_pts(S)
    mask  = make_mask(S, outer)

    ys = [pt[1] for pt in outer]; xs = [pt[0] for pt in outer]
    div_cx = (min(xs) + max(xs)) / 2
    div_cy = min(ys) + (max(ys) - min(ys)) * 0.488   # horizontal divider

    # Quarters: TL=dark, TR=light, BL=light, BR=dark
    pattern = Image.new('RGBA', (S, S), DARK)
    pdraw   = ImageDraw.Draw(pattern)
    pdraw.rectangle([div_cx, 0,      S,      div_cy], fill=LIGHT)  # top-right
    pdraw.rectangle([0,      div_cy, div_cx, S     ], fill=LIGHT)  # bottom-left

    clipped = Image.new('RGBA', (S, S), TRANS)
    clipped.paste(pattern, mask=mask)
    img = Image.alpha_composite(img, clipped)

    # Cross divider lines clipped to shield
    lw       = max(2, int(S * 0.018))
    line_img = Image.new('RGBA', (S, S), TRANS)
    ldraw    = ImageDraw.Draw(line_img)
    lc       = (15, 15, 15, 240)
    ldraw.line([(div_cx, 0), (div_cx, S)], fill=lc, width=lw)
    ldraw.line([(0, div_cy), (S, div_cy)], fill=lc, width=lw)
    cross    = Image.new('RGBA', (S, S), TRANS)
    cross.paste(line_img, mask=mask)
    img = Image.alpha_composite(img, cross)

    return img.resize((final_size, final_size), Image.LANCZOS)


# ── Generate all sizes ─────────────────────────────────

os.makedirs('icons', exist_ok=True)
for sz in [16, 48, 128]:
    make_icon(sz).save(f'icons/icon{sz}.png', 'PNG')
    print(f'  icons/icon{sz}.png  ({sz}×{sz})')
print('Done — reload extension in chrome://extensions')
