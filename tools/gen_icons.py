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
ORANGE = (255, 101,   0, 255)
BORDER = (255, 101,   0, 255)   # orange outline — crisp against dark background
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
    Heater shield for an S×S canvas.

    Normalised coordinates (0-1) are mapped into the padded work area
    [pad .. S-pad] on both axes, with pad = 8% of S.

    Circle for top arch (solved from 3 reference points):
      shoulders (0.14, 0.28), peak (0.50, 0.06)  →  cx=0.50, cy=0.465, r=0.405
    Arc angles: left ≈ 207.2°, peak = 270°, right ≈ 332.8°
    """
    pad = 0.08 * S
    SS  = S - 2 * pad          # working span

    def p(nx, ny):
        """Normalised [0-1] → canvas pixel."""
        return (pad + nx * SS, pad + ny * SS)

    # ── Top arch ────────────────────────────────────────
    arch_cx = pad + 0.500 * SS
    arch_cy = pad + 0.465 * SS
    arch_r  = 0.405 * SS
    arch    = arc_pts(arch_cx, arch_cy, arch_r, 207.2, 332.8, n=48)

    ls = arch[0]           # left  shoulder
    rs = arch[-1]          # right shoulder
    bp = p(0.500, 0.940)   # bottom point

    # ── Right side — nearly straight, slight outward taper ────────────
    # Arc tangent at 332.8° (CCW): (-sin332.8°, cos332.8°) = (0.454, 0.891)
    # Use a tiny k so the curve exits the arch smoothly but barely drifts outward.
    k    = SS * 0.030
    r_p1 = (rs[0] + 0.454*k, rs[1] + 0.891*k)  # smooth arch exit

    r_p3 = p(0.750, 0.820)                      # lower-right corner
    # P2: pulled inward of the straight rs→r_p3 line → slightly concave side
    mid_x = (rs[0] + r_p3[0]) / 2
    mid_y = (rs[1] + r_p3[1]) / 2
    r_p2  = (mid_x - 0.018*SS, mid_y)           # nudge inward

    right_side = cbez(rs,    r_p1, r_p2, r_p3,  n=32)
    right_bot  = cbez(r_p3,
                      p(0.635, 0.910),
                      p(0.555, 0.935),
                      bp,  n=18)

    # ── Left side — mirror ───────────────────────────────────────────
    l_p1 = (ls[0] - 0.454*k, ls[1] + 0.891*k)
    l_p3 = p(0.250, 0.820)
    mid_x = (ls[0] + l_p3[0]) / 2
    mid_y = (ls[1] + l_p3[1]) / 2
    l_p2  = (mid_x + 0.018*SS, mid_y)

    left_bot  = cbez(bp,
                     p(0.445, 0.935),
                     p(0.365, 0.910),
                     l_p3,  n=18)
    left_side = cbez(l_p3, l_p2, l_p1, ls, n=32)

    # Assemble (skip duplicate junction points)
    return (arch
            + right_side[1:]
            + right_bot [1:]
            + left_bot  [1:]
            + left_side [1:])


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

    img  = Image.new('RGBA', (S, S), TRANS)
    draw = ImageDraw.Draw(img)

    # 1. Dark rounded-square background (moderate corner radius)
    rrect(draw, 0, 0, S, S, int(S * 0.14), DARK)

    # 2. Shield outer fill (acts as the outline ring)
    outer = shield_pts(S)
    draw.polygon(outer, fill=BORDER)

    # 3. Quartered inner fill clipped to shield
    inner = shrink(outer, S * 0.030)
    mask  = make_mask(S, inner)

    ys = [pt[1] for pt in inner]; xs = [pt[0] for pt in inner]
    div_cx = (min(xs) + max(xs)) / 2
    div_cy = min(ys) + (max(ys) - min(ys)) * 0.488   # horizontal divider

    # TL=dark, TR=orange, BL=orange, BR=dark
    pattern = Image.new('RGBA', (S, S), DARK)
    pdraw   = ImageDraw.Draw(pattern)
    pdraw.rectangle([div_cx, 0,      S,      div_cy], fill=ORANGE)  # top-right
    pdraw.rectangle([0,      div_cy, div_cx, S     ], fill=ORANGE)  # bottom-left

    clipped = Image.new('RGBA', (S, S), TRANS)
    clipped.paste(pattern, mask=mask)
    img = Image.alpha_composite(img, clipped)

    # 4. Cross divider lines clipped to shield
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
