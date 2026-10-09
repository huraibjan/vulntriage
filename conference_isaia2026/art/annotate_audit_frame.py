#!/usr/bin/env python3
"""Put the real model inputs on the sheet in the slide-8 close-up frame.

The generated frame shows a magnifying glass over a sheet of placeholder lines.
This repaints the sheet with the feature groups the paper audits and shows the
two exploit-derived inputs in red under the lens (the circularity finding).
Source frame: generated/08a_audit_v2_closeup_blank.png -> generated/08a_audit.png
"""
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

GEN = Path(__file__).resolve().parent / "generated"
SRC, OUT = GEN / "08a_audit_v2_closeup_blank.png", GEN / "08a_audit.png"
FONT = "/System/Library/Fonts/Supplemental/Arial.ttf"
BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"
INK, RED, MUTED = (58, 66, 86), (214, 54, 60), (120, 126, 140)
TILT = 7.0  # degrees; the sheet's lines rise to the right

im = Image.open(SRC).convert("RGB")
a = np.asarray(im).astype(int)
H, W = a.shape[:2]

# Lens ring, measured on the source frame (the handle makes automatic fitting unreliable).
yy, xx = np.mgrid[0:H, 0:W]
cx, cy, r_outer, r_inner = 322, 495, 177, 158

# Sheet: bright, low-saturation pixels right of the board edge.
bright = (a.min(axis=2) > 196) & ((a.max(axis=2) - a.min(axis=2)) < 30) & (xx > 215)
paper_rgb = tuple(int(v) for v in np.median(a[bright], axis=0))
cols = np.nonzero(bright.sum(axis=0) > 200)[0]
left, right = cols.min(), cols.max()
top_left = np.nonzero(bright[:, left + 12])[0].min()
top_right = np.nonzero(bright[:, right - 12])[0].min()
sheet = [(left, top_left), (right, top_right), (right + 6, H), (left + 2, H)]
print("sheet", sheet, "colour", paper_rgb)

SHEAR = float(np.tan(np.radians(TILT)))


def sheared(layer, pivot_x):
    """Tilt lines upward to the right while keeping the left margin vertical, as on the sheet."""
    return layer.transform((W, H), Image.AFFINE, (1, 0, 0, SHEAR, 1, -SHEAR * pivot_x), resample=Image.BICUBIC)


def rotated_layer(draw_fn):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw_fn(ImageDraw.Draw(layer))
    return sheared(layer, left)

# 1. Repaint the sheet (keeping the pins), with a soft shadow where the lens sits.
sheet_mask = Image.new("L", (W, H), 0)
ImageDraw.Draw(sheet_mask).polygon(sheet, fill=255)
pins = (a.sum(axis=2) < 330) & (yy < 190)          # the two dark pin heads
keep = Image.fromarray((pins * 255).astype("uint8")).filter(ImageFilter.MaxFilter(15))
ring = Image.new("L", (W, H), 0)
ImageDraw.Draw(ring).ellipse([cx - r_outer - 2, cy - r_outer - 2, cx + r_outer + 2, cy + r_outer + 2], fill=255)
paint = Image.composite(Image.new("L", (W, H), 0), sheet_mask, Image.eval(keep, lambda v: v))
paint = Image.composite(Image.new("L", (W, H), 0), paint, ring)

paper = Image.new("RGB", (W, H), paper_rgb)
shadow = Image.new("L", (W, H), 0)
ImageDraw.Draw(shadow).ellipse([cx - r_outer + 26, cy - r_outer + 30, cx + r_outer + 26, cy + r_outer + 30], fill=70)
paper = Image.composite(Image.new("RGB", (W, H), (150, 150, 156)), paper, shadow.filter(ImageFilter.GaussianBlur(14)))

head = ImageFont.truetype(BOLD, 34)
row = ImageFont.truetype(FONT, 31)
small = ImageFont.truetype(FONT, 22)
x0 = left + 62
ROWS = [
    (top_left + 150, "CVSS base score"),
    (top_left + 222, "EPSS score"),
    (top_left + 318, "Public PoC flag"),
    (top_left + 402, "Metasploit flag"),
    (top_left + 498, "Reference count"),
    (top_left + 570, "Product count"),
    (top_left + 642, "Days since published"),
    (top_left + 714, "Description length"),
    (top_left + 786, "CWE category"),
]

def sheet_text(d):
    d.text((x0, top_left + 52), "MODEL INPUTS", font=head, fill=INK)
    d.line([(x0, top_left + 104), (x0 + 430, top_left + 104)], fill=MUTED, width=2)
    for y, label in ROWS:
        d.ellipse([x0, y + 12, x0 + 9, y + 21], fill=MUTED)
        d.text((x0 + 26, y), label, font=row, fill=INK)

paper.paste(rotated_layer(sheet_text), (0, 0), rotated_layer(sheet_text))
out = Image.composite(paper, im, paint)

# 2. Inside the lens: the two exploit-derived inputs, magnified and red.
lens = Image.new("RGB", (W, H), (250, 247, 240))
big = ImageFont.truetype(BOLD, 34)
note = ImageFont.truetype(FONT, 21)

def lens_text(d):
    lx = cx - r_inner + 30
    d.text((lx, cy - 74), "Public PoC flag", font=big, fill=RED)
    d.text((lx, cy - 16), "Metasploit flag", font=big, fill=RED)
    d.text((lx + 2, cy + 44), "same evidence as the label", font=note, fill=RED)

layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
lens_text(ImageDraw.Draw(layer))
layer = sheared(layer, cx)
lens.paste(layer, (0, 0), layer)
disc = Image.new("L", (W, H), 0)
ImageDraw.Draw(disc).ellipse([cx - r_inner, cy - r_inner, cx + r_inner, cy + r_inner], fill=255)
out = Image.composite(lens, out, disc.filter(ImageFilter.GaussianBlur(1.2)))
# glass highlight
hl = Image.new("L", (W, H), 0)
ImageDraw.Draw(hl).arc([cx - r_inner + 10, cy - r_inner + 10, cx + r_inner - 10, cy + r_inner - 10], 200, 250, fill=120, width=7)
out = Image.composite(Image.new("RGB", (W, H), (255, 255, 255)), out, hl.filter(ImageFilter.GaussianBlur(3)))

out.save(OUT)
print("wrote", OUT)
