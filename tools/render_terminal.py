"""
render_terminal.py — turn a real command transcript into a styled terminal image
(PNG) and optionally an animated GIF (line-by-line reveal).

The input is REAL captured output; this only renders it attractively (like
carbon.now.sh / termtosvg) for the README and blog. No output is fabricated.

Usage:
  python tools/render_terminal.py <transcript.txt> --title "Path 1" --png out.png [--gif out.gif]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

FONT_REG = r"C:\Windows\Fonts\consola.ttf"
FONT_BOLD = r"C:\Windows\Fonts\consolab.ttf"

# GitHub-dark-ish palette
BG = (13, 17, 23)
WIN = (22, 27, 34)
BAR = (33, 38, 45)
FG = (201, 209, 217)
GREEN = (63, 185, 80)
AMBER = (210, 153, 34)
BLUE = (88, 166, 255)
GREY = (139, 148, 158)
YELLOW = (240, 201, 80)
DOTS = [(237, 106, 94), (245, 191, 79), (98, 197, 84)]

FS = 22
LH = 32
PAD = 26
BAR_H = 46
MARGIN = 20


def color_for(line: str):
    s = line.strip()
    if s.startswith("PS>") or s.startswith("$"):
        return BLUE
    if s.startswith("==="):
        return YELLOW
    if "[+]" in line or "proven: True" in line or "VIABLE" in line or "SUCCESS" in line \
            or " PASS" in line or "passed," in line or " YES " in line:
        return GREEN
    if "[!]" in line or "DENIED" in line or "AccessDenied" in line or " FAIL" in line:
        return AMBER
    if line.startswith("[agent]") or "[*]" in line or line.strip().startswith("(note"):
        return GREY
    if s.startswith("[finding]"):
        return BLUE
    return FG


def _fonts():
    return ImageFont.truetype(FONT_REG, FS), ImageFont.truetype(FONT_BOLD, FS)


def _canvas_size(lines, font, title):
    tmp = Image.new("RGB", (10, 10))
    d = ImageDraw.Draw(tmp)
    widest = max([d.textlength(l, font=font) for l in lines] + [d.textlength(title, font=font)])
    w = int(widest) + PAD * 2 + MARGIN * 2
    h = BAR_H + PAD * 2 + LH * len(lines) + MARGIN * 2
    return max(w, 640), h


def _draw(lines, font, bold, title, size, upto=None):
    w, h = size
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    # window
    d.rounded_rectangle([MARGIN, MARGIN, w - MARGIN, h - MARGIN], radius=12, fill=WIN)
    # title bar
    d.rounded_rectangle([MARGIN, MARGIN, w - MARGIN, MARGIN + BAR_H], radius=12, fill=BAR)
    d.rectangle([MARGIN, MARGIN + BAR_H - 12, w - MARGIN, MARGIN + BAR_H], fill=BAR)
    for i, c in enumerate(DOTS):
        cx = MARGIN + 22 + i * 22
        cy = MARGIN + BAR_H // 2
        d.ellipse([cx - 7, cy - 7, cx + 7, cy + 7], fill=c)
    tw = d.textlength(title, font=bold)
    d.text(((w - tw) / 2, MARGIN + (BAR_H - FS) / 2 - 2), title, font=bold, fill=GREY)
    # body
    y = MARGIN + BAR_H + PAD
    shown = lines if upto is None else lines[:upto]
    for line in shown:
        d.text((MARGIN + PAD, y), line, font=font, fill=color_for(line))
        y += LH
    return img


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("transcript")
    ap.add_argument("--title", default="terminal")
    ap.add_argument("--png")
    ap.add_argument("--gif")
    args = ap.parse_args()

    lines = Path(args.transcript).read_text(encoding="utf-8").rstrip("\n").split("\n")
    font, bold = _fonts()
    size = _canvas_size(lines, font, args.title)

    if args.png:
        _draw(lines, font, bold, args.title, size).save(args.png)
        print("wrote", args.png)

    if args.gif:
        frames = []
        for k in range(1, len(lines) + 1):
            frames.append(_draw(lines, font, bold, args.title, size, upto=k))
        durations = [220] * (len(frames) - 1) + [2600]  # hold last frame
        frames[0].save(args.gif, save_all=True, append_images=frames[1:],
                       duration=durations, loop=0, optimize=True)
        print("wrote", args.gif)


if __name__ == "__main__":
    main()
