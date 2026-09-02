"""
render_flowchart.py — an animated GIF of the whole CloudFracture pipeline:
build -> attack -> log -> detect -> remediate. Stages light up in sequence
(pending -> active -> done) and the loop ends on "offense + defense, shipped".

    python tools/render_flowchart.py   ->   docs/media/project_flow.gif
"""

from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

FONT = r"C:\Windows\Fonts\consola.ttf"
FONTB = r"C:\Windows\Fonts\consolab.ttf"

BG = (13, 17, 23)
BOX = (22, 27, 34)
GREY = (110, 118, 129)
BLUE = (88, 166, 255)
GREEN = (63, 185, 80)
FG = (201, 209, 217)
SUB = (139, 148, 158)

STAGES = [
    ("1", "BUILD", ["Terraform -> vulnerable AWS", "agent | buckets | secret | IAM"]),
    ("2", "ATTACK", ["4 paths: PassRole privesc,", "poison | cred theft | exfil"]),
    ("3", "LOG", ["CloudTrail records", "every API call"]),
    ("4", "DETECT", ["4 Sigma rules fire", "tested green in CI"]),
    ("5", "REMEDIATE", ["least-privilege ->", "all attacks AccessDenied"]),
]

W, H = 1240, 300
MX, TOP = 28, 96
BW, BH, GAP = 210, 132, 29
TITLE = "CloudFracture  —  build  ·  attack  ·  detect  ·  remediate"
SUBTITLE = "one repo: build it, break it four ways, detect it, and prove the fix"


def _fonts():
    return {
        "title": ImageFont.truetype(FONTB, 26),
        "box": ImageFont.truetype(FONTB, 20),
        "sub": ImageFont.truetype(FONT, 13),
        "badge": ImageFont.truetype(FONTB, 20),
        "banner": ImageFont.truetype(FONTB, 19),
    }


def _accent(state):
    return {"P": GREY, "A": BLUE, "D": GREEN}[state]


def frame(states, f):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    d.text((MX, 22), TITLE, font=f["title"], fill=FG)
    d.text((MX, 58), SUBTITLE, font=f["sub"], fill=SUB)

    for i, (num, title, subs) in enumerate(STAGES):
        x = MX + i * (BW + GAP)
        st = states[i]
        col = _accent(st)
        # connector arrow from previous box
        if i > 0:
            ax = x - GAP - 2
            ay = TOP + BH // 2
            acol = GREEN if states[i - 1] == "D" else GREY
            d.line([(x - GAP + 4, ay), (x - 4, ay)], fill=acol, width=3)
            d.polygon([(x - 4, ay), (x - 12, ay - 6), (x - 12, ay + 6)], fill=acol)
        # box
        d.rounded_rectangle([x, TOP, x + BW, TOP + BH], radius=12, fill=BOX,
                            outline=col, width=3 if st != "P" else 1)
        # badge
        bx, by = x + 22, TOP + 26
        d.ellipse([bx - 16, by - 16, bx + 16, by + 16], fill=col if st != "P" else BOX,
                  outline=col, width=2)
        label = "OK" if st == "D" else num
        lw = d.textlength(label, font=f["badge"])
        d.text((bx - lw / 2, by - 12), label, font=f["badge"],
               fill=BG if st != "P" else col)
        # title + subs
        d.text((x + 48, TOP + 16), title, font=f["box"],
               fill=FG if st != "P" else SUB)
        for j, s in enumerate(subs):
            d.text((x + 20, TOP + 58 + j * 22), s, font=f["sub"], fill=SUB)

    # final banner
    if all(s == "D" for s in states):
        msg = "offense + defense loop, shipped as code  —  green in CI"
        bw = d.textlength(msg, font=f["banner"])
        bx0 = (W - bw) / 2 - 18
        d.rounded_rectangle([bx0, TOP + BH + 20, bx0 + bw + 36, TOP + BH + 56],
                            radius=10, fill=(16, 40, 22), outline=GREEN, width=2)
        d.text(((W - bw) / 2, TOP + BH + 27), msg, font=f["banner"], fill=GREEN)
    return img


def main():
    f = _fonts()
    steps = [
        ["A", "P", "P", "P", "P"],
        ["D", "A", "P", "P", "P"],
        ["D", "D", "A", "P", "P"],
        ["D", "D", "D", "A", "P"],
        ["D", "D", "D", "D", "A"],
        ["D", "D", "D", "D", "D"],
    ]
    frames = [frame(s, f) for s in steps]
    durations = [850, 850, 850, 850, 850, 3000]
    out = Path("docs/media/project_flow.gif")
    frames[0].save(out, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print("wrote", out)


if __name__ == "__main__":
    main()
