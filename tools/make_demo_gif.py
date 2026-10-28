"""Render docs/demo.gif from the real output of examples/walkthrough.py.

    pip install -e ".[demo]"
    python tools/make_demo_gif.py

No text is written by hand: the walkthrough is run, its stdout is captured, and a contiguous
slice of it (with a few over-long lines dropped) is drawn one line at a time.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.gif"

START = "[agent] Remove the test customer"
END = "customers: 200, orders: 1000"
SKIP = ("This will delete", "sample ")  # over-long lines; dropped, never edited

BG, FG = (22, 24, 30), (205, 211, 222)
COLORS = {"[agent]": (110, 190, 255), "[human]": (240, 200, 90)}
FONT_SIZE, PAD, LINE_H = 20, 28, 30
FONT_CANDIDATES = ["consola.ttf", "C:/Windows/Fonts/consola.ttf", "DejaVuSansMono.ttf"]

# Longer holds: the cascade line, the approval gate, the applied counts, the final state.
HOLDS = {"cascades={'orders': -4}": 1800, "approval_required": 1500, "customers now: 199": 2200, END: 3500}
BASE_MS = 450


def real_lines() -> list[str]:
    proc = subprocess.run([sys.executable, str(ROOT / "examples" / "walkthrough.py")],
                          capture_output=True, text=True, encoding="utf-8", cwd=ROOT,
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"}, check=True)
    lines = [ln.rstrip() for ln in proc.stdout.splitlines()]
    a = next(i for i, ln in enumerate(lines) if ln.startswith(START))
    b = next(i for i, ln in enumerate(lines) if ln.strip().endswith(END))
    return [ln for ln in lines[a:b + 1] if ln.strip() and not any(s in ln for s in SKIP)]


def color(line: str):
    for tag, c in COLORS.items():
        if line.startswith(tag):
            return c
    if "approval_required" in line or "risk=high" in line or "HIGH" in line:
        return (255, 150, 90)
    if "-> applied" in line or "now: 199" in line or "-> undone" in line or "customers: 200" in line:
        return (130, 220, 130)
    return FG


def main() -> None:
    font = None
    for f in FONT_CANDIDATES:
        try:
            font = ImageFont.truetype(f, FONT_SIZE)
            break
        except OSError:
            continue
    if font is None:
        raise SystemExit("no monospace font found (expected Consolas)")

    lines = real_lines()
    # Re-insert a blank gap before each speaker line, as in the real output.
    shown: list[str] = []
    for ln in lines:
        if ln.startswith("[") and shown:
            shown.append("")
        shown.append(ln)

    w = int(max(font.getlength(ln) for ln in shown)) + 2 * PAD
    h = len(shown) * LINE_H + 2 * PAD
    frames, durations = [], []
    for n in range(1, len(shown) + 1):
        img = Image.new("RGB", (w, h), BG)
        d = ImageDraw.Draw(img)
        for i, ln in enumerate(shown[:n]):
            d.text((PAD, PAD + i * LINE_H), ln, font=font, fill=color(ln))
        frames.append(img.quantize(colors=24, method=Image.Quantize.MEDIANCUT))
        last = shown[n - 1]
        durations.append(next((ms for k, ms in HOLDS.items() if k in last), BASE_MS if last else 200))

    OUT.parent.mkdir(exist_ok=True)
    frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(f"{OUT}: {OUT.stat().st_size / 1024:.0f} KB, {sum(durations) / 1000:.1f} s, {w}x{h}, {len(shown)} lines")


if __name__ == "__main__":
    main()
