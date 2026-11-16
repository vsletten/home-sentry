"""Draw the HomeSentry app icon (1024x1024 PNG): a house inside a shield, on a rounded tile.

uv run python packaging/make_icon.py desktop/app-icon.png
(then `npx tauri icon desktop/app-icon.png` renders every platform size)
"""

from __future__ import annotations

import sys

from PIL import Image, ImageDraw

S = 1024


def lerp(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b, strict=True))


def main(out: str) -> None:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # macOS-style tile: rounded square, vertical gradient
    tile = Image.new("RGBA", (S, S))
    td = ImageDraw.Draw(tile)
    top, bottom = (36, 86, 196), (18, 40, 104)
    for y in range(S):
        td.line([(0, y), (S, y)], fill=lerp(top, bottom, y / S) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([64, 64, S - 64, S - 64], radius=200, fill=255)
    img.paste(tile, (0, 0), mask)
    d = ImageDraw.Draw(img)
    # shield
    cx = S // 2
    shield = [
        (cx, 180),
        (cx + 300, 280),
        (cx + 280, 560),
        (cx + 170, 760),
        (cx, 860),
        (cx - 170, 760),
        (cx - 280, 560),
        (cx - 300, 280),
    ]
    d.polygon(shield, fill=(246, 245, 241, 255))
    inner = [(x - (x - cx) * 0.12, y + (530 - y) * 0.12) for x, y in shield]
    d.polygon(inner, fill=(31, 157, 85, 255))
    # house
    d.polygon([(cx, 360), (cx + 170, 500), (cx - 170, 500)], fill=(246, 245, 241, 255))
    d.rectangle([cx - 125, 495, cx + 125, 680], fill=(246, 245, 241, 255))
    d.rounded_rectangle([cx - 40, 570, cx + 40, 680], radius=14, fill=(31, 157, 85, 255))
    img.save(out)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "app-icon.png")
