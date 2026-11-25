"""Generate the browser-extension icons with only the standard library.

Run: python scripts/make_extension_icons.py
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "extension" / "icons"
SIZES = (16, 32, 48, 128)
SUPERSAMPLE = 4

SHIELD = [
    (0.500, 0.150),
    (0.660, 0.208),
    (0.790, 0.258),
    (0.790, 0.500),
    (0.735, 0.640),
    (0.625, 0.760),
    (0.500, 0.852),
    (0.375, 0.760),
    (0.265, 0.640),
    (0.210, 0.500),
    (0.210, 0.258),
    (0.340, 0.208),
]

CHECK = [((0.360, 0.500), (0.462, 0.610)), ((0.462, 0.610), (0.665, 0.400))]


def inside_round_rect(px: float, py: float, x0: float, y0: float, x1: float, y1: float, radius: float) -> bool:
    if not (x0 <= px <= x1 and y0 <= py <= y1):
        return False
    cx = min(max(px, x0 + radius), x1 - radius)
    cy = min(max(py, y0 + radius), y1 - radius)
    if (px < x0 + radius or px > x1 - radius) and (py < y0 + radius or py > y1 - radius):
        return (px - cx) ** 2 + (py - cy) ** 2 <= radius * radius
    return True


def inside_polygon(px: float, py: float, points) -> bool:
    inside = False
    j = len(points) - 1
    for i, (xi, yi) in enumerate(points):
        xj, yj = points[j]
        if (yi > py) != (yj > py):
            x_cross = (xj - xi) * (py - yi) / (yj - yi) + xi
            if px < x_cross:
                inside = not inside
        j = i
    return inside


def segment_distance(px: float, py: float, a, b) -> float:
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    length = dx * dx + dy * dy
    if length == 0:
        return ((px - ax) ** 2 + (py - ay) ** 2) ** 0.5
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length))
    cx, cy = ax + t * dx, ay + t * dy
    return ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5


def gradient(t: float) -> tuple[int, int, int]:
    start = (91, 140, 255)
    end = (139, 92, 246)
    return tuple(round(start[i] + (end[i] - start[i]) * t) for i in range(3))


def render(size: int) -> bytes:
    width = size * SUPERSAMPLE
    pixels: list[tuple[int, int, int, int]] = []
    for y in range(width):
        for x in range(width):
            px = (x + 0.5) / width
            py = (y + 0.5) / width
            color = (0, 0, 0, 0)
            if inside_round_rect(px, py, 0.015, 0.015, 0.985, 0.985, 0.225):
                base = gradient((px + py) / 2)
                if inside_polygon(px, py, SHIELD):
                    stroke = min(segment_distance(px, py, a, b) for a, b in CHECK)
                    if stroke <= 0.062:
                        color = (31, 61, 158, 255)
                    else:
                        color = (245, 249, 255, 255)
                else:
                    color = (*base, 255)
            pixels.append(color)

    # Box-filter downsample.
    output = bytearray()
    for y in range(size):
        row = bytearray()
        for x in range(size):
            r = g = b = a = 0
            for sy in range(SUPERSAMPLE):
                for sx in range(SUPERSAMPLE):
                    pr, pg, pb, pa = pixels[(y * SUPERSAMPLE + sy) * width + x * SUPERSAMPLE + sx]
                    r += pr * pa
                    g += pg * pa
                    b += pb * pa
                    a += pa
            count = SUPERSAMPLE * SUPERSAMPLE
            if a:
                row.extend((r // a, g // a, b // a, a // count))
            else:
                row.extend((0, 0, 0, 0))
        output.extend(b"\x00")
        output.extend(row)
    return bytes(output)


def png(size: int) -> bytes:
    raw = render(size)

    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for size in SIZES:
        path = OUT_DIR / f"icon{size}.png"
        path.write_bytes(png(size))
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
