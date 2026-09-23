#!/usr/bin/env python3
"""Export the checked-in mark and font as self-contained branding assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont


ROOT = Path(__file__).resolve().parent
NAME = "mcp-infisical-rs"
SVG = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVG)
THEMES = {
    "light": ("#F7F5F0", "#23201B", "#236B64", "#B66A45"),
    "dark": ("#23201B", "#F7F5F0", "#78B8AA", "#D99772"),
}
ICONS = {
    "resources": '<path d="m3 8 9-5 9 5-9 5ZM3 12l9 5 9-5M3 16l9 5 9-5"/>',
    "connections": '<path d="M2 12h6m8 0h6"/><circle cx="12" cy="12" r="4"/>',
    "certificates": '<path d="M11 21H5V3h10l4 4v5M14 3v5h5M13 19v3l3-2 3 2v-3"/><circle cx="16" cy="16" r="4"/>',
}


def document(width: int, height: int, title: str, body: str) -> str:
    return (
        f'<svg xmlns="{SVG}" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title">\n'
        f'<title id="title">{title}</title>\n{body}\n</svg>\n'
    )


def symbol(ink: str, teal: str, copper: str) -> str:
    root = ET.parse(ROOT / "symbol.svg").getroot()
    replacements = {"#23201B": ink, "#236B64": teal, "#B66A45": copper}
    for element in root.iter():
        for attribute in ("fill", "stroke"):
            value = element.get(attribute)
            if value in replacements:
                element.set(attribute, replacements[value])
    return "".join(ET.tostring(child, encoding="unicode") for child in root if child.tag != f"{{{SVG}}}title")


def wordmark(font: TTFont, x: float, baseline: float, size: float, color: str) -> str:
    glyphs = font.getGlyphSet()
    cmap = font.getBestCmap()
    scale = size / font["head"].unitsPerEm
    pieces = []
    for char in NAME:
        glyph = glyphs[cmap[ord(char)]]
        pen = SVGPathPen(glyphs)
        glyph.draw(pen)
        pieces.append(
            f'<path transform="translate({x:.3f} {baseline}) scale({scale:.6f} {-scale:.6f})" '
            f'd="{pen.getCommands()}"/>'
        )
        x += glyph.width * scale
    return f'<g fill="{color}" aria-label="{NAME}">' + "".join(pieces) + "</g>"


def exports() -> dict[str, bytes]:
    for entry in json.loads((ROOT / "fonts/sources.json").read_text()):
        data = (ROOT / "fonts" / entry["file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"Font source checksum mismatch: {entry['file']}")
    font = instantiateVariableFont(TTFont(ROOT / "fonts/Manrope.ttf"), {"wght": 750})
    files = {}
    for theme, (background, ink, teal, copper) in THEMES.items():
        mark = symbol(ink, teal, copper)
        files[f"symbol-{theme}.svg"] = document(96, 96, NAME, mark)
        for kind, width, height, mark_x, mark_y, size, text_x, baseline in (
            ("header", 960, 200, 48, 52, 80, 180, 128),
            ("wordmark", 760, 144, 24, 24, 61, 146, 94),
            ("social-preview", 1280, 640, 192, 272, 96, 332, 355),
        ):
            body = f'<rect width="{width}" height="{height}" fill="{background}"/>'
            body += f'<g transform="translate({mark_x} {mark_y})">{mark}</g>'
            body += wordmark(font, text_x, baseline, size, ink)
            files[f"{kind}-{theme}.svg"] = document(width, height, NAME, body)
        for name, paths in ICONS.items():
            body = f'<g fill="none" stroke="{ink}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{paths}</g>'
            files[f"{name}-{theme}.svg"] = document(24, 24, name.capitalize(), body)
    files["symbol-mono.svg"] = document(96, 96, NAME, symbol("#23201B", "#23201B", "#23201B"))
    return {name: content.encode() for name, content in files.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify checked-in SVGs without changing them")
    parser.add_argument("--png", action="store_true", help="Also render PNG exports; requires resvg-py")
    args = parser.parse_args()
    files = exports()
    if args.png:
        import resvg_py

        for theme in THEMES:
            files[f"social-preview-{theme}.png"] = resvg_py.svg_to_bytes(
                svg_string=files[f"social-preview-{theme}.svg"].decode(), skip_system_fonts=True
            )
            for size in (16, 32):
                files[f"symbol-{theme}-{size}.png"] = resvg_py.svg_to_bytes(
                    svg_string=files[f"symbol-{theme}.svg"].decode(), width=size, height=size, skip_system_fonts=True
                )
    assets = ROOT / "assets"
    if not args.check:
        assets.mkdir(exist_ok=True)
    mismatches = []
    for name, data in files.items():
        path = assets / name
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                mismatches.append(name)
        else:
            path.write_bytes(data)
    if mismatches:
        raise SystemExit("Stale branding exports: " + ", ".join(mismatches))
    print(f"{'Verified' if args.check else 'Exported'} {len(files)} branding assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
