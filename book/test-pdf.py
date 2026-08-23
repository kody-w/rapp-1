#!/usr/bin/env python3
"""Validate print geometry, text, and every external PDF annotation."""

from __future__ import annotations

import argparse
import html
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlparse


SOURCE_REVISION = "afc913ca3fe7dbc9da97871e67240f34416e5929"
PAGES_PREFIX = "https://kody-w.github.io/rapp-1/"
SOURCE_PREFIX = f"https://github.com/kody-w/rapp-1/blob/{SOURCE_REVISION}/"


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf", nargs="?", type=Path)
    parser.add_argument(
        "--portable-render",
        action="store_true",
        help="allow platform font pagination while retaining geometry and URI checks",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    pdf = args.pdf or root / "book" / "the-rapp-programming-language.pdf"
    pdf = pdf.resolve()
    assert pdf.is_file() and pdf.stat().st_size > 0

    info = run("pdfinfo", str(pdf))
    pages_match = re.search(r"^Pages:\s+(\d+)$", info, re.MULTILINE)
    assert pages_match, info
    pages = int(pages_match.group(1))
    if args.portable_render:
        assert 100 <= pages <= 108, info
    else:
        assert pages == 108, info
    assert re.search(r"^Page size:\s+432 x 648 pts", info, re.MULTILINE), info

    output = root / ".book-build" / "pdf-validation"
    output.mkdir(parents=True, exist_ok=True)
    xml_base = output / "book.xml"
    subprocess.run(
        ["pdftohtml", "-xml", "-hidden", "-i", str(pdf), str(xml_base)],
        check=True,
        capture_output=True,
        text=True,
    )
    xml = xml_base.read_text(encoding="utf-8")
    hrefs = [html.unescape(value) for value in re.findall(r'href="([^"]+)"', xml)]
    external = sorted({href for href in hrefs if urlparse(href).scheme})
    assert external, "PDF has no external URI annotations"

    for uri in external:
        parsed = urlparse(uri)
        assert parsed.scheme == "https", f"non-HTTPS PDF URI: {uri}"
        assert uri.startswith(PAGES_PREFIX) or uri.startswith(SOURCE_PREFIX), (
            f"PDF URI outside allowlist: {uri}"
        )

    forbidden = ("localhost", "127.0.0.1", "rapp-Clevergirl", "/Users/", ".copilot/")
    assert not any(token in uri for token in forbidden for uri in external), external
    assert f"{SOURCE_PREFIX}SPEC.md" in external
    assert f"{SOURCE_PREFIX}README.md" in external
    assert f"{SOURCE_PREFIX}examples/04_typed_addresses.py" in external
    assert f"{SOURCE_PREFIX}examples/05_failure_atlas.py" in external
    assert f"{PAGES_PREFIX}book/" in external

    text = run("pdftotext", str(pdf), "-")
    assert text.count("COPY EXAMPLES ONLINE") == 15
    assert re.search(r"The RAPP\s+Programming\s+Language", text)
    print(
        f"validated {pages}-page 6x9 PDF with {len(external)} "
        "HTTPS allowlisted URI annotations"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
