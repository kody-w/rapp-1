#!/usr/bin/env python3
"""Validate the built interactive book without third-party Python packages."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys


class BookParser(HTMLParser):
    VOID_ELEMENTS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.code: list[str] = []
        self._code_chunks: list[str] | None = None
        self.buttons = 0
        self.links = 0
        self.statuses = 0
        self.wrappers = 0
        self.aria_labels: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        parent = self.stack[-1] if self.stack else ""
        if tag not in self.VOID_ELEMENTS:
            self.stack.append(tag)
        if tag == "code" and parent == "pre":
            self._code_chunks = []
        if "data-copy-code-docs" in values:
            self.wrappers += 1
            assert re.fullmatch(r"code-example-[a-z0-9-]+-\d+", values.get("id", ""))
        if "data-copy-code-button" in values:
            self.buttons += 1
            assert tag == "button"
            assert values.get("type") == "button"
            self.aria_labels.append(values.get("aria-label", ""))
        if "data-copy-code-link" in values:
            self.links += 1
            self.aria_labels.append(values.get("aria-label", ""))
        if "data-copy-code-status" in values:
            self.statuses += 1
            assert values.get("role") == "status"
            assert values.get("aria-live") == "polite"

    def handle_endtag(self, tag: str) -> None:
        if tag == "code" and self._code_chunks is not None:
            self.code.append("".join(self._code_chunks))
            self._code_chunks = None
        if self.stack:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if self._code_chunks is not None:
            self._code_chunks.append(data)


def parse(html: str) -> BookParser:
    parser = BookParser()
    parser.feed(html)
    return parser


def chrome_binary() -> str:
    mac = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    if mac.is_file():
        return str(mac)
    for command in ("google-chrome", "chromium", "chromium-browser"):
        result = subprocess.run(
            ["sh", "-c", f"command -v {command}"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    raise RuntimeError("Chrome or Chromium is required")


def dump_dom(chrome: str, url: str) -> str:
    result = subprocess.run(
        [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--virtual-time-budget=1000",
            "--dump-dom",
            url,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("site", type=Path, help="Jekyll output directory")
    parser.add_argument("--base-url", required=True, help="HTTP origin serving site")
    args = parser.parse_args()

    book = args.site / "book"
    assets = book / "assets"
    assert (assets / "copy-code-docs.js").is_file()
    assert (assets / "copy-code-docs.css").is_file()
    runtime = (assets / "copy-code-docs.js").read_text(encoding="utf-8")
    assert "fetch(" not in runtime
    assert "XMLHttpRequest" not in runtime
    assert "clipboard.read" not in runtime

    pages = sorted(
        page for page in book.glob("*.html")
        if page.name != "print.html" and "<pre" in page.read_text(encoding="utf-8")
    )
    assert pages, "no interactive code pages were generated"
    chrome = chrome_binary()
    total = 0

    for page in pages:
        source = parse(page.read_text(encoding="utf-8"))
        rendered = parse(dump_dom(chrome, f"{args.base_url}/book/{page.name}"))
        assert rendered.code == source.code, f"code bytes changed in {page.name}"
        count = len(source.code)
        assert rendered.wrappers == count, f"wrapper mismatch in {page.name}"
        assert rendered.buttons == count, f"button mismatch in {page.name}"
        assert rendered.links == count, f"deep-link mismatch in {page.name}"
        assert rendered.statuses == count, f"status mismatch in {page.name}"
        assert all(
            re.fullmatch(r"(Copy|Link to) code example \d+", label)
            for label in rendered.aria_labels
        )
        assert all("Copy" not in text and "Copied" not in text for text in rendered.code)
        total += count

    print(f"validated {total} byte-exact examples across {len(pages)} interactive pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
