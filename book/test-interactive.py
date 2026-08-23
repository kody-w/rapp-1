#!/usr/bin/env python3
"""Validate the built interactive book without third-party Python packages."""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import subprocess
import sys


UPSTREAM_NOTICE = """Rapp Clevergirl
Copyright 2026 Wildhaven Homes LLC

This project contains work derived from OpenRappter:
https://github.com/kody-w/openrappter
Upstream source revision: 9913ca2e5237c44620f5422644cbe6060f2c8c18

The Observe Mode v2 engine, context adapters, closed contract, tests, fixtures,
skill guidance, and documentation were extracted from OpenRappter origin/main
and adapted into this standalone package under the Apache License 2.0.
"""


class BookParser(HTMLParser):
    VOID_ELEMENTS = {
        "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr",
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.examples: list[str] = []
        self._example_chunks: list[str] | None = None
        self.buttons = 0
        self.links = 0
        self.statuses = 0
        self.wrapper_kinds: list[str] = []
        self.prompt_declarations = 0
        self.hints = 0
        self.aria_labels: list[str] = []
        self.ids: list[str] = []
        self.wrapper_ids: list[str] = []
        self.anchor_hrefs: list[str] = []
        self.diagnostics = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        parent = self.stack[-1] if self.stack else ""
        if tag not in self.VOID_ELEMENTS:
            self.stack.append(tag)
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "code" and parent == "pre":
            self._example_chunks = []
        if tag in {"pre", "code"} and "data-copy-kind" in values:
            assert values["data-copy-kind"] in {"code", "prompt"}
            if values["data-copy-kind"] == "prompt":
                self.prompt_declarations += 1
        if "data-copy-example-state" in values:
            self.diagnostics += 1
        if "data-copy-example" in values:
            kind = values.get("data-copy-kind", "")
            assert kind in {"code", "prompt"}
            self.wrapper_kinds.append(kind)
            assert re.fullmatch(
                rf"{kind}-example-[a-z0-9-]+-\d+",
                values.get("id", ""),
            )
            self.wrapper_ids.append(values["id"])
        if "data-copy-example-button" in values:
            self.buttons += 1
            assert tag == "button"
            assert values.get("type") == "button"
            assert values.get("data-copy-kind") in {"code", "prompt"}
            assert values.get("aria-controls")
            assert values.get("aria-describedby")
            self.aria_labels.append(values.get("aria-label", ""))
        if "data-copy-example-link" in values:
            self.links += 1
            self.aria_labels.append(values.get("aria-label", ""))
            self.anchor_hrefs.append(values.get("href", ""))
        if "data-copy-example-status" in values:
            self.statuses += 1
            assert values.get("role") == "status"
            assert values.get("aria-live") == "polite"
            assert values.get("aria-atomic") == "true"
        if "data-copy-example-hint" in values:
            self.hints += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "code" and self._example_chunks is not None:
            self.examples.append("".join(self._example_chunks))
            self._example_chunks = None
        if self.stack:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if self._example_chunks is not None:
            self._example_chunks.append(data)


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
    script = assets / "copy-code-and-prompt-docs.js"
    assert script.is_file()
    stylesheet = assets / "copy-code-and-prompt-docs.css"
    assert stylesheet.is_file()
    license_file = assets / "COPY-CODE-AND-PROMPT-DOCS-LICENSE.txt"
    notice_file = assets / "COPY-CODE-AND-PROMPT-DOCS-NOTICE.txt"
    assert license_file.is_file()
    assert notice_file.is_file()
    assert hashlib.sha256(script.read_bytes()).hexdigest() == (
        "81246bcec676ff235dda93ed5b9e6079c59af6ad27f6340627b35db388a703ff"
    )
    assert hashlib.sha256(stylesheet.read_bytes()).hexdigest() == (
        "1fa5aa5a2197a89913b6316d75e6d9d68a773ba222a2ead4b9045b9f81fbc297"
    )
    assert hashlib.sha256(license_file.read_bytes()).hexdigest() == (
        "28fdcf32d60f1c8deee2ea703c60be19c896d6c282d24b0ea83631bba172fd08"
    )
    notice = notice_file.read_text(encoding="utf-8")
    assert "commit 5a01e1ec549cfa13efb8953eb2b386469c3bdbe2" in notice
    assert notice.endswith(UPSTREAM_NOTICE)
    runtime = script.read_text(encoding="utf-8")
    assert "fetch(" not in runtime
    assert "XMLHttpRequest" not in runtime
    assert "clipboard.read" not in runtime
    assert ".submit(" not in runtime
    assert "eval(" not in runtime

    pages = sorted(
        page for page in book.glob("*.html")
        if page.name != "print.html" and "<pre" in page.read_text(encoding="utf-8")
    )
    assert pages, "no interactive example pages were generated"
    chrome = chrome_binary()
    total = 0
    prompt_total = 0

    for page in pages:
        source_html = page.read_text(encoding="utf-8")
        assert "/book/assets/copy-code-and-prompt-docs.css" in source_html
        assert "/book/assets/copy-code-and-prompt-docs.js" in source_html
        source = parse(source_html)
        rendered_html = dump_dom(chrome, f"{args.base_url}/book/{page.name}")
        rendered = parse(rendered_html)
        assert rendered.examples == source.examples, f"example bytes changed in {page.name}"
        count = len(source.examples)
        assert len(rendered.wrapper_kinds) == count, f"wrapper mismatch in {page.name}"
        assert rendered.buttons == count, f"button mismatch in {page.name}"
        assert rendered.links == count, f"deep-link mismatch in {page.name}"
        assert rendered.statuses == count, f"status mismatch in {page.name}"
        assert rendered.wrapper_kinds.count("prompt") == source.prompt_declarations
        assert rendered.hints == source.prompt_declarations
        assert rendered.diagnostics == 0
        assert len(rendered.ids) == len(set(rendered.ids)), f"duplicate IDs in {page.name}"
        assert set(rendered.anchor_hrefs) == {f"#{anchor}" for anchor in rendered.wrapper_ids}
        if source.prompt_declarations:
            assert "Paste into any AI you choose and adapt it to your context." in rendered_html
        assert all(
            re.fullmatch(
                r"(Copy (?:code|prompt) to clipboard|Link to (?:code|prompt) example \d+)",
                label,
            )
            for label in rendered.aria_labels
        )
        assert all(
            "Copy code" not in text
            and "Copy prompt" not in text
            and "copied" not in text.lower()
            for text in rendered.examples
        )
        total += count
        prompt_total += source.prompt_declarations

    assert len(pages) == 14, f"expected 14 interactive pages, got {len(pages)}"
    assert total == 79, f"expected 79 examples, got {total}"
    assert prompt_total == 1, f"expected 1 prompt, got {prompt_total}"
    print(
        f"validated {total} byte-exact examples "
        f"({prompt_total} prompt) across {len(pages)} interactive pages"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
