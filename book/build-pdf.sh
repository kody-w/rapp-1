#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${PDF_OUTPUT:-$ROOT/book/the-rapp-programming-language.pdf}"
BUILD_DIR="$ROOT/.book-build/pdf"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

if ! command -v jekyll >/dev/null 2>&1; then
  echo "jekyll is required to build the print edition" >&2
  exit 1
fi

if [[ -n "${CHROME:-}" && -x "$CHROME" ]]; then
  CHROME_BIN="$CHROME"
elif [[ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]]; then
  CHROME_BIN="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
elif command -v google-chrome >/dev/null 2>&1; then
  CHROME_BIN="$(command -v google-chrome)"
elif command -v chromium >/dev/null 2>&1; then
  CHROME_BIN="$(command -v chromium)"
else
  echo "Google Chrome or Chromium is required to render the PDF" >&2
  exit 1
fi

PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

jekyll build \
  --source "$ROOT" \
  --destination "$BUILD_DIR" \
  --baseurl "" \
  --quiet

python3 -m http.server "$PORT" \
  --bind 127.0.0.1 \
  --directory "$BUILD_DIR" \
  >"$BUILD_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/book/print.html" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

curl -fsS "http://127.0.0.1:$PORT/book/print.html" >/dev/null

"$CHROME_BIN" \
  --headless=new \
  --disable-gpu \
  --no-pdf-header-footer \
  --print-to-pdf-no-header \
  --print-to-pdf="$OUTPUT" \
  "http://127.0.0.1:$PORT/book/print.html" \
  >/dev/null 2>&1

if [[ ! -s "$OUTPUT" ]]; then
  echo "PDF renderer did not create $OUTPUT" >&2
  exit 1
fi

if command -v pdfinfo >/dev/null 2>&1; then
  pdfinfo "$OUTPUT" | grep -E "^(Pages|Page size|File size)"
fi

echo "wrote $OUTPUT"
