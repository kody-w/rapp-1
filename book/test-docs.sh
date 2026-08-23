#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_ROOT="$ROOT/.book-build/tests"
SITE_A="$BUILD_ROOT/site-a"
SITE_B="$BUILD_ROOT/site-b"
SERVER_PID=""
SERVER_B_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_B_PID" ]]; then
    kill "$SERVER_B_PID" 2>/dev/null || true
    wait "$SERVER_B_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

if ! command -v jekyll >/dev/null 2>&1; then
  echo "jekyll is required" >&2
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
  echo "Google Chrome or Chromium is required" >&2
  exit 1
fi

for command in pdfinfo pdftohtml pdftotext; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "$command is required" >&2
    exit 1
  fi
done

rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"

jekyll build --source "$ROOT" --destination "$SITE_A" --baseurl "" --quiet
jekyll build --source "$ROOT" --destination "$SITE_B" --baseurl "" --quiet
diff -rq "$SITE_A" "$SITE_B"
cmp "$SITE_A/book/print.html" "$SITE_B/book/print.html"

PORT="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"

python3 -m http.server "$PORT" \
  --bind 127.0.0.1 \
  --directory "$SITE_A" \
  >"$BUILD_ROOT/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/book/" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$PORT/book/" >/dev/null

python3 "$ROOT/book/test-interactive.py" \
  "$SITE_A" \
  --base-url "http://127.0.0.1:$PORT"

"$CHROME_BIN" \
  --headless=new \
  --disable-gpu \
  --hide-scrollbars \
  --force-device-scale-factor=1 \
  --window-size=900,1200 \
  --virtual-time-budget=1000 \
  --screenshot="$BUILD_ROOT/print-a.png" \
  "http://127.0.0.1:$PORT/book/print.html" \
  >/dev/null 2>&1

PORT_B="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
python3 -m http.server "$PORT_B" \
  --bind 127.0.0.1 \
  --directory "$SITE_B" \
  >"$BUILD_ROOT/server-b.log" 2>&1 &
SERVER_B_PID=$!
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT_B/book/print.html" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -fsS "http://127.0.0.1:$PORT_B/book/print.html" >/dev/null

"$CHROME_BIN" \
  --headless=new \
  --disable-gpu \
  --hide-scrollbars \
  --force-device-scale-factor=1 \
  --window-size=900,1200 \
  --virtual-time-budget=1000 \
  --screenshot="$BUILD_ROOT/print-b.png" \
  "http://127.0.0.1:$PORT_B/book/print.html" \
  >/dev/null 2>&1
cmp "$BUILD_ROOT/print-a.png" "$BUILD_ROOT/print-b.png"

"$ROOT/book/build-pdf.sh"
python3 "$ROOT/book/test-pdf.py"

echo "documentation build, DOM, representative render, and PDF checks passed"
