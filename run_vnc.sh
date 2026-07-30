#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DISPLAY:-}" ]]; then
  export DISPLAY=:99
fi

Xvfb :99 -screen 0 1280x720x24 &
XVFB_PID=$!
trap 'kill "$XVFB_PID"' EXIT
sleep 3

websockify --web=/usr/share/novnc/ 5901 localhost:5900 &
WEBSOCKIFY_PID=$!
trap 'kill "$WEBSOCKIFY_PID"; kill "$XVFB_PID"' EXIT
sleep 3

python3 axupdate.py &
AXUPDATE_PID=$!
trap 'kill "$AXUPDATE_PID"; kill "$WEBSOCKIFY_PID"; kill "$XVFB_PID"' EXIT

python3 pinggy_tunnel.py --port 5901 > /tmp/pinggy-url.txt 2>&1 &
PINGGY_PID=$!
sleep 5
PINGGY_URL=$(grep -E '^https?://' /tmp/pinggy-url.txt | tail -n 1 || true)

echo "axupdate launched and accessible through noVNC at:"
echo "  http://127.0.0.1:5901/vnc.html?host=127.0.0.1&port=5901"
if [[ -n "$PINGGY_URL" ]]; then
  echo "Pinggy tunnel URL: $PINGGY_URL"
else
  echo "Pinggy tunnel is starting. Check /tmp/pinggy-url.txt for the URL."
fi

echo "Use the Pinggy URL to reach the noVNC session from a browser."
echo "Press CTRL-C to stop the session."
wait $AXUPDATE_PID
