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

echo "axupdate launched and accessible through noVNC at:"
echo "  http://127.0.0.1:5901/vnc.html?host=127.0.0.1&port=5901"
echo "Use this URL in a browser once port 5901 is forwarded or exposed."

echo "Press CTRL-C to stop the session."
wait $AXUPDATE_PID