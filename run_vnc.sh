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
sleep 10

echo "axupdate launched and accessible through noVNC on port 5901"
echo "Kill this script to stop the session"
wait $AXUPDATE_PID