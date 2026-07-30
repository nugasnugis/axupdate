#!/usr/bin/env bash
set -euo pipefail

DISPLAY_NUM="${DISPLAY_NUM:-:99}"
VNC_PORT="${VNC_PORT:-5901}"
NOVNC_WEB_PORT="${NOVNC_WEB_PORT:-6080}"
NOVNC_WEB_ROOT="${NOVNC_WEB_ROOT:-/usr/share/novnc/}"
PINGGY_PORT="${PINGGY_PORT:-$VNC_PORT}"
PINGGY_TYPE="${PINGGY_TYPE:-http}"
APP_CMD="${APP_CMD:-python3 axupdate.py}"

if [[ -z "${DISPLAY:-}" ]]; then
  export DISPLAY="$DISPLAY_NUM"
fi

Xvfb "$DISPLAY_NUM" -screen 0 1280x720x24 &
XVFB_PID=$!
trap 'kill "$XVFB_PID"' EXIT
sleep 3

websockify --web="$NOVNC_WEB_ROOT" "$NOVNC_WEB_PORT" localhost:"$VNC_PORT" &
WEBSOCKIFY_PID=$!
trap 'kill "$WEBSOCKIFY_PID"; kill "$XVFB_PID"' EXIT
sleep 3

bash -lc "$APP_CMD" &
AXUPDATE_PID=$!
trap 'kill "$AXUPDATE_PID"; kill "$WEBSOCKIFY_PID"; kill "$XVFB_PID"' EXIT

python3 pinggy_tunnel.py --port "$PINGGY_PORT" > /tmp/pinggy-url.txt 2>&1 &
PINGGY_PID=$!
sleep 5
PINGGY_URL=$(grep -E '^https?://' /tmp/pinggy-url.txt | tail -n 1 || true)

echo "axupdate launched and accessible through noVNC at:"
echo "  http://127.0.0.1:$NOVNC_WEB_PORT/vnc.html?host=127.0.0.1&port=$VNC_PORT"
if [[ -n "$PINGGY_URL" ]]; then
  echo "Pinggy tunnel URL: $PINGGY_URL"
else
  echo "Pinggy tunnel is starting. Check /tmp/pinggy-url.txt for the URL."
fi

echo "Use the Pinggy URL to reach the noVNC session from a browser."
echo "Press CTRL-C to stop the session."
wait $AXUPDATE_PID
