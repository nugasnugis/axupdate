#!/usr/bin/env bash
set -euo pipefail

DISPLAY_NUM="${DISPLAY_NUM:-:99}"
VNC_PORT="${VNC_PORT:-5900}"
NOVNC_WEB_PORT="${NOVNC_WEB_PORT:-6080}"
NOVNC_WEB_ROOT="${NOVNC_WEB_ROOT:-/usr/share/novnc/}"
PINGGY_PORT="${PINGGY_PORT:-$NOVNC_WEB_PORT}"
APP_CMD="${APP_CMD:-python3 axupdate.py}"

export DISPLAY="$DISPLAY_NUM"

Xvfb "$DISPLAY_NUM" -screen 0 1280x720x24 &
XVFB_PID=$!
X11VNC_PID=""
WEBSOCKIFY_PID=""
APP_PID=""
PINGGY_PID=""

cleanup() {
  [[ -n "$APP_PID" ]] && kill "$APP_PID" 2>/dev/null || true
  [[ -n "$PINGGY_PID" ]] && kill "$PINGGY_PID" 2>/dev/null || true
  [[ -n "$WEBSOCKIFY_PID" ]] && kill "$WEBSOCKIFY_PID" 2>/dev/null || true
  [[ -n "$X11VNC_PID" ]] && kill "$X11VNC_PID" 2>/dev/null || true
  [[ -n "$XVFB_PID" ]] && kill "$XVFB_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 3
x11vnc -display "$DISPLAY_NUM" -nopw -forever -shared -rfbport "$VNC_PORT" &
X11VNC_PID=$!
sleep 2

websockify --web="$NOVNC_WEB_ROOT" "$NOVNC_WEB_PORT" localhost:"$VNC_PORT" &
WEBSOCKIFY_PID=$!
sleep 2

bash -lc "$APP_CMD" &
APP_PID=$!

python3 pinggy_tunnel.py --port "$PINGGY_PORT" > /tmp/pinggy-url.txt 2>&1 &
PINGGY_PID=$!
sleep 5
PINGGY_URL=$(grep -E '^https?://' /tmp/pinggy-url.txt | tail -n 1 || true)

# Print connection information for local browser and public relay.
echo "Local noVNC (browser): http://127.0.0.1:$NOVNC_WEB_PORT/vnc.html?host=127.0.0.1&port=$NOVNC_WEB_PORT"
if [[ -n "$PINGGY_URL" ]]; then
  echo "Pinggy public URL: $PINGGY_URL"
else
  echo "Pinggy tunnel is still starting; inspect /tmp/pinggy-url.txt for the public link."
fi

echo "The desktop session should now be reachable through noVNC."
echo "Press Ctrl+C to stop the launcher."
wait "$APP_PID"
