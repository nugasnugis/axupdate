#!/usr/bin/env python3
import argparse
import signal
import sys
import time

import pinggy


def main() -> int:
    parser = argparse.ArgumentParser(description="Expose a local port through Pinggy.")
    parser.add_argument("--port", type=int, default=5901, help="Local port to expose")
    args = parser.parse_args()

    tunnel = pinggy.start_tunnel(args.port, type="http")
    print(tunnel.url, flush=True)

    def shutdown(signum, frame):
        try:
            tunnel.stop()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    raise SystemExit(main())