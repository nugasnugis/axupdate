# axupdate

axupdate is a Linux GUI update manager for Debian Testing running KDE Plasma (Wayland). It uses PyQt6 and provides a package update table, security rating, and an embedded terminal-style output area.

## Files
- `axupdate.py` - main GUI application
- `axupdate.desktop` - XDG desktop launcher
- `requirements.txt` - Python dependencies

## Install
```bash
sudo install -m755 axupdate.py /usr/local/bin/axupdate.py
sudo install -m644 axupdate.desktop /usr/share/applications/axupdate.desktop
pip install -r requirements.txt
```

## Run
```bash
python3 axupdate.py
```

## GitHub Actions Simulation
A workflow is provided to install dependencies, run syntax checks, and start a headless browser-accessible VNC session with noVNC.
