# axupdate

axupdate is a Linux GUI update manager for Debian Testing running KDE Plasma (Wayland). It uses PyQt6 and provides a package update table, security rating, and an embedded terminal-style output area.

## Files
- `axupdate.py` - main GUI application
- `axreports.py` - report engine plus GUI wrapper
- `axupdate.desktop` - XDG desktop launcher
- `axreports.desktop` - XDG desktop launcher for the report GUI
- `requirements.txt` - Python dependencies

## Install
```bash
sudo install -m755 axupdate.py /usr/local/bin/axupdate.py
sudo install -m755 axreports.py /usr/local/bin/axreports.py
sudo install -m644 icons/axupdate.svg /usr/share/pixmaps/axupdate.svg
sudo install -m644 icons/axreports.svg /usr/share/pixmaps/axreports.svg
sudo install -m644 axupdate.desktop /usr/share/applications/axupdate.desktop
sudo install -m644 axreports.desktop /usr/share/applications/axreports.desktop
pip install -r requirements.txt
```

## Run
```bash
python3 axupdate.py
python3 axreports.py --gui
```

## GitHub Actions Simulation
A workflow is provided to install dependencies, run syntax checks, and start a headless browser-accessible VNC session with noVNC.
