#!/usr/bin/env python3
"""axreports.py - lightweight OS update report generator.

Reports whether the system has pending Debian/apt updates and ranks them by
severity similar to a Mintreport-style summary.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

try:
    from PyQt6 import QtCore, QtWidgets
    HAVE_QT = True
except Exception:
    QtCore = None
    QtWidgets = None
    HAVE_QT = False

APP_VERSION = "1.0.0"


@dataclass
class PackageInfo:
    name: str
    current_version: str
    new_version: str
    size: str
    origin: str
    security_level: int
    repo_url: str = ""
    repo_channel: str = ""


def run_cmd_capture(cmd: List[str], timeout: Optional[int] = None, suppress_stderr: bool = False) -> str:
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL if suppress_stderr else subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return completed.stdout
    except subprocess.SubprocessError as exc:
        return f"ERROR running {' '.join(cmd)}: {exc}"


def classify_security_level(pkg_name: str, origin: str) -> int:
    pn = pkg_name.lower()
    o = (origin or "").lower()
    critical_keywords = [
        "libssl", "openssl", "libc6", "glibc", "linux-image", "linux-headers",
        "systemd", "sudo", "openssh", "grub", "bash", "containerd", "docker",
    ]
    if "security" in o or "-security" in o or "security.debian" in o:
        return 5
    if any(kw in pn for kw in critical_keywords):
        return 5
    if "backports" in o or "proposed" in o or "experimental" in o:
        return 4
    if pn.startswith("lib") or pn.endswith("-dev"):
        return 3
    if pn.startswith("linux-") or "kernel" in pn:
        return 5
    return 2


def load_repo_source_map(config_path: str = "repo_sources.json") -> Dict[str, Any]:
    default_map = {
        "version": 1,
        "defaults": {"repo_url": "https://deb.debian.org/debian", "channel": "stable"},
        "rules": [
            {"match": "security", "repo_url": "https://deb.debian.org/debian-security", "channel": "security"},
            {"match": "backports", "repo_url": "https://deb.debian.org/debian", "channel": "backports"},
            {"match": "proposed", "repo_url": "https://deb.debian.org/debian", "channel": "proposed"},
            {"match": "experimental", "repo_url": "https://deb.debian.org/debian", "channel": "experimental"},
            {"match": "debian", "repo_url": "https://deb.debian.org/debian", "channel": "stable"},
            {"match": "ubuntu", "repo_url": "https://archive.ubuntu.com/ubuntu", "channel": "ubuntu"},
        ],
        "release_channels": {
            "kernel": {"repo_url": "https://deb.debian.org/debian", "channel": "stable"},
            "applications": {"repo_url": "https://deb.debian.org/debian", "channel": "stable"},
            "os_upgrades": {"repo_url": "https://deb.debian.org/debian", "channel": "stable"},
        },
        "release_targets": {
            "bookworm": {"next": "trixie", "channel": "stable"},
            "trixie": {"next": "forky", "channel": "testing"},
            "forky": {"next": "duke", "channel": "testing"},
        },
    }

    try:
        with open(config_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return default_map


def repo_link_for(origin: str, package_name: str, config_path: str = "repo_sources.json") -> tuple[str, str]:
    origin_map = load_repo_source_map(config_path)
    defaults = origin_map.get("defaults", {})
    rules = origin_map.get("rules", [])
    o = (origin or "").lower()

    for rule in rules:
        match = (rule.get("match") or "").lower()
        if match and match in o:
            return (rule.get("repo_url") or defaults.get("repo_url") or "https://deb.debian.org/debian", rule.get("channel") or defaults.get("channel") or "stable")

    if "debian" in o:
        return (defaults.get("repo_url") or "https://deb.debian.org/debian", defaults.get("channel") or "stable")
    if "ubuntu" in o:
        return ("https://archive.ubuntu.com/ubuntu", "ubuntu")
    return ("https://packages.debian.org/" + package_name, "unknown")


def get_host_os_release() -> str:
    os_release_path = "/etc/os-release"
    if not os.path.exists(os_release_path):
        return "unknown"
    try:
        with open(os_release_path, "r", encoding="utf-8") as handle:
            data = handle.read()
    except Exception:
        return "unknown"

    for line in data.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def get_host_release_metadata() -> Dict[str, str]:
    os_release_path = "/etc/os-release"
    values: Dict[str, str] = {
        "PRETTY_NAME": "unknown",
        "VERSION_ID": "unknown",
        "VERSION_CODENAME": "unknown",
        "ID": "unknown",
    }
    if not os.path.exists(os_release_path):
        return values

    try:
        with open(os_release_path, "r", encoding="utf-8") as handle:
            data = handle.read()
    except Exception:
        return values

    for line in data.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in values:
            values[key] = value.strip().strip('"')
    return values


def read_host_apt_sources() -> str:
    source_parts: List[str] = []
    source_paths = ["/etc/apt/sources.list"]
    source_paths.extend(sorted(glob.glob("/etc/apt/sources.list.d/*")))
    for path in source_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                source_parts.append(handle.read())
        except Exception:
            continue
    return "\n".join(source_parts)


def detect_release_upgrade_status(config_path: str = "repo_sources.json") -> Dict[str, Any]:
    metadata = get_host_release_metadata()
    repo_map = load_repo_source_map(config_path)
    release_targets = repo_map.get("release_targets", {})
    current_codename = (metadata.get("VERSION_CODENAME") or "").lower()
    source_text = read_host_apt_sources().lower()

    target_release = None
    target_channel = "stable"
    do_release = shutil.which("do-release-upgrade")
    if do_release:
        detect_cmd = [do_release, "-s"]
        sim_output = run_cmd_capture(detect_cmd, timeout=60, suppress_stderr=True)
        match = re.search(r"New release '[^']+' available", sim_output, flags=re.IGNORECASE)
        if match:
            target_release = re.search(r"'([^']+)'", match.group(0))
            if target_release:
                target_release = target_release.group(1)
        if target_release:
            target_channel = "detected"

    fallback_target_info = release_targets.get(current_codename)
    if not target_release and isinstance(fallback_target_info, dict):
        target_release = (fallback_target_info or {}).get("next")
        target_channel = (fallback_target_info or {}).get("channel", "stable")

    current_supported = current_codename in source_text
    target_support = bool(target_release and target_release in source_text)
    source_support = current_supported or target_support

    return {
        "host": get_host_os_release(),
        "id": metadata.get("ID", "unknown"),
        "version_id": metadata.get("VERSION_ID", "unknown"),
        "codename": current_codename,
        "target_release": target_release,
        "target_channel": target_channel,
        "host_sources_support_current": current_supported,
        "host_sources_support_target": target_support,
        "ready_for_release_upgrade": bool(target_release and source_support),
        "source_of_truth": "/etc/apt/sources.list and /etc/apt/sources.list.d/*.list/*.sources",
        "detection_mode": "host-tool" if do_release else "fallback-map",
    }


def apply_release_upgrade(config_path: str = "repo_sources.json") -> int:
    status = detect_release_upgrade_status(config_path=config_path)
    target_release = status.get("target_release")
    if not target_release:
        print("[axreports] no Debian release upgrade target is defined for the current host code name.")
        return 1

    if not status.get("ready_for_release_upgrade"):
        print(
            "[axreports] host sources are not prepared for a release upgrade target; "
            "set the active Debian apt source definitions on the host in /etc/apt first."
        )
        return 2

    do_release = shutil.which("do-release-upgrade")
    apt_cmd = shutil.which("apt") or "/usr/bin/apt"
    sudo_cmd = shutil.which("sudo")

    if do_release:
        cmd = [do_release, "-f", "DistUpgradeViewNonInteractive"]
        if sudo_cmd and os.geteuid() != 0:
            cmd = [sudo_cmd] + cmd
        print(f"[axreports] running Debian release-upgrade toolchain: {' '.join(cmd)}")
        completed = subprocess.run(cmd, text=True)
        return int(completed.returncode)

    # Fall back to the host's supported apt based upgrade path when no dedicated
    # release-upgrade tool is present on the machine.
    cmd = [apt_cmd, "full-upgrade", "-y"]
    if sudo_cmd and os.geteuid() != 0:
        cmd = [sudo_cmd] + cmd
    print(f"[axreports] running host apt upgrade path for release-check preparation: {' '.join(cmd)}")
    completed = subprocess.run(cmd, text=True)
    return int(completed.returncode)


def query_upgradable_packages(config_path: str = "repo_sources.json") -> List[PackageInfo]:
    print("[axreports] running apt update...")
    _ = run_cmd_capture(["apt", "update"], timeout=90, suppress_stderr=True)

    raw = run_cmd_capture(["apt", "list", "--upgradable"], timeout=60, suppress_stderr=True)
    lines = raw.splitlines()
    results: List[PackageInfo] = []

    for line in lines:
        if not line or line.startswith("Listing..."):
            continue

        m = re.match(r"^([^/]+)/\S+\s+(\S+)\s+.*(\[upgradable from: ([^\]]+)\])?", line)
        if m:
            name = m.group(1)
            new_version = m.group(2) or ""
            current_version = m.group(4) or ""
        else:
            parts = line.split()
            if not parts:
                continue
            if "/" in parts[0]:
                name = parts[0].split("/", 1)[0]
            else:
                name = parts[0]
            new_version = parts[1] if len(parts) >= 2 else ""
            current_version = ""

        if name.startswith("WARNING:"):
            continue

        if not name:
            continue

        show_out = run_cmd_capture(["apt", "show", name], timeout=30)
        show_map = {}
        for show_line in show_out.splitlines():
            if ":" not in show_line:
                continue
            key, value = show_line.split(":", 1)
            show_map[key.strip().lower()] = value.strip()

        if not current_version:
            current_version = show_map.get("installed", show_map.get("version", ""))
        if not new_version:
            new_version = show_map.get("candidate", show_map.get("version", ""))

        size = show_map.get("size") or show_map.get("installed-size") or "Unknown"
        policy_out = run_cmd_capture(["apt-cache", "policy", name], timeout=20)
        origin = ""
        for pol_line in policy_out.splitlines():
            pol_line = pol_line.strip()
            if pol_line.startswith("500") or pol_line.startswith("100"):
                origin = pol_line
                break
            if "security" in pol_line.lower() or "security.debian" in pol_line.lower():
                origin = pol_line
                break
        if not origin:
            origin = policy_out.splitlines()[0] if policy_out.splitlines() else ""

        repo_url, repo_channel = repo_link_for(origin, name, config_path=config_path)
        results.append(
            PackageInfo(
                name=name,
                current_version=current_version,
                new_version=new_version,
                size=size,
                origin=origin,
                security_level=classify_security_level(name, origin),
                repo_url=repo_url,
                repo_channel=repo_channel,
            )
        )

    return results


def human_level(level: int) -> str:
    return {
        5: "Critical",
        4: "High",
        3: "Medium",
        2: "Normal",
        1: "Low",
    }.get(level, str(level))


def print_report(items: List[PackageInfo]) -> None:
    print("\n=== axreports update report ===")
    if not items:
        print("No pending operating system updates found.")
        return

    print(f"Updates found: {len(items)}")
    for item in items:
        print(
            f"- {item.name}: {item.current_version} -> {item.new_version} | "
            f"size={item.size} | origin={item.origin} | channel={item.repo_channel} | "
            f"repo={item.repo_url} | security={human_level(item.security_level)}"
        )


def to_json(items: List[PackageInfo]) -> str:
    return json.dumps([asdict(item) for item in items], indent=2)


def apply_updates(config_path: str = "repo_sources.json") -> int:
    items = query_upgradable_packages(config_path=config_path)
    if not items:
        print("[axreports] system already on the latest available host package sources.")
        return 0

    apt_cmd = shutil.which("apt") or "/usr/bin/apt"
    sudo_cmd = shutil.which("sudo")
    cmd = [apt_cmd, "full-upgrade", "-y"]
    if sudo_cmd and os.geteuid() != 0:
        cmd = [sudo_cmd] + cmd

    print(f"[axreports] applying updates from the active host sources: {' '.join(cmd)}")
    completed = subprocess.run(cmd, text=True)
    return int(completed.returncode)


class AxReportsWindow(QtWidgets.QMainWindow):
    def __init__(self, repo_config: str = "repo_sources.json"):
        super().__init__()
        self.repo_config = repo_config
        self.setWindowTitle("axreports")
        self.resize(860, 600)

        self.text_area = QtWidgets.QPlainTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setFont(QtWidgets.QApplication.font())

        self.refresh_btn = QtWidgets.QPushButton("Refresh Report")
        self.refresh_btn.clicked.connect(self.refresh_report)

        self.apply_btn = QtWidgets.QPushButton("Apply Package Updates")
        self.apply_btn.clicked.connect(self.apply_updates_gui)

        self.release_check_btn = QtWidgets.QPushButton("Release Check")
        self.release_check_btn.clicked.connect(self.release_check_gui)

        self.release_upgrade_btn = QtWidgets.QPushButton("Release Upgrade")
        self.release_upgrade_btn.clicked.connect(self.release_upgrade_gui)

        self.export_btn = QtWidgets.QPushButton("Export JSON")
        self.export_btn.clicked.connect(self.export_json)

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.refresh_btn)
        btn_row.addWidget(self.apply_btn)
        btn_row.addWidget(self.release_check_btn)
        btn_row.addWidget(self.release_upgrade_btn)
        btn_row.addWidget(self.export_btn)

        container = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(container)
        layout.addLayout(btn_row)
        layout.addWidget(self.text_area)
        self.setCentralWidget(container)

        self.refresh_report()

    def _payload(self) -> Dict[str, Any]:
        host_release = get_host_os_release()
        items = query_upgradable_packages(config_path=self.repo_config)
        return {
            "host": host_release,
            "updates": [asdict(item) for item in items],
            "release_upgrade": detect_release_upgrade_status(config_path=self.repo_config),
        }

    def refresh_report(self) -> None:
        payload = self._payload()
        self.text_area.setPlainText(json.dumps(payload, indent=2))

    def apply_updates_gui(self) -> None:
        rc = apply_updates(config_path=self.repo_config)
        self.text_area.setPlainText(f"[axreports] apply_updates returned exit code {rc}\n")
        self.refresh_report()

    def release_check_gui(self) -> None:
        payload = detect_release_upgrade_status(config_path=self.repo_config)
        self.text_area.setPlainText(json.dumps(payload, indent=2))

    def release_upgrade_gui(self) -> None:
        rc = apply_release_upgrade(config_path=self.repo_config)
        self.text_area.setPlainText(f"[axreports] release-upgrade path returned exit code {rc}\n")
        self.refresh_report()

    def export_json(self) -> None:
        payload = self._payload()
        output_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export JSON", "axreports-export.json", "JSON Files (*.json)")
        if output_path:
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, indent=2))
            self.text_area.setPlainText(f"[axreports] exported JSON to {output_path}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an OS update report for Debian-based systems.")
    parser.add_argument("--version", action="store_true", help="Print the axreports application version and exit.")
    parser.add_argument("--json", action="store_true", help="Emit report as JSON instead of text output.")
    parser.add_argument("--apply", action="store_true", help="Apply pending updates from the active host package sources if any are available.")
    parser.add_argument("--release-upgrade", action="store_true", help="Check and apply a Debian release-upgrade path using the host's configured apt/release toolchain.")
    parser.add_argument("--release-check", action="store_true", help="Print the Debian release-upgrade readiness status without mutating system package state.")
    parser.add_argument("--gui", action="store_true", help="Launch a graphical Mintreport-style window for the host report and release checks.")
    parser.add_argument("--repo-config", default="repo_sources.json", help="Path to the repo-source metadata file used for report links and channel mapping.")
    parser.add_argument("--output", help="Optional output file path for exported JSON or text report content.")
    args = parser.parse_args()

    if args.version:
        print(f"axreports {APP_VERSION}")
        return 0

    if args.gui:
        if not HAVE_QT:
            print("[axreports] GUI mode requires PyQt6 to be installed.")
            return 1
        app = QtWidgets.QApplication(sys.argv)
        window = AxReportsWindow(repo_config=args.repo_config)
        window.show()
        return app.exec()

    if args.release_check:
        report_text = json.dumps(detect_release_upgrade_status(config_path=args.repo_config), indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(report_text)
            print(f"[axreports] release status written to {args.output}")
            return 0
        print(report_text)
        return 0

    if args.release_upgrade:
        return apply_release_upgrade(config_path=args.repo_config)

    host_release = get_host_os_release()
    items = query_upgradable_packages(config_path=args.repo_config)
    if args.apply:
        return apply_updates(config_path=args.repo_config)

    payload = {
        "host": host_release,
        "updates": [asdict(item) for item in items],
        "release_upgrade": detect_release_upgrade_status(config_path=args.repo_config),
    }

    if args.json:
        report_text = json.dumps(payload, indent=2)
    else:
        report_text = f"[axreports] Host OS: {host_release}\n"
        report_text += "\n=== axreports update report ===\n"
        if not items:
            report_text += "No pending operating system updates found.\n"
        else:
            report_text += f"Updates found: {len(items)}\n"
            for item in items:
                report_text += (
                    f"- {item.name}: {item.current_version} -> {item.new_version} | "
                    f"size={item.size} | origin={item.origin} | channel={item.repo_channel} | "
                    f"repo={item.repo_url} | security={human_level(item.security_level)}\n"
                )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report_text)
        print(f"[axreports] report written to {args.output}")
        return 0

    print(report_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
