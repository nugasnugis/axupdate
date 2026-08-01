#!/usr/bin/env python3
"""axreports.py - lightweight OS update report generator.

Reports whether the system has pending Debian/apt updates and ranks them by
severity similar to a Mintreport-style summary.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

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


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an OS update report for Debian-based systems.")
    parser.add_argument("--version", action="store_true", help="Print the axreports application version and exit.")
    parser.add_argument("--json", action="store_true", help="Emit report as JSON instead of text output.")
    parser.add_argument("--apply", action="store_true", help="Apply pending updates from the active host package sources if any are available.")
    parser.add_argument("--repo-config", default="repo_sources.json", help="Path to the repo-source metadata file used for report links and channel mapping.")
    parser.add_argument("--output", help="Optional output file path for exported JSON or text report content.")
    args = parser.parse_args()

    if args.version:
        print(f"axreports {APP_VERSION}")
        return 0

    host_release = get_host_os_release()
    items = query_upgradable_packages(config_path=args.repo_config)
    if args.apply:
        return apply_updates(config_path=args.repo_config)

    payload = {
        "host": host_release,
        "updates": [asdict(item) for item in items],
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
