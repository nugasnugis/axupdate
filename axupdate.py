#!/usr/bin/env python3
"""
axupdate.py - GUI update manager (run as normal user; prompts for password on upgrade)
Requirements:
 - Python 3.9+
 - PyQt6 (python3-pyqt6)
 - plyer (optional) or notify-send (libnotify-bin)
Install:
 sudo install -m755 axupdate.py /usr/local/bin/axupdate.py
"""
import sys
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from typing import List, Optional

from PyQt6 import QtCore, QtGui, QtWidgets

# Optional notification support
try:
    from plyer import notification as plyer_notify
    HAVE_PLYER = True
except Exception:
    HAVE_PLYER = False


@dataclass
class PackageInfo:
    name: str
    current_version: str
    new_version: str
    size: str
    origin: str
    security_level: int
    checked: bool = True


@dataclass
class KernelInfo:
    package: str
    version: str
    status: str
    source: str = ""


def run_cmd_capture(cmd: List[str], timeout: Optional[int] = None) -> str:
    """Run a command and capture stdout+stderr as text."""
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return completed.stdout
    except subprocess.SubprocessError as e:
        return f"ERROR running {' '.join(cmd)}: {e}"


def classify_security_level(pkg_name: str, origin: str, candidate_version: str) -> int:
    pn = pkg_name.lower()
    o = (origin or "").lower()
    critical_keywords = [
        "libssl", "openssl", "libc6", "glibc", "linux-image", "linux-headers",
        "systemd", "sudo", "openssh", "grub", "bash", "containerd", "docker"
    ]
    if "security" in o or "-security" in o or "security.debian" in o:
        return 5
    for kw in critical_keywords:
        if kw in pn:
            return 5
    if "backports" in o or "proposed" in o or "experimental" in o:
        return 4
    if pn.startswith("lib") or pn.endswith("-dev"):
        return 3
    if pn.startswith("linux-") or "kernel" in pn:
        return 5
    return 2


class KernelThread(QtCore.QThread):
    results_ready = QtCore.pyqtSignal(list)
    status = QtCore.pyqtSignal(str)

    def run(self):
        self.status.emit("Querying installed and available kernel packages...")
        running = run_cmd_capture(["uname", "-r"], timeout=10).strip() or "unknown"
        installed_out = run_cmd_capture(["apt", "list", "--installed"], timeout=30)
        available_out = run_cmd_capture(["apt", "list"], timeout=30)

        entries: List[KernelInfo] = []
        seen = set()

        for raw_line in installed_out.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("Listing..."):
                continue
            if "linux-image" in line or "linux-headers" in line or "linux-modules" in line:
                parts = line.split()
                if len(parts) >= 1:
                    pkg = parts[0]
                    version = parts[1] if len(parts) >= 2 else ""
                    if pkg not in seen:
                        entries.append(KernelInfo(package=pkg, version=version, status="installed", source="host"))
                        seen.add(pkg)

        for raw_line in available_out.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("Listing..."):
                continue
            if "linux-image" in line or "linux-headers" in line or "linux-modules" in line:
                parts = line.split()
                if len(parts) >= 1:
                    pkg = parts[0]
                    version = parts[1] if len(parts) >= 2 else ""
                    if pkg not in seen:
                        entries.append(KernelInfo(package=pkg, version=version, status="available", source="apt"))
                        seen.add(pkg)

        for item in entries:
            if item.package.startswith("linux-image") and item.version.startswith(running):
                item.status = "running"

        self.status.emit(f"Found {len(entries)} kernel entries.")
        self.results_ready.emit(entries)


class FetcherThread(QtCore.QThread):
    results_ready = QtCore.pyqtSignal(list)
    status = QtCore.pyqtSignal(str)

    def run(self):
        self.status.emit("Running apt update (no password required if possible)...")
        # First attempt: run apt update as current user
        out = run_cmd_capture(["apt", "update"], timeout=60)
        if ("permission denied" in out.lower() or "e: could not open lock" in out.lower() or "e: permission denied" in out.lower()):
            # Can't update without root; proceed to fetch upgradable list anyway
            self.status.emit("apt update could not run as user (permission issue); proceeding to check upgradable list.")
        else:
            self.status.emit("apt update completed (user).")

        self.status.emit("Querying upgradable packages...")
        raw = run_cmd_capture(["apt", "list", "--upgradable"])
        lines = raw.splitlines()
        pkgs: List[PackageInfo] = []
        for line in lines:
            if not line or line.startswith("Listing..."):
                continue
            m = re.match(r'^([^/]+)/\S+\s+(\S+)\s+.*(\[upgradable from: ([^\]]+)\])?', line)
            if m:
                name = m.group(1)
                new_ver = m.group(2) or ""
                cur_ver = m.group(4) or ""
            else:
                parts = line.split()
                if len(parts) >= 1 and "/" in parts[0]:
                    name = parts[0].split("/", 1)[0]
                else:
                    name = parts[0]
                new_ver = parts[1] if len(parts) >= 2 else ""
                cur_ver = ""
            name = name.strip()
            if not name:
                continue

            show_out = run_cmd_capture(["apt", "show", name])
            current = cur_ver
            cand = new_ver
            si = {}
            for line2 in show_out.splitlines():
                if ":" not in line2:
                    continue
                key, val = line2.split(":", 1)
                si[key.strip().lower()] = val.strip()
            if not current:
                current = si.get("installed", si.get("version", ""))
            if not cand:
                cand = si.get("candidate", si.get("version", ""))
            size = si.get("size") or si.get("installed-size") or "Unknown"
            policy_out = run_cmd_capture(["apt-cache", "policy", name])
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
            sec_level = classify_security_level(name, origin, cand)
            pkg = PackageInfo(name=name, current_version=current, new_version=cand, size=size, origin=origin, security_level=sec_level, checked=True)
            pkgs.append(pkg)

        self.status.emit(f"Found {len(pkgs)} upgradable packages.")
        self.results_ready.emit(pkgs)


class UpgradeThread(QtCore.QThread):
    output_line = QtCore.pyqtSignal(str)
    finished_signal = QtCore.pyqtSignal(int)
    password_requested = QtCore.pyqtSignal()
    status = QtCore.pyqtSignal(str)

    def __init__(self, packages: List[PackageInfo], parent=None):
        super().__init__(parent)
        self.packages = packages
        self._password_event = threading.Event()
        self._password_value = None
        self._stop_requested = False
        self.proc: Optional[QtCore.QProcess] = None
        self.need_sudo = False

    def run(self):
        axpm_path = shutil.which("axpm")
        apt_path = shutil.which("apt") or shutil.which("apt-get") or "apt"

        self.need_sudo = (os.geteuid() != 0)
        if axpm_path:
            base_cmd = [axpm_path, "full-upgrade", "-y"]
        else:
            base_cmd = [apt_path, "full-upgrade", "-y"]

        if self.need_sudo:
            cmd = ["sudo", "-S"] + base_cmd
        else:
            cmd = base_cmd

        self.status.emit("Starting upgrade command: " + " ".join(cmd))

        self.proc = QtCore.QProcess()
        self.proc.setProcessChannelMode(QtCore.QProcess.ProcessChannelMode.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._handle_output)
        self.proc.finished.connect(self._on_finished)
        self.proc.errorOccurred.connect(self._on_error)

        program = cmd[0]
        arguments = cmd[1:]
        self.proc.start(program, arguments)

        if not self.proc.waitForStarted(10000):
            self.output_line.emit("[axupdate] Failed to start upgrade process.")
            self.finished_signal.emit(1)
            return

        loop = QtCore.QEventLoop()
        self.proc.finished.connect(loop.quit)
        loop.exec()

    def _handle_output(self):
        if self.proc is None:
            return

        raw = self.proc.readAllStandardOutput().data().decode(errors="replace")
        for line in raw.splitlines():
            self.output_line.emit(line)
            if self.need_sudo and re.search(r"[Pp]assword", line):
                self.password_requested.emit()
                if not self._password_event.wait(30000):
                    self.output_line.emit("[axupdate] No password response received; aborting upgrade...")
                    if self.proc is not None and self.proc.state() == QtCore.QProcess.ProcessState.Running:
                        self.proc.kill()
                    break
                if self._password_value is None:
                    self.output_line.emit("[axupdate] No password provided; aborting upgrade...")
                    if self.proc is not None and self.proc.state() == QtCore.QProcess.ProcessState.Running:
                        self.proc.kill()
                    break
                try:
                    self.proc.write((self._password_value + "\n").encode())
                    self.proc.waitForBytesWritten(5000)
                except Exception as e:
                    self.output_line.emit(f"[axupdate] Failed to send password: {e}")
                self._password_value = None
                self._password_event.clear()
            if self._stop_requested and self.proc is not None and self.proc.state() == QtCore.QProcess.ProcessState.Running:
                self.proc.kill()
                break

    def _on_finished(self, exit_code: int, exit_status: QtCore.QProcess.ExitStatus):
        self.finished_signal.emit(exit_code)

    def _on_error(self, error: QtCore.QProcess.ProcessError):
        self.output_line.emit(f"[axupdate] Process error: {error}")

    def send_password(self, password: Optional[str]):
        self._password_value = password
        self._password_event.set()

    def stop(self):
        self._stop_requested = True
        self._password_event.set()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("axupdate - OS Update Manager")
        self.setWindowIcon(QtGui.QIcon.fromTheme("system-software-update"))
        self.resize(900, 700)
        self._packages: List[PackageInfo] = []
        self._kernels: List[KernelInfo] = []
        self.fetcher: Optional[FetcherThread] = None
        self.kernel_fetcher: Optional[KernelThread] = None
        self.upgrader: Optional[UpgradeThread] = None

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_v = QtWidgets.QVBoxLayout(central)
        main_v.setContentsMargins(8, 8, 8, 8)
        main_v.setSpacing(8)

        self.tabs = QtWidgets.QTabWidget()
        self.overview_page = QtWidgets.QWidget()
        overview_layout = QtWidgets.QVBoxLayout(self.overview_page)
        overview_layout.setContentsMargins(0, 0, 0, 0)
        overview_layout.setSpacing(8)

        self.header = QtWidgets.QLabel()
        self.header.setFixedHeight(80)
        self.header.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        font = self.header.font()
        font.setPointSize(18)
        font.setBold(True)
        self.header.setFont(font)
        self.header.setText("Checking for updates...")
        self.set_header_state("checking")
        overview_layout.addWidget(self.header)

        table_frame = QtWidgets.QFrame()
        table_layout = QtWidgets.QVBoxLayout(table_frame)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(6)

        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["", "Package", "Current Version", "New Version", "Size", "Security"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        table_layout.addWidget(self.table)

        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addStretch()
        self.update_btn = QtWidgets.QPushButton("Update Now")
        self.update_btn.setIcon(QtGui.QIcon.fromTheme("system-software-update"))
        self.update_btn.setFixedHeight(40)
        self.update_btn.setStyleSheet("font-size:16px; padding:8px;")
        self.update_btn.clicked.connect(self.on_update_now)
        btn_layout.addWidget(self.update_btn)
        table_layout.addLayout(btn_layout)

        overview_layout.addWidget(table_frame, stretch=3)

        term_label = QtWidgets.QLabel("Output")
        overview_layout.addWidget(term_label)
        self.terminal = QtWidgets.QTextEdit()
        self.terminal.setReadOnly(True)
        mono = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        self.terminal.setFont(mono)
        self.terminal.setMinimumHeight(220)
        overview_layout.addWidget(self.terminal, stretch=2)

        self.tabs.addTab(self.overview_page, "Overview")
        self.tabs.addTab(self._build_kernel_tab(), "Kernel")
        main_v.addWidget(self.tabs)

        self.status_bar = QtWidgets.QStatusBar()
        self.setStatusBar(self.status_bar)

        QtCore.QTimer.singleShot(200, self.start_fetch)
        QtCore.QTimer.singleShot(250, self.start_kernel_fetch)

    def set_header_state(self, state: str, updates_count: int = 0):
        if state == "ok":
            self.header.setStyleSheet("background-color:#2e7d32; color: white; border-radius:6px; padding:12px;")
            self.header.setText("System up to date")
        elif state == "updates":
            self.header.setStyleSheet("background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #1565c0, stop:1 #ff9800); color: white; border-radius:6px; padding:12px;")
            self.header.setText(f"{updates_count} updates available")
        else:
            self.header.setStyleSheet("background-color:#1976d2; color: white; border-radius:6px; padding:12px;")
            self.header.setText("Checking for updates...")

    def _build_kernel_tab(self) -> QtWidgets.QWidget:
        page = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.kernel_table = QtWidgets.QTableWidget(0, 4)
        self.kernel_table.setHorizontalHeaderLabels(["Package", "Version", "Status", "Source"])
        self.kernel_table.verticalHeader().setVisible(False)
        self.kernel_table.setAlternatingRowColors(True)
        self.kernel_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        header = self.kernel_table.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.kernel_table)

        btn_layout = QtWidgets.QHBoxLayout()
        self.kernel_refresh_btn = QtWidgets.QPushButton("Refresh Kernel List")
        self.kernel_refresh_btn.clicked.connect(self.start_kernel_fetch)
        self.install_kernel_btn = QtWidgets.QPushButton("Install Recommended Kernel")
        self.install_kernel_btn.clicked.connect(self.install_recommended_kernel)
        self.reboot_kernel_btn = QtWidgets.QPushButton("Reboot After Kernel Change")
        self.reboot_kernel_btn.clicked.connect(self.reboot_for_kernel_change)
        btn_layout.addWidget(self.kernel_refresh_btn)
        btn_layout.addWidget(self.install_kernel_btn)
        btn_layout.addWidget(self.reboot_kernel_btn)
        layout.addLayout(btn_layout)

        self.kernel_status = QtWidgets.QLabel("Kernel information not yet scanned.")
        layout.addWidget(self.kernel_status)
        return page

    def start_fetch(self):
        if self.fetcher is not None and self.fetcher.isRunning():
            return
        self.terminal.append("[axupdate] Starting package check...")
        self.fetcher = FetcherThread()
        self.fetcher.results_ready.connect(self.on_fetch_results)
        self.fetcher.status.connect(self.on_status)
        self.fetcher.start()

    def start_kernel_fetch(self):
        if self.kernel_fetcher is not None and self.kernel_fetcher.isRunning():
            return
        self.kernel_status.setText("Scanning kernel packages from the active host sources...")
        self.kernel_fetcher = KernelThread()
        self.kernel_fetcher.results_ready.connect(self.on_kernel_results)
        self.kernel_fetcher.status.connect(self.on_status)
        self.kernel_fetcher.start()

    def on_kernel_results(self, kernels: List[KernelInfo]):
        self._kernels = kernels
        self.kernel_table.setRowCount(0)
        for kernel in kernels:
            r = self.kernel_table.rowCount()
            self.kernel_table.insertRow(r)
            items = [
                QtWidgets.QTableWidgetItem(kernel.package),
                QtWidgets.QTableWidgetItem(kernel.version),
                QtWidgets.QTableWidgetItem(kernel.status),
                QtWidgets.QTableWidgetItem(kernel.source),
            ]
            for col, item in enumerate(items):
                item.setFlags(item.flags() ^ QtCore.Qt.ItemFlag.ItemIsEditable)
                self.kernel_table.setItem(r, col, item)
        self.kernel_status.setText(f"Kernel scan complete: {len(kernels)} entries found.")

    def install_recommended_kernel(self):
        reply = QtWidgets.QMessageBox.question(
            self,
            "Install recommended kernel",
            "Install the recommended kernel packages from the active host package sources?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if reply != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        self.terminal.append("[axupdate] Installing recommended kernel packages...")
        cmd = ["sudo", "apt", "install", "-y", "linux-image-generic", "linux-headers-generic"]
        completed = subprocess.run(cmd, text=True)
        self.terminal.append(f"[axupdate] Kernel install finished with exit code {completed.returncode}")
        self.start_kernel_fetch()

    def reboot_for_kernel_change(self):
        reply = QtWidgets.QMessageBox.question(
            self,
            "Reboot system",
            "Reboot now so the new kernel can be applied?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
        )
        if reply != QtWidgets.QMessageBox.StandardButton.Yes:
            return
        self.terminal.append("[axupdate] Rebooting system to apply kernel changes...")
        subprocess.run(["systemctl", "reboot"], check=False)

    def on_status(self, msg: str):
        self.status_bar.showMessage(msg, 5000)
        self.terminal.append(f"[fetch] {msg}")

    def on_fetch_results(self, pkgs: List[PackageInfo]):
        self._packages = pkgs
        self.refresh_table()
        if len(pkgs) == 0:
            self.set_header_state("ok")
            self.notify_updates(0)
        else:
            self.set_header_state("updates", updates_count=len(pkgs))
            self.notify_updates(len(pkgs))

    def refresh_table(self):
        self.table.setRowCount(0)
        for p in self._packages:
            r = self.table.rowCount()
            self.table.insertRow(r)
            chk = QtWidgets.QCheckBox()
            chk.setChecked(p.checked)
            cell_widget = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(cell_widget)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(chk)
            layout.setAlignment(chk, QtCore.Qt.AlignmentFlag.AlignCenter)
            self.table.setCellWidget(r, 0, cell_widget)
            name_item = QtWidgets.QTableWidgetItem(p.name)
            name_item.setFlags(name_item.flags() ^ QtCore.Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 1, name_item)
            cur_item = QtWidgets.QTableWidgetItem(p.current_version or "")
            cur_item.setFlags(cur_item.flags() ^ QtCore.Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 2, cur_item)
            new_item = QtWidgets.QTableWidgetItem(p.new_version or "")
            new_item.setFlags(new_item.flags() ^ QtCore.Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 3, new_item)
            size_item = QtWidgets.QTableWidgetItem(str(p.size))
            size_item.setFlags(size_item.flags() ^ QtCore.Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(r, 4, size_item)
            sec_item = QtWidgets.QTableWidgetItem(f"{p.security_level}")
            sec_item.setFlags(sec_item.flags() ^ QtCore.Qt.ItemFlag.ItemIsEditable)
            color_map = {5: "#b71c1c", 4: "#ff6f00", 3: "#f57f17", 2: "#0288d1", 1: "#2e7d32"}
            bg = color_map.get(p.security_level, "#9e9e9e")
            sec_item.setBackground(QtGui.QColor(bg))
            sec_item.setForeground(QtGui.QColor("white"))
            self.table.setItem(r, 5, sec_item)
            chk.stateChanged.connect(self.make_checkbox_slot(p))

    def make_checkbox_slot(self, pkg: PackageInfo):
        def on_state_changed(state):
            pkg.checked = (state == QtCore.Qt.CheckState.Checked)
        return on_state_changed

    def notify_updates(self, count: int):
        title = "axupdate"
        body = "System is up to date" if count == 0 else f"{count} updates available for axupdate"
        if HAVE_PLYER:
            try:
                plyer_notify.notify(title=title, message=body, app_name="axupdate")
                return
            except Exception:
                pass

        if shutil.which("notify-send"):
            try:
                subprocess.run(["notify-send", title, body], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    def on_update_now(self):
        selected = [p for p in self._packages if p.checked]
        if not selected:
            reply = QtWidgets.QMessageBox.question(self, "No packages selected", "No packages are selected for update in the list. Proceed to run full system upgrade anyway?", QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No)
            if reply != QtWidgets.QMessageBox.StandardButton.Yes:
                return
        self.update_btn.setEnabled(False)
        self.set_header_state("checking")
        self.terminal.append("[axupdate] Starting upgrade...")
        self.upgrader = UpgradeThread(self._packages)
        self.upgrader.output_line.connect(self._append_terminal)
        self.upgrader.password_requested.connect(self._on_password_requested)
        self.upgrader.finished_signal.connect(self._on_upgrade_finished)
        self.upgrader.status.connect(self.on_status)
        self.upgrader.start()

    @QtCore.pyqtSlot(str)
    def _append_terminal(self, text: str):
        self.terminal.append(text)
        self.terminal.verticalScrollBar().setValue(self.terminal.verticalScrollBar().maximum())

    @QtCore.pyqtSlot()
    def _on_password_requested(self):
        pwd, ok = QtWidgets.QInputDialog.getText(self, "Authentication required", "Enter your sudo password:", QtWidgets.QLineEdit.EchoMode.Password)
        if ok:
            if self.upgrader is not None:
                self.upgrader.send_password(pwd)
        else:
            if self.upgrader is not None:
                self.upgrader.send_password(None)

    @QtCore.pyqtSlot(int)
    def _on_upgrade_finished(self, rc: int):
        self.terminal.append(f"[axupdate] Upgrade finished with exit code {rc}")
        self.update_btn.setEnabled(True)
        self.start_fetch()
        if rc == 0:
            self.set_header_state("ok")
        else:
            self.set_header_state("updates", updates_count=len(self._packages))
        if shutil.which("notify-send"):
            try:
                subprocess.run(["notify-send", "axupdate", "Upgrade finished"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass


def main():
    app = QtWidgets.QApplication(sys.argv)
    try:
        app.setAttribute(QtCore.Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)
    except Exception:
        pass
    mw = MainWindow()
    mw.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
