"""
L.O.G.S. — Network Scan View
Runs a localhost nmap scan in a background QThread and displays port results.
"""

import logging
from datetime import datetime

from PyQt5.QtCore    import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui     import QColor
from PyQt5.QtWidgets import (
    QFrame, QHBoxLayout, QHeaderView, QLabel,
    QListWidget, QListWidgetItem, QMessageBox,
    QProgressBar, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

logger = logging.getLogger("logs.scan_view")

# Palette — matches firewall_window
BG   = "#eef1f6";  SURF = "#f8fafc";  HOV  = "#dde3ed"
BDR  = "#bfc8d6";  TXT  = "#1a1e2e";  MUT  = "#667388"
ACC  = "#1e88e5";  SUC  = "#2e7d55";  WAR  = "#8a6020";  DAN = "#8b2020"

# Risk sort order: lower number = more dangerous (sorts first ascending)
_RISK_PRIORITY = {"Critical": 0, "Risky": 1, "Low": 2, "Closed": 3}


class _SortableItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically by Qt.UserRole when set."""

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        mv = self.data(Qt.UserRole)
        ov = other.data(Qt.UserRole)
        if mv is not None and ov is not None:
            return mv < ov
        return super().__lt__(other)


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    """
    Runs the full scan pipeline in a background thread:
      NetworkScanner → FirewallAnalyzer → RiskEngine → AnomalyDetector

    Signals:
        scan_complete(dict): Combined results dict on success.
        scan_error(str):     Error message on failure.
        progress(str):       Status message updates.
    """

    scan_complete = pyqtSignal(dict)
    scan_error    = pyqtSignal(str)
    progress      = pyqtSignal(str)

    def __init__(self, profile: str = "standard", parent=None):
        super().__init__(parent)
        self._profile = profile

    def run(self):
        """Execute the full scan pipeline."""
        try:
            # ---- 1. Port scan ----
            self.progress.emit("Initializing nmap scanner…")
            from core.scanner import NetworkScanner, SCAN_PROFILES
            scanner = NetworkScanner()

            prof = SCAN_PROFILES.get(self._profile, SCAN_PROFILES["standard"])
            self.progress.emit(
                f"Scanning localhost ({prof['port_desc']} ports) "
                f"— {prof['label']}…"
            )
            scan_results = scanner.scan_localhost(profile=self._profile)

            # ---- 2. Firewall analysis ----
            self.progress.emit("Querying Windows Firewall rules via PowerShell…")
            from core.firewall import FirewallAnalyzer
            fw_analyzer  = FirewallAnalyzer()
            fw_results   = fw_analyzer.analyze()

            # ---- 3. Risk scoring ----
            self.progress.emit("Calculating risk score…")
            from core.risk_engine import RiskEngine
            risk_engine  = RiskEngine()
            risk_percent = risk_engine.calculate_risk(scan_results, fw_results)
            hints        = risk_engine.get_remediation_hints(scan_results, fw_results)

            # ---- 4. Anomaly detection ----
            self.progress.emit("Checking for anomalies against baseline…")
            from core.anomaly_detector import AnomalyDetector
            detector  = AnomalyDetector()
            anomalies = detector.detect(scan_results)

            # ---- 5. Combine ----
            open_ports = [
                p for p in scan_results.get("ports", [])
                if p.get("state") == "open"
            ]

            combined = {
                "scan_results":           scan_results,
                "firewall_results":       fw_results,
                "risk_percent":           risk_percent,
                "open_ports_count":       len(open_ports),
                "firewall_issues_count":  len(fw_results.get("issues", [])),
                "anomaly_count":          len(anomalies),
                "anomalies":              anomalies,
                "remediation_hints":      hints,
                "timestamp":              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            self.scan_complete.emit(combined)

        except Exception as exc:
            logger.error(f"ScanWorker failed: {exc}", exc_info=True)
            self.scan_error.emit(str(exc))


# ---------------------------------------------------------------------------
# Scan View Widget
# ---------------------------------------------------------------------------

class ScanView(QWidget):
    """
    Displays scan controls and a table of discovered open ports/services.

    Signals:
        scan_completed(dict): Emitted with combined results after a successful scan.
    """

    scan_completed = pyqtSignal(dict)
    scan_failed    = pyqtSignal(str)

    _RISK_COLORS = {
        "Critical": QColor("#ff4444"),
        "Risky":    QColor("#ffaa00"),
        "Low":      QColor("#00ff88"),
        "Closed":   QColor("#666674"),
    }

    CRITICAL_PORTS = frozenset({21, 22, 23, 445, 3389})
    RISKY_PORTS    = frozenset({25, 80, 110, 143, 443, 3306, 5432, 5900, 8080, 8443})

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: ScanWorker | None = None
        self._current_profile: str = "standard"
        self._profile_keys: list[str] = []
        self._setup_ui()

    def _setup_ui(self):
        self.setStyleSheet(f"background-color: {BG};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        # Populate profile keys (controls live in the main window header)
        from core.scanner import SCAN_PROFILES, DEFAULT_PROFILE
        self._profile_keys = list(SCAN_PROFILES.keys())
        self._current_profile = DEFAULT_PROFILE

        # ---- Progress / status ----
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setVisible(False)
        self._progress_bar.setFixedHeight(3)
        self._progress_bar.setStyleSheet(
            f"QProgressBar {{ border: none; background: {HOV}; border-radius: 1px; }}"
            f"QProgressBar::chunk {{ background: {ACC}; border-radius: 1px; }}"
        )
        layout.addWidget(self._progress_bar)

        self._status_label = QLabel("Click 'Run Scan' in the header to begin.")
        self._status_label.setStyleSheet(f"color: {MUT}; font-size: 12px;")
        layout.addWidget(self._status_label)

        # ---- Results table ----
        self._table = QTableWidget()
        self._table.setColumnCount(5)
        self._table.setHorizontalHeaderLabels(
            ["Port", "Service", "Version", "State", "Risk Level"]
        )
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)   # Port
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)            # Service
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)            # Version
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)   # State
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)   # Risk Level
        self._table.setSortingEnabled(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet(
            f"QTableWidget {{ background: {SURF}; alternate-background-color: {BG}; "
            f"color: {TXT}; border: none; gridline-color: {BDR}; "
            f"font-size: 12px; outline: none; }}"
            f"QHeaderView::section {{ background: {HOV}; color: {MUT}; "
            f"border: none; border-bottom: 1px solid {BDR}; "
            f"padding: 9px 10px; font-size: 11px; font-weight: 600; "
            f"letter-spacing: 0.4px; }}"
            f"QTableWidget::item {{ padding: 6px 8px; }}"
            f"QTableWidget::item:selected {{ background: {HOV}; color: {TXT}; }}"
        )
        layout.addWidget(self._table)

        # ---- Findings panel (hidden until scan completes) ----
        self._findings_panel = QFrame()
        self._findings_panel.setVisible(False)
        self._findings_panel.setFixedHeight(180)
        self._findings_panel.setStyleSheet(
            f"QFrame {{ background: {SURF}; border-top: 1px solid {BDR}; }}"
        )
        findings_row = QHBoxLayout(self._findings_panel)
        findings_row.setContentsMargins(0, 0, 0, 0)
        findings_row.setSpacing(0)

        # Left column — Anomalies
        anomaly_col = QWidget()
        anomaly_col.setStyleSheet(f"background: transparent; border-right: 1px solid {BDR};")
        anomaly_layout = QVBoxLayout(anomaly_col)
        anomaly_layout.setContentsMargins(16, 10, 16, 10)
        anomaly_layout.setSpacing(6)
        self._anomaly_header = QLabel("Anomalies  (0)")
        self._anomaly_header.setStyleSheet(
            f"font-size: 11px; font-weight: 600; color: {MUT}; letter-spacing: 0.4px;"
        )
        self._anomaly_list = QListWidget()
        self._anomaly_list.setStyleSheet(
            f"QListWidget {{ background: transparent; border: none; color: {TXT}; font-size: 12px; }}"
            f"QListWidget::item {{ padding: 3px 0; }}"
        )
        self._anomaly_list.setFocusPolicy(Qt.NoFocus)
        anomaly_layout.addWidget(self._anomaly_header)
        anomaly_layout.addWidget(self._anomaly_list)
        findings_row.addWidget(anomaly_col)

        # Right column — Recommendations
        remed_col = QWidget()
        remed_col.setStyleSheet("background: transparent;")
        remed_layout = QVBoxLayout(remed_col)
        remed_layout.setContentsMargins(16, 10, 16, 10)
        remed_layout.setSpacing(6)
        self._remed_header = QLabel("Recommendations  (0)")
        self._remed_header.setStyleSheet(
            f"font-size: 11px; font-weight: 600; color: {MUT}; letter-spacing: 0.4px;"
        )
        self._remed_list = QListWidget()
        self._remed_list.setStyleSheet(
            f"QListWidget {{ background: transparent; border: none; color: {TXT}; font-size: 12px; }}"
            f"QListWidget::item {{ padding: 3px 0; }}"
        )
        self._remed_list.setFocusPolicy(Qt.NoFocus)
        remed_layout.addWidget(self._remed_header)
        remed_layout.addWidget(self._remed_list)
        findings_row.addWidget(remed_col)

        layout.addWidget(self._findings_panel)

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def set_profile(self, key: str):
        """Set the scan profile to use on the next run_scan() call."""
        self._current_profile = key

    def run_scan(self):
        """Start a scan using the current profile (set via set_profile or default)."""
        if self._worker and self._worker.isRunning():
            return

        self._progress_bar.setVisible(True)
        self._status_label.setText("Starting scan…")
        self._table.setRowCount(0)
        self._findings_panel.setVisible(False)

        self._worker = ScanWorker(profile=self._current_profile)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_error.connect(self._on_scan_error)
        self._worker.progress.connect(self._status_label.setText)
        self._worker.start()

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    @pyqtSlot(dict)
    def _on_scan_complete(self, data: dict):
        self._progress_bar.setVisible(False)

        profile_label = data.get("scan_results", {}).get("profile_label", "")
        suffix = f"  [{profile_label}]" if profile_label else ""
        ts = data.get("timestamp", "")
        self._status_label.setText(f"Scan complete — {ts}{suffix}")

        ports = data.get("scan_results", {}).get("ports", [])
        self._populate_table(ports)
        self._populate_findings(data)
        self.scan_completed.emit(data)

    @pyqtSlot(str)
    def _on_scan_error(self, error_msg: str):
        self._progress_bar.setVisible(False)
        self._status_label.setText(f"Scan failed: {error_msg}")
        self.scan_failed.emit(error_msg)
        QMessageBox.critical(
            self,
            "Scan Error",
            f"The scan encountered an error:\n\n{error_msg}\n\n"
            "Ensure:\n"
            "• nmap is installed and on your PATH\n"
            "• The application is run as Administrator",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _populate_findings(self, data: dict):
        """Populate the anomalies/recommendations findings panel."""
        # --- Anomalies ---
        anomalies = data.get("anomalies", [])
        self._anomaly_list.clear()
        self._anomaly_header.setText(f"Anomalies  ({len(anomalies)})")
        if anomalies:
            for msg in anomalies:
                item = QListWidgetItem(f"  {msg}")
                item.setForeground(QColor(WAR))
                self._anomaly_list.addItem(item)
        else:
            item = QListWidgetItem("  No anomalies detected")
            item.setForeground(QColor(SUC))
            self._anomaly_list.addItem(item)

        # --- Recommendations (network/port issues only, not firewall rule issues) ---
        hints = [h for h in data.get("remediation_hints", []) if not h.startswith("Firewall:")]
        self._remed_list.clear()
        self._remed_header.setText(f"Recommendations  ({len(hints)})")
        if hints:
            for hint in hints:
                item = QListWidgetItem(f"  {hint}")
                item.setForeground(QColor(TXT))
                self._remed_list.addItem(item)
        else:
            item = QListWidgetItem("  No recommendations — looking good")
            item.setForeground(QColor(SUC))
            self._remed_list.addItem(item)

        self._findings_panel.setVisible(True)

    def _populate_table(self, ports: list):
        self._table.setSortingEnabled(False)   # prevent mid-population re-sort
        self._table.setRowCount(len(ports))

        for row, p in enumerate(ports):
            port_num = p.get("port", 0)
            service  = p.get("service", "unknown") or "unknown"
            version  = p.get("version", "") or "—"
            state    = p.get("state", "unknown")

            if p.get("is_critical"):
                risk = "Critical"
            elif p.get("is_risky"):
                risk = "Risky"
            elif state == "open":
                risk = "Low"
            else:
                risk = "Closed"

            color = self._RISK_COLORS.get(risk, QColor("#888888"))

            for col, text in enumerate([str(port_num), service, version, state, risk]):
                item = _SortableItem(text)
                item.setForeground(color if col != 2 else QColor(MUT))
                item.setTextAlignment(Qt.AlignCenter)
                if col == 0:    # Port — numeric sort
                    item.setData(Qt.UserRole, port_num)
                elif col == 4:  # Risk Level — priority sort (Critical=0 first)
                    item.setData(Qt.UserRole, _RISK_PRIORITY.get(risk, 99))
                self._table.setItem(row, col, item)

        self._table.setSortingEnabled(True)
