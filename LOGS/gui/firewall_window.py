"""
L.O.G.S. — Main Application Window
Primary UI from netwatch_demo (FirewallDemoWindow) with a Network Scan tab
integrated from netwatch's ScanView.
"""

import ctypes
import logging
from datetime import datetime

from PyQt5.QtCore    import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui     import QColor
from PyQt5.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFormLayout,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QStackedWidget, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

logger = logging.getLogger("logs.firewall_window")


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# Palette
BG   = "#eef1f6";  SURF = "#f8fafc";  HOV  = "#dde3ed"
BDR  = "#bfc8d6";  TXT  = "#1a1e2e";  MUT  = "#667388"
ACC  = "#1e88e5";  SUC  = "#2e7d55";  WAR  = "#8a6020";  DAN = "#8b2020"

# Sort priorities (lower = sorts first on ascending click)
_SEVERITY_PRIORITY = {"High": 0, "Medium": 1, "Low": 2}


class _SortableItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically by Qt.UserRole when set."""

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        mv = self.data(Qt.UserRole)
        ov = other.data(Qt.UserRole)
        if mv is not None and ov is not None:
            return mv < ov
        return super().__lt__(other)


# ---------------------------------------------------------------------------
# Background firewall worker
# ---------------------------------------------------------------------------

class FirewallWorker(QThread):
    """Runs FirewallAnalyzer.analyze() off the main thread."""

    complete = pyqtSignal(dict)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)

    def run(self):
        try:
            self.progress.emit("Querying Windows Firewall rules via PowerShell…")
            from core.firewall import FirewallAnalyzer
            self.complete.emit(FirewallAnalyzer().analyze())
        except Exception as exc:
            logger.error(f"FirewallWorker failed: {exc}", exc_info=True)
            self.error.emit(str(exc))


# ---------------------------------------------------------------------------
# KPI stat card
# ---------------------------------------------------------------------------

class StatCard(QFrame):
    """Minimal stat card — large number, small label. Clickable to filter issues."""

    clicked = pyqtSignal(str)

    def __init__(self, label: str, color: str, filter_key: str = "", parent=None):
        super().__init__(parent)
        self._color      = color
        self._filter_key = filter_key
        self.setObjectName("statCard")
        self._base_ss = (
            f"QFrame#statCard {{ background: {SURF}; border-radius: 8px; "
            f"border: 1px solid {BDR}; }}"
        )
        self.setCursor(Qt.PointingHandCursor)

        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(4)
        lay.setContentsMargins(16, 12, 16, 12)

        self._val = QLabel("—")
        self._val.setAlignment(Qt.AlignCenter)
        self._val.setStyleSheet(f"font-size: 26px; font-weight: 700; color: {color};")

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet(f"font-size: 10px; color: {MUT}; letter-spacing: 0.5px;")

        lay.addWidget(self._val)
        lay.addWidget(lbl)

        self.setFixedSize(130, 80)
        self.setStyleSheet(self._base_ss)

    def set_value(self, val):
        self._val.setText(str(val))

    def set_active(self, active: bool):
        if active:
            self.setStyleSheet(
                f"QFrame#statCard {{ background: {SURF}; border-radius: 8px; "
                f"border: 2px solid {self._color}; }}"
            )
        else:
            self.setStyleSheet(self._base_ss)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self._filter_key)
        super().mousePressEvent(event)


# ---------------------------------------------------------------------------
# Add Rule dialog
# ---------------------------------------------------------------------------

class RuleDialog(QDialog):
    """Modal form for creating a new firewall rule."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Firewall Rule")
        self.setMinimumWidth(440)
        self.setStyleSheet(
            f"QDialog {{ background: {BG}; }}"
            f"QLabel {{ color: {TXT}; font-size: 12px; }}"
            f"QLineEdit, QComboBox {{ background: {HOV}; color: {TXT}; "
            f"border: 1px solid {BDR}; border-radius: 4px; "
            f"padding: 6px 10px; font-size: 12px; }}"
            f"QLineEdit:focus, QComboBox:focus {{ border-color: {ACC}; }}"
            f"QComboBox::drop-down {{ border: none; width: 18px; }}"
            f"QComboBox QAbstractItemView {{ background: {HOV}; color: {TXT}; "
            f"selection-background-color: {ACC}; border: 1px solid {BDR}; }}"
        )

        form = QFormLayout(self)
        form.setContentsMargins(24, 20, 24, 20)
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignRight)

        self._name = QLineEdit()
        self._name.setPlaceholderText("e.g.  Block Telnet Inbound")

        self._direction = QComboBox()
        self._direction.addItems(["Inbound", "Outbound"])

        self._action = QComboBox()
        self._action.addItems(["Block", "Allow"])

        self._protocol = QComboBox()
        self._protocol.addItems(["TCP", "UDP", "Any"])
        self._protocol.currentTextChanged.connect(self._on_proto_changed)

        self._port = QLineEdit()
        self._port.setPlaceholderText("80  or  8080-9000  or  Any")

        self._profile = QComboBox()
        self._profile.addItems(["Any", "Domain", "Private", "Public"])

        self._desc = QLineEdit()
        self._desc.setPlaceholderText("Optional description")

        form.addRow("Display Name *", self._name)
        form.addRow("Direction",      self._direction)
        form.addRow("Action",         self._action)
        form.addRow("Protocol",       self._protocol)
        form.addRow("Local Port",     self._port)
        form.addRow("Profile",        self._profile)
        form.addRow("Description",    self._desc)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setText("Create Rule")
        btns.button(QDialogButtonBox.Ok).setStyleSheet(
            f"QPushButton {{ background: {ACC}; color: #fff; border: none; "
            f"padding: 7px 20px; border-radius: 4px; "
            f"font-size: 12px; font-weight: 600; }}"
            f"QPushButton:hover {{ background: #0d47a1; }}"
        )
        btns.button(QDialogButtonBox.Cancel).setStyleSheet(
            f"QPushButton {{ background: transparent; color: {MUT}; "
            f"border: 1px solid {BDR}; padding: 7px 20px; "
            f"border-radius: 4px; font-size: 12px; }}"
            f"QPushButton:hover {{ color: {TXT}; border-color: #484860; }}"
        )
        btns.accepted.connect(self._validate)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def _on_proto_changed(self, text: str):
        self._port.setEnabled(text != "Any")
        if text == "Any":
            self._port.clear()
            self._port.setPlaceholderText("—")
        else:
            self._port.setPlaceholderText("80  or  8080-9000  or  Any")

    def _validate(self):
        if not self._name.text().strip():
            QMessageBox.warning(self, "Required", "Display Name is required.")
            return
        self.accept()

    def values(self) -> dict:
        return {
            "name":        self._name.text().strip(),
            "direction":   self._direction.currentText(),
            "action":      self._action.currentText(),
            "protocol":    self._protocol.currentText(),
            "port":        self._port.text().strip() or "Any",
            "profile":     self._profile.currentText(),
            "description": self._desc.text().strip(),
        }


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------


class FirewallDemoWindow(QMainWindow):
    """
    L.O.G.S. main window.

    Tabs:
    - Issues         (firewall issues from netwatch_demo)
    - All Rules      (all firewall rules from netwatch_demo)
    - Recent Changes (rule action history from netwatch_demo)
    - Network Scan   (port scan from netwatch)
    """

    _SEVERITY_COLORS = {
        "High":   QColor(DAN),
        "Medium": QColor(WAR),
        "Low":    QColor(SUC),
    }
    _DIR_MAP  = {"1": "Inbound",  "2": "Outbound"}
    _ACT_MAP  = {"2": "Allow",    "4": "Block"}
    _PROF_MAP = {"1": "Domain", "2": "Private", "4": "Public",
                 "2147483647": "Any", "-1": "Any"}

    def __init__(self):
        super().__init__()
        self.setWindowTitle("L.O.G.S. — Log, Observe, Guard, Secure")
        self.setMinimumSize(1100, 700)
        self._issues:            list = []
        self._displayed_issues:  list = []
        self._all_rules:         list = []
        self._changes:           list = []
        self._severity_filter:   str  = ""
        self._worker: FirewallWorker | None = None
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self):
        root = QWidget()
        root.setStyleSheet(f"background-color: {BG};")
        self.setCentralWidget(root)

        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Header spans full width
        main_layout.addWidget(self._build_header())

        # Body: sidebar on left, stacked content on right
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        body.addWidget(self._build_sidebar())

        self._stack = QStackedWidget()

        # Page 0 — Firewall Analysis (toolbar + tabs + action bar)
        fw_page = QWidget()
        fw_page.setStyleSheet(f"background: {BG};")
        fw_layout = QVBoxLayout(fw_page)
        fw_layout.setContentsMargins(0, 0, 0, 0)
        fw_layout.setSpacing(0)
        fw_layout.addWidget(self._build_toolbar())
        fw_layout.addWidget(self._build_firewall_tabs(), stretch=1)
        fw_layout.addWidget(self._build_actions())
        self._stack.addWidget(fw_page)

        # Page 1 — Network Scan
        from gui.scan_view import ScanView
        self._scan_view = ScanView()
        self._scan_view.scan_completed.connect(self._on_scan_header_complete)
        self._scan_view.scan_failed.connect(self._on_scan_header_failed)
        self._stack.addWidget(self._scan_view)

        # Page 2 — Recent Changes
        self._stack.addWidget(self._build_changes_panel())

        body.addWidget(self._stack)
        main_layout.addLayout(body, stretch=1)

        self._navigate(0)

    def _build_header(self) -> QFrame:
        bar = QFrame()
        bar.setStyleSheet(
            f"QFrame {{ background: {SURF}; border-bottom: 1px solid {BDR}; }}"
        )
        bar.setFixedHeight(88)

        row = QHBoxLayout(bar)
        row.setContentsMargins(28, 0, 28, 0)
        row.setSpacing(20)

        title_col = QVBoxLayout()
        title_col.setSpacing(3)
        logo = QLabel("L.O.G.S.")
        logo.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {TXT};")
        sub = QLabel("Log, Observe, Guard, Secure")
        sub.setStyleSheet(f"font-size: 11px; color: {MUT}; letter-spacing: 0.5px;")
        title_col.addStretch()
        title_col.addWidget(logo)
        title_col.addWidget(sub)
        title_col.addStretch()
        row.addLayout(title_col)
        row.addStretch()

        # --- Firewall KPI cards (shown on Firewall Analysis page) ---
        self._fw_cards_widget = QWidget()
        self._fw_cards_widget.setStyleSheet("background: transparent;")
        fw_cards_row = QHBoxLayout(self._fw_cards_widget)
        fw_cards_row.setContentsMargins(0, 0, 0, 0)
        fw_cards_row.setSpacing(20)
        fw_cards_row.setAlignment(Qt.AlignVCenter)

        self._card_total  = StatCard("Total Rules",     TXT, "")
        self._card_high   = StatCard("High Severity",   DAN, "High")
        self._card_medium = StatCard("Medium Severity", WAR, "Medium")
        self._card_low    = StatCard("Low Severity",    SUC, "Low")

        for card in (self._card_total, self._card_high,
                     self._card_medium, self._card_low):
            fw_cards_row.addWidget(card)
            card.clicked.connect(self._filter_by_severity)

        row.addWidget(self._fw_cards_widget)

        # --- Scan controls (shown on Network Scan page) ---
        self._scan_ctrl_widget = QWidget()
        self._scan_ctrl_widget.setStyleSheet("background: transparent;")
        self._scan_ctrl_widget.setVisible(False)
        scan_ctrl_row = QHBoxLayout(self._scan_ctrl_widget)
        scan_ctrl_row.setContentsMargins(0, 0, 0, 0)
        scan_ctrl_row.setSpacing(10)
        scan_ctrl_row.setAlignment(Qt.AlignVCenter)

        from core.scanner import SCAN_PROFILES, DEFAULT_PROFILE
        scan_profile_lbl = QLabel("Profile:")
        scan_profile_lbl.setStyleSheet(
            f"color: {MUT}; font-size: 12px; padding-right: 4px;"
        )
        scan_ctrl_row.addWidget(scan_profile_lbl)

        self._scan_profile_keys: list[str] = []
        self._scan_profile_combo = QComboBox()
        self._scan_profile_combo.setStyleSheet(
            f"QComboBox {{ background: {HOV}; color: {TXT}; "
            f"border: 1px solid {BDR}; border-radius: 4px; "
            f"padding: 6px 12px; font-size: 12px; min-width: 180px; }}"
            f"QComboBox:hover {{ border-color: {ACC}; }}"
            f"QComboBox::drop-down {{ border: none; }}"
            f"QComboBox QAbstractItemView {{ background: {HOV}; color: {TXT}; "
            f"selection-background-color: {ACC}; border: 1px solid {BDR}; }}"
        )
        default_scan_idx = 0
        for idx, (key, prof) in enumerate(SCAN_PROFILES.items()):
            self._scan_profile_combo.addItem(f"{prof['label']}  ({prof['port_desc']})")
            self._scan_profile_combo.setItemData(idx, prof["description"], Qt.ToolTipRole)
            self._scan_profile_keys.append(key)
            if key == DEFAULT_PROFILE:
                default_scan_idx = idx
        self._scan_profile_combo.setCurrentIndex(default_scan_idx)
        scan_ctrl_row.addWidget(self._scan_profile_combo)

        scan_ctrl_row.addSpacing(4)

        self._scan_risk_badge = QLabel("—")
        self._scan_risk_badge.setFixedHeight(26)
        self._scan_risk_badge.setAlignment(Qt.AlignCenter)
        self._scan_risk_badge.setStyleSheet(
            f"background: {HOV}; color: {MUT}; border-radius: 4px; "
            f"font-size: 11px; font-weight: 600; padding: 0 10px;"
        )
        scan_ctrl_row.addWidget(self._scan_risk_badge)

        self._scan_run_btn = QPushButton("Run Scan")
        self._scan_run_btn.setFixedHeight(34)
        self._scan_run_btn.setCursor(Qt.PointingHandCursor)
        self._scan_run_btn.setStyleSheet(
            f"QPushButton {{ background: {ACC}; color: #fff; border: none; "
            f"padding: 0 24px; font-size: 13px; font-weight: 600; border-radius: 5px; }}"
            f"QPushButton:hover    {{ background: #0d47a1; }}"
            f"QPushButton:disabled {{ background: {HOV}; color: {MUT}; }}"
        )
        self._scan_run_btn.clicked.connect(self._on_scan_header_run)
        scan_ctrl_row.addWidget(self._scan_run_btn)

        row.addWidget(self._scan_ctrl_widget)
        return bar

    def _build_toolbar(self) -> QFrame:
        bar = QFrame()
        bar.setFixedHeight(52)
        bar.setStyleSheet(
            f"QFrame {{ background: {BG}; border-bottom: 1px solid {BDR}; }}"
        )

        row = QHBoxLayout(bar)
        row.setContentsMargins(28, 0, 28, 0)
        row.setSpacing(10)

        self._analyze_btn = QPushButton("Analyze Firewall Rules")
        self._analyze_btn.setFixedHeight(34)
        self._analyze_btn.setCursor(Qt.PointingHandCursor)
        self._analyze_btn.setStyleSheet(
            f"QPushButton {{ background: {ACC}; color: #fff; border: none; "
            f"padding: 0 24px; font-size: 13px; font-weight: 600; border-radius: 5px; }}"
            f"QPushButton:hover    {{ background: #0d47a1; }}"
            f"QPushButton:disabled {{ background: {HOV}; color: {MUT}; }}"
        )
        self._analyze_btn.clicked.connect(self._run_analysis)

        self._add_btn = QPushButton("+ Add Rule")
        self._add_btn.setFixedHeight(34)
        self._add_btn.setCursor(Qt.PointingHandCursor)
        self._add_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {MUT}; "
            f"border: 1px solid {BDR}; border-radius: 5px; "
            f"padding: 0 18px; font-size: 12px; }}"
            f"QPushButton:hover {{ border-color: {ACC}; color: {ACC}; background: {HOV}; }}"
        )
        self._add_btn.clicked.connect(self._add_rule)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter issues…")
        self._search.setFixedHeight(34)
        self._search.setFixedWidth(220)
        self._search.setStyleSheet(
            f"QLineEdit {{ background: {HOV}; color: {TXT}; "
            f"border: 1px solid {BDR}; border-radius: 5px; "
            f"padding: 0 12px; font-size: 12px; }}"
            f"QLineEdit:focus {{ border-color: {ACC}; }}"
        )
        self._search.textChanged.connect(lambda _: self._apply_issue_filters())

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setVisible(False)
        self._progress_bar.setFixedHeight(3)
        self._progress_bar.setFixedWidth(180)
        self._progress_bar.setStyleSheet(
            f"QProgressBar {{ border: none; background: {HOV}; border-radius: 1px; }}"
            f"QProgressBar::chunk {{ background: {ACC}; border-radius: 1px; }}"
        )

        self._status_lbl = QLabel("Click Analyze Firewall Rules to begin.")
        self._status_lbl.setStyleSheet(f"color: {MUT}; font-size: 12px;")

        row.addWidget(self._analyze_btn)
        row.addWidget(self._add_btn)
        row.addSpacing(8)
        row.addWidget(self._search)
        row.addWidget(self._progress_bar)
        row.addWidget(self._status_lbl)
        row.addStretch()

        return bar

    def _build_firewall_tabs(self) -> QTabWidget:
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: none; background: {BG}; }}"
            f"QTabBar::tab {{ background: {SURF}; color: {MUT}; "
            f"border: none; border-bottom: 2px solid transparent; "
            f"padding: 10px 22px 16px 22px; font-size: 12px; min-width: 120px; }}"
            f"QTabBar::tab:selected {{ color: {TXT}; border-bottom: 2px solid {ACC}; }}"
            f"QTabBar::tab:hover {{ color: {TXT}; background: {HOV}; }}"
        )
        self._tabs.tabBar().setExpanding(False)
        self._tabs.addTab(self._build_issues_tab(),    "Issues")
        self._tabs.addTab(self._build_all_rules_tab(), "All Rules")
        return self._tabs

    def _make_table(self, headers: list) -> QTableWidget:
        t = QTableWidget()
        t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.setSortingEnabled(True)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.setAlternatingRowColors(True)
        t.verticalHeader().setVisible(False)
        t.setWordWrap(True)
        t.setStyleSheet(
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
        return t

    def _build_issues_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {BG};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self._table = self._make_table(
            ["Rule Name", "Issue Type", "Severity", "Suggested Fix"]
        )
        self._enable_name_only_sort(self._table)
        lay.addWidget(self._table)
        return w

    def _build_all_rules_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background: {BG};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self._all_table = self._make_table(
            ["Rule Name", "Direction", "Action", "Profile", "Enabled"]
        )
        self._enable_name_only_sort(self._all_table)
        lay.addWidget(self._all_table)
        return w

    def _enable_name_only_sort(self, table: QTableWidget):
        """Allow sorting only on the Rule Name column (col 0)."""
        hdr = table.horizontalHeader()

        def on_section_clicked(col):
            if col != 0:
                # Re-sort by name to undo Qt's auto-sort on other columns
                table.sortItems(0, hdr.sortIndicatorOrder())
                hdr.setSortIndicator(0, hdr.sortIndicatorOrder())

        hdr.sectionClicked.connect(on_section_clicked)

    def _build_changes_panel(self) -> QFrame:
        panel = QFrame()
        panel.setStyleSheet(f"QFrame {{ background: {BG}; }}")
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ---- Header bar ----
        header = QFrame()
        header.setFixedHeight(40)
        header.setStyleSheet(
            f"QFrame {{ background: {SURF}; border-bottom: 1px solid {BDR}; }}"
        )
        hr = QHBoxLayout(header)
        hr.setContentsMargins(20, 0, 20, 0)

        self._changes_header_lbl = QLabel("RECENT CHANGES")
        self._changes_header_lbl.setStyleSheet(
            f"font-size: 11px; font-weight: 600; color: {MUT}; letter-spacing: 0.5px;"
        )
        hr.addWidget(self._changes_header_lbl)
        hr.addSpacing(16)
        hint = QLabel("Changes made during this session are logged here.")
        hint.setStyleSheet(f"color: {MUT}; font-size: 11px;")
        hr.addWidget(hint)
        hr.addStretch()

        clear_btn = QPushButton("Clear History")
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.setFixedHeight(28)
        clear_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {MUT}; "
            f"border: 1px solid {BDR}; border-radius: 4px; "
            f"padding: 0 14px; font-size: 11px; }}"
            f"QPushButton:hover {{ color: {TXT}; border-color: #484860; "
            f"background: {HOV}; }}"
        )
        clear_btn.clicked.connect(self._clear_changes)
        hr.addWidget(clear_btn)
        lay.addWidget(header)

        # ---- Table ----
        self._changes_table = self._make_table(
            ["Time", "Action", "Rule Name", "Details"]
        )
        hdr2 = self._changes_table.horizontalHeader()
        hdr2.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr2.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr2.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr2.setSectionResizeMode(3, QHeaderView.Stretch)
        lay.addWidget(self._changes_table)

        return panel

    def _build_actions(self) -> QFrame:
        bar = QFrame()
        bar.setFixedHeight(54)
        bar.setStyleSheet(
            f"QFrame {{ background: {SURF}; border-top: 1px solid {BDR}; }}"
        )

        row = QHBoxLayout(bar)
        row.setContentsMargins(28, 0, 28, 0)
        row.setSpacing(10)

        help_lbl = QLabel("Select a row, then:")
        help_lbl.setStyleSheet(f"color: {MUT}; font-size: 12px;")
        row.addWidget(help_lbl)

        self._enable_btn = QPushButton("Enable Rule")
        self._enable_btn.setCursor(Qt.PointingHandCursor)
        self._enable_btn.setFixedHeight(32)
        self._enable_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {SUC}; "
            f"border: 1px solid {SUC}; border-radius: 5px; "
            f"padding: 0 18px; font-size: 12px; }}"
            f"QPushButton:hover {{ background: {SUC}; color: #fff; }}"
        )
        self._enable_btn.clicked.connect(self._enable_selected)

        self._disable_btn = QPushButton("Disable Rule")
        self._disable_btn.setCursor(Qt.PointingHandCursor)
        self._disable_btn.setFixedHeight(32)
        self._disable_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {WAR}; "
            f"border: 1px solid {WAR}; border-radius: 5px; "
            f"padding: 0 18px; font-size: 12px; }}"
            f"QPushButton:hover {{ background: {WAR}; color: #fff; }}"
        )
        self._disable_btn.clicked.connect(self._disable_selected)

        self._remove_btn = QPushButton("Remove Rule")
        self._remove_btn.setCursor(Qt.PointingHandCursor)
        self._remove_btn.setFixedHeight(32)
        self._remove_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {DAN}; "
            f"border: 1px solid {DAN}; border-radius: 5px; "
            f"padding: 0 18px; font-size: 12px; }}"
            f"QPushButton:hover {{ background: {DAN}; color: #fff; }}"
        )
        self._remove_btn.clicked.connect(self._remove_selected)

        row.addWidget(self._enable_btn)
        row.addWidget(self._disable_btn)
        row.addWidget(self._remove_btn)
        row.addStretch()

        admin = _is_admin()
        icon  = "✓" if admin else "✗"
        color = SUC  if admin else DAN
        text  = f"{icon}  Administrator privileges {'active' if admin else 'not detected'}"
        note  = QLabel(text)
        note.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: 600;")
        row.addWidget(note)

        return bar

    # ------------------------------------------------------------------
    # Sidebar navigation
    # ------------------------------------------------------------------

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setFixedWidth(180)
        sidebar.setStyleSheet(
            f"QFrame {{ background: {SURF}; border-right: 1px solid {BDR}; }}"
        )
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 16, 0, 16)
        layout.setSpacing(4)

        self._nav_buttons: list[QPushButton] = []
        for label, index in [
            ("  Firewall Analysis", 0),
            ("  Network Scan",      1),
            ("  Recent Changes",    2),
        ]:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setFixedHeight(42)
            btn.setStyleSheet(
                f"QPushButton {{ background: transparent; color: {MUT}; "
                f"border: none; border-left: 3px solid transparent; "
                f"padding: 0 16px; text-align: left; font-size: 13px; }}"
                f"QPushButton:hover {{ background: {HOV}; color: {TXT}; }}"
                f"QPushButton:checked {{ background: {HOV}; color: {TXT}; "
                f"border-left: 3px solid {ACC}; font-weight: 600; }}"
            )
            btn.clicked.connect(lambda _, i=index: self._navigate(i))
            layout.addWidget(btn)
            self._nav_buttons.append(btn)

        layout.addStretch()
        return sidebar

    def _navigate(self, index: int):
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.setChecked(i == index)
        self._fw_cards_widget.setVisible(index == 0)
        self._scan_ctrl_widget.setVisible(index == 1)

    # ------------------------------------------------------------------
    # Scan header slots
    # ------------------------------------------------------------------

    @pyqtSlot()
    def _on_scan_header_run(self):
        """Sync profile to ScanView, reset badge, disable controls, start scan."""
        idx = self._scan_profile_combo.currentIndex()
        if 0 <= idx < len(self._scan_profile_keys):
            self._scan_view.set_profile(self._scan_profile_keys[idx])
        self._scan_run_btn.setEnabled(False)
        self._scan_profile_combo.setEnabled(False)
        self._scan_risk_badge.setText("—")
        self._scan_risk_badge.setStyleSheet(
            f"background: {HOV}; color: {MUT}; border-radius: 4px; "
            f"font-size: 11px; font-weight: 600; padding: 0 10px;"
        )
        self._scan_view.run_scan()

    @pyqtSlot(dict)
    def _on_scan_header_complete(self, data: dict):
        """Re-enable controls and update risk badge after scan completes."""
        self._scan_run_btn.setEnabled(True)
        self._scan_profile_combo.setEnabled(True)
        pct = data.get("risk_percent", 0)
        badge_color = DAN if pct > 70 else WAR if pct > 30 else SUC
        self._scan_risk_badge.setText(f"Risk  {pct}%")
        self._scan_risk_badge.setStyleSheet(
            f"background: {HOV}; color: {badge_color}; border-radius: 4px; "
            f"font-size: 11px; font-weight: 600; padding: 0 10px;"
        )

    @pyqtSlot(str)
    def _on_scan_header_failed(self, _msg: str):
        """Re-enable controls after a failed scan."""
        self._scan_run_btn.setEnabled(True)
        self._scan_profile_combo.setEnabled(True)

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _run_analysis(self):
        if self._worker and self._worker.isRunning():
            return
        self._analyze_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._table.setRowCount(0)
        self._all_table.setRowCount(0)
        self._issues    = []
        self._all_rules = []
        self._reset_cards()
        self._worker = FirewallWorker()
        self._worker.complete.connect(self._on_complete)
        self._worker.error.connect(self._on_error)
        self._worker.progress.connect(self._status_lbl.setText)
        self._worker.start()

    @pyqtSlot(dict)
    def _on_complete(self, data: dict):
        self._analyze_btn.setEnabled(True)
        self._progress_bar.setVisible(False)

        self._issues    = data.get("issues", [])
        self._all_rules = data.get("rules",  [])
        total  = data.get("total_rules", 0)
        high   = sum(1 for i in self._issues if i.get("severity") == "High")
        medium = sum(1 for i in self._issues if i.get("severity") == "Medium")
        low    = sum(1 for i in self._issues if i.get("severity") == "Low")

        self._card_total.set_value(total)
        self._card_high.set_value(high)
        self._card_medium.set_value(medium)
        self._card_low.set_value(low)

        self._status_lbl.setText(
            f"{len(self._issues)} issue(s) found across {total} rule(s)  —  "
            f"High: {high}   Medium: {medium}   Low: {low}"
        )
        self._search.clear()
        self._populate_issues(self._issues)
        self._populate_all_rules(self._all_rules)
        self._card_total.set_active(True)

    @pyqtSlot(str)
    def _on_error(self, msg: str):
        self._analyze_btn.setEnabled(True)
        self._progress_bar.setVisible(False)
        self._status_lbl.setText(f"Error: {msg}")
        QMessageBox.critical(
            self, "Analysis Failed",
            f"{msg}\n\nEnsure you are running as Administrator.",
        )

    def _reset_cards(self):
        self._severity_filter = ""
        for card in (self._card_total, self._card_high,
                     self._card_medium, self._card_low):
            card.set_active(False)
            card.set_value("—")

    # ------------------------------------------------------------------
    # Table population
    # ------------------------------------------------------------------

    def _populate_issues(self, issues: list):
        self._displayed_issues = issues
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(issues))
        for row, issue in enumerate(issues):
            severity = issue.get("severity", "Low")
            color    = self._SEVERITY_COLORS.get(severity, QColor(MUT))
            for col, text in enumerate([
                issue.get("rule_name",     ""),
                issue.get("issue_type",    ""),
                severity,
                issue.get("suggested_fix", ""),
            ]):
                item = QTableWidgetItem(str(text))
                item.setForeground(color)
                self._table.setItem(row, col, item)
        self._table.setSortingEnabled(True)
        self._table.resizeRowsToContents()

    def _populate_all_rules(self, rules: list):
        self._all_table.setSortingEnabled(False)
        self._all_table.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            enabled    = rule.get("Enabled", True)
            is_enabled = str(enabled).lower() not in ("false", "0")
            dir_raw    = str(rule.get("Direction", ""))
            act_raw    = str(rule.get("Action", ""))
            prof_raw   = str(rule.get("Profile", ""))

            direction = self._DIR_MAP.get(dir_raw,  dir_raw)
            action    = self._ACT_MAP.get(act_raw,   act_raw)
            profile   = self._PROF_MAP.get(prof_raw, prof_raw)

            color = QColor(TXT) if is_enabled else QColor(MUT)
            for col, text in enumerate([
                rule.get("DisplayName", ""),
                direction,
                action,
                profile,
                "Yes" if is_enabled else "No",
            ]):
                item = QTableWidgetItem(str(text))
                item.setForeground(color)
                self._all_table.setItem(row, col, item)
        self._all_table.setSortingEnabled(True)
        self._all_table.resizeRowsToContents()

    # ------------------------------------------------------------------
    # Search / filter
    # ------------------------------------------------------------------

    def _apply_issue_filters(self):
        q   = self._search.text().lower()
        sev = self._severity_filter
        filtered = [
            i for i in self._issues
            if (not sev or i.get("severity") == sev)
            and (not q
                 or q in i.get("rule_name",     "").lower()
                 or q in i.get("issue_type",    "").lower()
                 or q in i.get("severity",      "").lower()
                 or q in i.get("suggested_fix", "").lower())
        ]
        self._populate_issues(filtered)

    def _filter_by_severity(self, severity: str):
        if severity and self._severity_filter == severity:
            severity = ""
        self._severity_filter = severity
        self._card_total.set_active(severity == "")
        self._card_high.set_active(severity == "High")
        self._card_medium.set_active(severity == "Medium")
        self._card_low.set_active(severity == "Low")
        self._tabs.setCurrentIndex(0)
        self._apply_issue_filters()

    # ------------------------------------------------------------------
    # Selected rule name (tab-aware)
    # ------------------------------------------------------------------

    def _selected_rule_name(self) -> str | None:
        tab = self._tabs.currentIndex()
        if tab == 0:
            row = self._table.currentRow()
            if row < 0:
                QMessageBox.warning(self, "No Selection",
                                    "Select a rule from the Issues table first.")
                return None
            item = self._table.item(row, 0)
            if item is None:
                QMessageBox.warning(self, "No Selection",
                                    "Select a valid rule row from the Issues table.")
                return None
            name = item.text().strip()
            return name or None
        elif tab == 1:
            row = self._all_table.currentRow()
            if row < 0:
                QMessageBox.warning(self, "No Selection",
                                    "Select a rule from the All Rules table first.")
                return None
            item = self._all_table.item(row, 0)
            if item is None:
                QMessageBox.warning(self, "No Selection",
                                    "Select a valid rule row from the All Rules table.")
                return None
            name = item.text().strip()
            return name or None
        else:
            QMessageBox.information(self, "Hint",
                                    "Select a rule from the Issues or All Rules tab first.")
            return None

    # ------------------------------------------------------------------
    # Change log
    # ------------------------------------------------------------------

    _CHANGE_COLORS = {
        "Added":    QColor(SUC),
        "Enabled":  QColor(SUC),
        "Disabled": QColor(WAR),
        "Removed":  QColor(DAN),
    }

    def _log_change(self, action: str, rule_name: str, details: str = ""):
        self._changes.insert(0, {
            "time":      datetime.now().strftime("%H:%M:%S"),
            "action":    action,
            "rule_name": rule_name,
            "details":   details,
        })
        self._refresh_changes_table()
        count = len(self._changes)
        self._changes_header_lbl.setText(f"RECENT CHANGES  ({count})")

    def _refresh_changes_table(self):
        self._changes_table.setRowCount(len(self._changes))
        for row, entry in enumerate(self._changes):
            color = self._CHANGE_COLORS.get(entry["action"], QColor(TXT))
            for col, text in enumerate([
                entry["time"],
                entry["action"],
                entry["rule_name"],
                entry["details"],
            ]):
                item = QTableWidgetItem(str(text))
                item.setForeground(color)
                self._changes_table.setItem(row, col, item)

    def _clear_changes(self):
        self._changes.clear()
        self._changes_table.setRowCount(0)
        self._changes_header_lbl.setText("RECENT CHANGES")

    # ------------------------------------------------------------------
    # Add Rule
    # ------------------------------------------------------------------

    def _add_rule(self):
        dlg = RuleDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        v = dlg.values()
        if QMessageBox.question(
            self, "Confirm Create",
            f"Create new firewall rule:\n\n"
            f"  Name:      {v['name']}\n"
            f"  Direction: {v['direction']}\n"
            f"  Action:    {v['action']}\n"
            f"  Protocol:  {v['protocol']}\n"
            f"  Port:      {v['port']}\n"
            f"  Profile:   {v['profile']}",
            QMessageBox.Yes | QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        try:
            from core.firewall import FirewallAnalyzer
            ok = FirewallAnalyzer().create_rule(
                name=v["name"],        direction=v["direction"],
                action=v["action"],    protocol=v["protocol"],
                port=v["port"],        profile=v["profile"],
                description=v["description"],
            )
            if ok:
                QMessageBox.information(self, "Done", f"Rule '{v['name']}' created.")
                self._log_change(
                    "Added", v["name"],
                    f"{v['action']} {v['direction']} {v['protocol']} port {v['port']}",
                )
                self._run_analysis()
            else:
                QMessageBox.warning(self, "Failed", "Could not create rule.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    # ------------------------------------------------------------------
    # Enable / Disable / Remove
    # ------------------------------------------------------------------

    def _run_rule_action(self, title: str, msg: str, method: str, log_action: str):
        """Shared handler for enable/disable/remove."""
        from core.firewall import FirewallAnalyzer
        name = self._selected_rule_name()
        if not name:
            return
        if QMessageBox.question(self, title, msg.format(name=name),
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        try:
            if getattr(FirewallAnalyzer(), method)(name):
                QMessageBox.information(self, "Done", f"Rule '{name}' {log_action.lower()}.")
                self._log_change(log_action, name)
                self._run_analysis()
            else:
                QMessageBox.warning(self, "Failed", f"Could not {log_action.lower()} rule.")
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _enable_selected(self):
        self._run_rule_action("Confirm Enable",
                              "Enable firewall rule:\n\n  '{name}'",
                              "enable_rule", "Enabled")

    def _disable_selected(self):
        self._run_rule_action("Confirm Disable",
                              "Disable firewall rule:\n\n  '{name}'\n\nThis may affect connectivity.",
                              "disable_rule", "Disabled")

    def _remove_selected(self):
        self._run_rule_action("Confirm Remove",
                              "PERMANENTLY REMOVE:\n\n  '{name}'\n\nThis cannot be undone.",
                              "remove_rule", "Removed")
