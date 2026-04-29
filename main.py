import sys
import os
import sqlite3
import matplotlib.pyplot as plt
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFileDialog,
    QTextEdit, QLineEdit, QTableWidget, QTableWidgetItem, QComboBox
)
from PyQt5.QtGui import QIcon

from core.collector import collect_evidence,collect_logs, simulate_memory_capture, scan_directory
from core.analyzer import analyze_evidence
from core.reporter import generate_report
from core import db

class ForensicVault(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ForensicVault – Digital Forensics Toolkit")
        self.setGeometry(200, 100, 1000, 650)
        #self.setWindowIcon(QIcon("assets/logo.png"))
        self.setWindowIcon(QIcon(resource_path("assets/logo.png")))


        # Keep consistent naming across all modules
        self.current_case = None  

        # Investigation Templates (Predefined Keyword Sets)
        self.TEMPLATES = {
            "Select Template": [],
            "Ransomware Attack": [
                "decrypt", "ransom", "bitcoin", "wallet", "readme", ".locked", ".enc"
            ],
            "Phishing / Malware": [
                "attachment", "credentials", "password", "suspicious_link", "exe", "dll", "login"
            ],
            "Insider Threat": [
                "confidential", "intellectual property", "transfer", "upload", "resign", "server_logs"
            ],
        }

        # Initialize UI
        self.initUI()

    # ==========================
    # MAIN LAYOUT
    # ==========================
    def initUI(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)

        header = QLabel("ForensicVault – Digital Forensics Toolkit")
        header.setStyleSheet("font-size: 18pt; font-weight: bold; color: #00d26a; padding: 10px;")
        header.setAlignment(Qt.AlignCenter)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.cases_tab(), "Cases")
        self.tabs.addTab(self.collect_tab(), "Collect")
        self.tabs.addTab(self.analyze_tab(), "Analyze")
        self.tabs.addTab(self.custody_tab(), "Custody")
        self.tabs.addTab(self.report_tab(), "Report")
        self.tabs.addTab(self.verify_tab(), "Verify")

        main_layout.addWidget(header)
        main_layout.addWidget(self.tabs)
        self.setCentralWidget(central_widget)
        self.statusBar().showMessage("Ready.")

    # ==========================
    # CASES TAB
    # ==========================
    def cases_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Case Management")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #00d26a;")

        self.case_name_input = QLineEdit()
        self.case_name_input.setPlaceholderText("Enter new case name...")

        btn_create = QPushButton("Create New Case")
        btn_open = QPushButton("Open Existing Case")

        self.case_status = QLabel("No case selected.")
        self.case_status.setStyleSheet("color: #aaaaaa;")

        btn_create.clicked.connect(self.create_case)
        btn_open.clicked.connect(self.open_case)

        layout.addWidget(title)
        layout.addWidget(self.case_name_input)
        layout.addWidget(btn_create)
        layout.addWidget(btn_open)
        layout.addWidget(self.case_status)
        widget.setLayout(layout)
        return widget

    def create_case(self):
        """Create a new forensic case in the app's data directory."""
        name = self.case_name_input.text().strip()
        if not name:
            self.case_status.setText("⚠️ Please enter a case name.")
            return

        # Dynamically resolve base data directory relative to the executable
        # base_dir = QFileDialog.getExistingDirectory(self, "Select Base Directory for Case")
        # if not base_dir:
        #     return
        # case_dir = os.path.join(base_dir, name)

        base_dir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "data")
        os.makedirs(base_dir, exist_ok=True)

        case_dir = os.path.join(base_dir, name)
        os.makedirs(case_dir, exist_ok=True)

        # Initialize DB and set case path
        from core import db
        db.init_case_db(case_dir)
        self.current_case = case_dir

        self.case_status.setText(f"✅ Case created: {name}")
        print(f"[INFO] Case created at: {case_dir}")

        # name = self.case_name_input.text().strip()
        # if not name:
        #     self.case_status.setText("⚠️ Please enter a case name.")
        #     return
        # case_dir = f"D:/ForensicVault/data/{name}"
        # os.makedirs(case_dir, exist_ok=True)
        # db.init_case_db(case_dir)
        # self.current_case = case_dir
        # self.case_status.setText(f"✅ Case created: {name}")

    def open_case(self):

        """Open an existing forensic case folder."""
        # Default to data directory relative to the app location
        default_dir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "data")
        os.makedirs(default_dir, exist_ok=True)

        folder = QFileDialog.getExistingDirectory(self, "Select Case Folder", default_dir)
        if folder:
            self.current_case = folder
            self.case_status.setText(f"📂 Opened case: {os.path.basename(folder)}")
            print(f"[INFO] Opened case: {folder}")

        # folder = QFileDialog.getExistingDirectory(self, "Select Case Folder", "D:/ForensicVault/data")
        # if folder:
        #     self.current_case = folder
        #     self.case_status.setText(f"📂 Opened case: {os.path.basename(folder)}")

    # ==========================
    # COLLECT TAB
    # ==========================
    def collect_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # --- Log output box ---
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.append("📁 Ready to collect evidence.\n")

        # --- Button row ---
        btn_row = QWidget()
        row_layout = QHBoxLayout(btn_row)

        # 1️⃣  File/Disk Image collection
        btn_select = QPushButton("Select File(s) / Disk Image")
        btn_select.clicked.connect(self.select_files)
        row_layout.addWidget(btn_select)

        # 2️⃣  Simulated Memory Capture
        btn_mem = QPushButton("Simulate Memory Capture")
        btn_mem.clicked.connect(self.simulate_memory)
        row_layout.addWidget(btn_mem)

        # 3️⃣  System / Cloud Log Collection
        btn_log = QPushButton("Collect System/Cloud Logs")
        btn_log.clicked.connect(self.collect_system_logs)
        row_layout.addWidget(btn_log)

        # 4️⃣  Folder / Drive Scan
        btn_scan = QPushButton("Scan Directory / Drive")
        btn_scan.clicked.connect(self.scan_directory_action)
        row_layout.addWidget(btn_scan)


        # add everything
        layout.addWidget(btn_row)
        layout.addWidget(self.log_box)
        widget.setLayout(layout)
        return widget

    def select_files(self):
        """Handles the selection and logging of generic evidence files."""
        files, _ = QFileDialog.getOpenFileNames(self, "Select Evidence Files")
        if not files:
            return
        # Use 'current_case_path' if it exists, otherwise prompt user (Error handling from original)
        if not hasattr(self, 'current_case') or not self.current_case:
            self.log_box.append("⚠️ Please create or open a case first.\n")
            return

        actor = "Investigator1"
        for file in files:
            self.log_box.append(f"🔹 Processing: {file}")
            try:
                # Assumes collect_evidence is imported and available
                info = collect_evidence(self.current_case, actor, file)
                msg = (f"✅ {info['filename']} hashed.\n"
                    f"Hash: {info['sha256']}\n"
                    f"Block: {info['block_hash']}\n"
                    f"Timestamp: {info['timestamp']}\n")
                self.log_box.append(msg)
            except Exception as e:
                self.log_box.append(f"❌ Error: {str(e)}\n")


    # ===============================================================
    # Support functions called by the new buttons
    # ===============================================================

    def simulate_memory(self):
        """Simulates a memory capture and logs results."""
        
        # 1. Determine the correct attribute name for the case path.
        #    Prefer 'current_case_path' if it exists, otherwise fall back to 'current_case'.
        case_path = getattr(self, "current_case", getattr(self, "current_case", None))
        
        # 2. Single, clean check for an active case.
        if not case_path or not os.path.isdir(case_path):
            self.log_box.append("⚠️ No active case selected. Please create or open a case first.\n")
            return

        actor = "Investigator1"

        try:
            # Assumes simulate_memory_capture is imported and available
            info = simulate_memory_capture(case_path, actor)
            msg = (f"✅ Simulated memory dump captured.\n"
                f"File: {info['filename']}\n"
                f"Hash: {info['sha256']}\n"
                f"Block: {info['block_hash']}\n"
                f"Timestamp: {info['timestamp']}\n")
            self.log_box.append(msg)
        except Exception as e:
            self.log_box.append(f"❌ Memory capture failed: {e}\n")

    def collect_system_logs(self):
        """Collects a selected log file and registers it in the custody chain."""
        
        # 1. Determine the correct attribute name for the case path.
        #    Prefer 'current_case_path' if it exists, otherwise fall back to 'current_case'.
        case_path = getattr(self, "current_case", getattr(self, "current_case", None))
        
        # 2. Single, clean check for an active case.
        if not case_path or not os.path.isdir(case_path):
            self.log_box.append("⚠️ No active case selected. Please create or open a case first.\n")
            return

        actor = "Investigator1"

        log_file, _ = QFileDialog.getOpenFileName(
            self, "Select System/Cloud Log File", filter="Log Files (*.log *.txt *.evtx)"
        )
        if not log_file:
            return

        # for demo assume it's a Windows event or generic cloud log
        system_type = "windows_event"
        self.log_box.append(f"🔹 Collecting Log: {log_file}\n")

        try:
            # Assumes collect_logs is imported and available
            info = collect_logs(case_path, actor, system_type, log_file)
            msg = (f"✅ Log collected.\n"
                f"File: {info['filename']}\n"
                f"Type: {info['type']}\n"
                f"Hash: {info['sha256']}\n"
                f"Block: {info['block_hash']}\n"
                f"Timestamp: {info['timestamp']}\n")
            self.log_box.append(msg)
        except Exception as e:
            self.log_box.append(f"❌ Log collection failed: {e}\n")


    def scan_directory_action(self):
        """Select a directory and perform recursive hashing & custody logging."""
        
        # --- FIX: Robustly check for the active case path attribute ---
        # This checks for 'current_case_path', then 'current_case', falling back to None.
        case_path = getattr(self, "current_case", getattr(self, "current_case", None))
        
        # Check if a valid path was found
        if not case_path or not os.path.isdir(case_path):
            self.log_box.append("⚠️ No active case selected. Please create or open a case first.\n")
            return
        # -----------------------------------------------------------------

        folder = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if not folder:
            return

        actor = "Investigator1"
        self.log_box.append(f"🗂️ Scanning folder: {folder}\n")

        try:
            # Pass the validated case_path
            summary = scan_directory(case_path, actor, folder)
            msg = (f"✅ Scan complete.\n"
                f"Files scanned: {summary['total_files']}\n"
                f"Total size: {summary['total_size']} bytes\n"
                f"Records added to chain: {summary['total_files']}\n")
            self.log_box.append(msg)
        except Exception as e:
            self.log_box.append(f"❌ Folder scan failed: {e}\n")

    # ============================================================
    # ANALYZE TAB UI SETUP
    # ============================================================
    def analyze_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # --- Template selector row ---
        template_row = QWidget()
        hbox = QHBoxLayout(template_row)

        self.template_box = QComboBox()
        # Ensure self.TEMPLATES is defined elsewhere in your class, e.g.,
        # self.TEMPLATES = {"General": ["password", "confidential"], "Financial": ["account", "invoice"]}
        # If self.TEMPLATES is not defined, this line will cause an AttributeError.
        if hasattr(self, 'TEMPLATES'):
            self.template_box.addItems(self.TEMPLATES.keys())
            self.template_box.currentIndexChanged.connect(self.load_template_keywords)
        else:
            self.template_box.addItems(["(TEMPLATES not loaded)"])

        self.keyword_input = QLineEdit()
        self.keyword_input.setPlaceholderText("Enter or edit keywords (comma-separated, e.g., password, confidential)")

        hbox.addWidget(QLabel("Template:"))
        hbox.addWidget(self.template_box)
        hbox.addWidget(self.keyword_input)

        # --- Analyze button and log box ---
        btn_analyze = QPushButton("Select File(s) to Analyze")
        btn_analyze.clicked.connect(self.select_for_analysis)

        self.analyze_log = QTextEdit()
        self.analyze_log.setReadOnly(True)
        self.analyze_log.append("🔍 Ready for analysis.\nSelect a template or enter custom keywords.\n")

        # --- Layout assembly ---
        layout.addWidget(template_row)
        layout.addWidget(btn_analyze)
        layout.addWidget(self.analyze_log)
        widget.setLayout(layout)
        return widget

    # ============================================================
    # ANALYSIS EXECUTION
    # ============================================================
    def select_for_analysis(self):
        """Choose files and run keyword + pattern analysis."""
        # Robust check for active case path (handles current_case_path or current_case)
        case_path = getattr(self, "current_case", getattr(self, "current_case", None))
        
        if not case_path or not os.path.isdir(case_path):
            self.analyze_log.append("⚠️ No active case selected. Please open or create a case first.\n")
            return

        files, _ = QFileDialog.getOpenFileNames(self, "Select Files for Analysis")
        if not files:
            return

        keywords = [kw.strip() for kw in self.keyword_input.text().split(",") if kw.strip()]
        if not keywords:
            self.analyze_log.append("⚠️ Please enter or select keywords before analysis.\n")
            return

        actor = "Investigator1"
        for f in files:
            self.analyze_log.append(f"Analyzing: {f} ...")
            try:
                # Assumes analyze_evidence is imported and available
                result = analyze_evidence(case_path, actor, f, keywords)
                report = (
                    f"✅ {result['file']} analyzed.\n"
                    f"Type: {result['type']}\n"
                    f"Keywords: {len(result['keywords'])} hit(s)\n"
                    f"Carvings: {len(result['carvings'])} hit(s)\n"
                    # Use .get() for the new 'deleted_recovery' field for robustness
                    f"Recovery: {len(result.get('deleted_recovery', []))} fragment(s)\n"
                    f"Block: {result['block_hash']}\n"
                    f"Timestamp: {result['timestamp']}\n"
                )
                self.analyze_log.append(report)
            except Exception as e:
                self.analyze_log.append(f"❌ Error analyzing {f}: {e}\n")

    # ============================================================
    # HELPER FUNCTION
    # ============================================================
    def load_template_keywords(self):
        """Load default keywords for selected investigation template."""
        if not hasattr(self, 'TEMPLATES'):
            self.analyze_log.append("❌ TEMPLATES attribute is missing from the class.\n")
            return
            
        selected = self.template_box.currentText()
        keywords = self.TEMPLATES.get(selected, [])
        self.keyword_input.setText(", ".join(keywords))

    # ==========================
    # REPORT TAB
    # ==========================
    def report_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        self.report_btn = QPushButton("Generate Forensic Report")
        self.report_btn.clicked.connect(self.create_report)

        self.report_log = QTextEdit()
        self.report_log.setReadOnly(True)
        self.report_log.append("🧾 Ready to generate reports.\n")

        layout.addWidget(self.report_btn)
        layout.addWidget(self.report_log)
        widget.setLayout(layout)
        return widget

    def create_report(self):
        if not self.current_case:
            self.report_log.append("⚠️ Please open or create a case first.\n")
            return
        investigator = "Investigator1"
        try:
            out_path, verified, blocks = generate_report(self.current_case, investigator)
            msg = (f"✅ Report generated successfully!\n"
                   f"File: {out_path}\n"
                   f"Chain Status: {'VALID' if verified else 'TAMPERED'} ({blocks} blocks)\n")
            self.report_log.append(msg)
        except Exception as e:
            self.report_log.append(f"❌ Error generating report: {e}\n")

    # ==========================
    # VERIFY TAB (with timeline)
    # ==========================
    def verify_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        label_status = QLabel("Chain verification pending...")
        label_status.setStyleSheet("font-size: 13pt; font-weight: bold; color: #e8e8e8;")

        btn_verify = QPushButton("Run Chain Verification")
        btn_verify.clicked.connect(lambda: self.run_verification(label_status))

        btn_timeline = QPushButton("View Timeline")
        btn_timeline.clicked.connect(self.show_timeline)

        self.icon_indicator = QLabel("")
        self.icon_indicator.setAlignment(Qt.AlignCenter)
        self.icon_indicator.setStyleSheet("font-size: 40pt; margin-top: 20px;")

        layout.addWidget(btn_verify)
        layout.addWidget(btn_timeline)
        layout.addWidget(label_status)
        layout.addWidget(self.icon_indicator)
        widget.setLayout(layout)
        return widget

    def run_verification(self, label):
        if not self.current_case:
            label.setText("⚠️ Please open or create a case first.")
            return
        db_path = os.path.join(self.current_case, "case.db")

        try:
            verified, blocks = db.verify_chain(db_path)
            if verified:
                label.setText(f"✅ Chain Verified: VALID ({blocks} blocks)")
                label.setStyleSheet("font-size: 13pt; font-weight: bold; color: #00ff88;")
                self.icon_indicator.setText("🟢")
            else:
                label.setText(f"❌ Chain Tampered at Block {blocks}")
                label.setStyleSheet("font-size: 13pt; font-weight: bold; color: #ff5555;")
                self.icon_indicator.setText("🔴")
        except Exception as e:
            label.setText(f"⚠️ Error verifying chain: {e}")
            label.setStyleSheet("font-size: 13pt; font-weight: bold; color: #ffcc00;")
            self.icon_indicator.setText("⚠️")

    # ==========================
    # CUSTODY TAB
    # ==========================

    def custody_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()

        btn_refresh = QPushButton("Refresh Custody Chain")
        
        self.custody_table = QTableWidget()
        self.custody_table.setColumnCount(4)
        self.custody_table.setHorizontalHeaderLabels(["Block #", "Timestamp", "Prev Hash", "Block Hash"])
        self.custody_table.horizontalHeader().setStretchLastSection(True)

        btn_refresh.clicked.connect(self.load_custody_chain)

        layout.addWidget(btn_refresh)
        layout.addWidget(self.custody_table)
        widget.setLayout(layout)
        return widget

    def load_custody_chain(self):
        if not self.current_case:
            return
        db_path = os.path.join(self.current_case, "case.db")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        rows = c.execute("SELECT block_index, ts_utc, prev_hash, block_hash FROM chain").fetchall()
        conn.close()

        self.custody_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, val in enumerate(row):
                self.custody_table.setItem(i, j, QTableWidgetItem(str(val)))

    # ==========================
    # TIMELINE VIEW
    # ==========================
    
    def show_timeline(self):
        """Display forensic actions chronologically with color-coded event types."""
        if not self.current_case:
            return

        db_path = os.path.join(self.current_case, "case.db")
        if not os.path.exists(db_path):
            print("⚠️ Case database not found.")
            return

        import sqlite3
        import matplotlib.pyplot as plt
        from datetime import datetime

        # --- Fetch actions from database ---
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        data = c.execute(
            "SELECT ts_utc, action_type, target FROM actions ORDER BY ts_utc ASC"
        ).fetchall()
        conn.close()

        if not data:
            print("⚠️ No actions recorded for timeline.")
            return

        # --- Prepare data ---
        times = [datetime.fromisoformat(t) for t, _, _ in data]
        labels = [f"{a} ({tgt})" for _, a, tgt in data]

        # --- Assign colors based on action type ---
        colors = []
        for _, act, _ in data:
            if "add" in act:
                colors.append("blue")        # Evidence collection
            elif "analyze" in act:
                colors.append("orange")      # Analysis
            elif "collect" in act:
                colors.append("green")       # Log collection
            elif "scan" in act:
                colors.append("purple")      # Directory scan
            else:
                colors.append("gray")        # Other

        # --- Create the timeline plot ---
        plt.figure(figsize=(10, 4))
        plt.scatter(times, range(len(times)), c=colors, s=60, edgecolors='black', zorder=2)
        plt.plot(times, range(len(times)), linestyle='--', color='lightgray', zorder=1)

        # --- Add text labels beside points ---
        for i, label in enumerate(labels):
            plt.text(times[i], i, label, fontsize=8, verticalalignment='bottom', ha='left')

        # --- Format and beautify ---
        plt.title("ForensicVault Action Timeline", fontsize=12, fontweight="bold")
        plt.xlabel("Time (UTC)", fontsize=10)
        plt.ylabel("Action Sequence", fontsize=10)
        plt.xticks(rotation=45, ha='right')
        plt.grid(True, linestyle='--', alpha=0.4)
        plt.tight_layout()
        plt.show()

def resource_path(relative):
    """Return absolute path to resource, works for PyInstaller bundle and dev."""
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ForensicVault()

    # Apply Dark Theme
    try:
        style_path = resource_path("assets/ui/style.qss")
        with open(style_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
        # with open("assets/ui/style.qss", "r") as f:
        #     app.setStyleSheet(f.read())
    except Exception as e:
        print("Theme load failed:", e)

    window.show()
    sys.exit(app.exec_())
