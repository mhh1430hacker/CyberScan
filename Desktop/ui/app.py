from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any

import customtkinter as ctk

from config import DEFAULT_SETTINGS, SAMPLE_DIR, ensure_directories
from core.deep_embedding import HighDimensionalEmbedding
from core.file_analyzer import EICAR_TEST_SIGNATURE
from core.global_intelligence import GlobalIntelligenceEngine
from core.nextgen_engine import NextGenCyberEngine
from core.scanner import scan_target
from monitoring.downloads_monitor import DownloadMonitor
from reports.exporter import export_report
from reports.report_generator import generate_report
from ui.translations import AR_TRANSLATIONS, translate_text

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


class CyberScanApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ensure_directories()
        self.title("CyberScan | Hybrid Threat Detection")
        self.geometry("1320x880")
        self.minsize(1100, 720)
        self.settings = dict(DEFAULT_SETTINGS)
        self.language = "en"
        self.current_tab = "live"
        self.selected_file_path: str | None = None
        self.last_result = None
        self.last_nextgen: dict[str, Any] | None = None
        self.last_osint: dict[str, Any] | None = None
        self.last_vector: tuple[float, ...] | None = None
        self.last_scan_bytes: bytes | None = None
        self.embedding_engine = HighDimensionalEmbedding()
        self._scan_busy = False
        self._stage_states: list[str] = []
        self.ui_queue: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.monitor = DownloadMonitor(self.settings["monitoring_directory"], callback=self.handle_download_event)
        self.configure(fg_color="#090A0F")
        self.build_ui()
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.after(40, self._drain_ui_queue)

    def build_ui(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0E1320")
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(sidebar, text="CYBERSCAN", font=ctk.CTkFont(size=28, weight="bold"), text_color="#00F0FF").pack(pady=(28, 10))
        ctk.CTkLabel(sidebar, text="Hybrid Threat Detection", font=ctk.CTkFont(size=12), text_color="#A0A5B5").pack(pady=(0, 24))

        self.nav_buttons = {
            "live": ctk.CTkButton(sidebar, text="Live Analysis", command=lambda: self.show_tab("live"), height=40),
            "yara": ctk.CTkButton(sidebar, text="YARA & PE", command=lambda: self.show_tab("yara"), height=40),
            "mitre": ctk.CTkButton(sidebar, text="MITRE ATT&CK", command=lambda: self.show_tab("mitre"), height=40),
            "ml": ctk.CTkButton(sidebar, text="Embedding Model", command=lambda: self.show_tab("ml"), height=40),
            "logs": ctk.CTkButton(sidebar, text="Audit Logs", command=lambda: self.show_tab("logs"), height=40),
            "settings": ctk.CTkButton(sidebar, text="Settings", command=lambda: self.show_tab("settings"), height=40),
            "about": ctk.CTkButton(sidebar, text="About", command=lambda: self.show_tab("about"), height=40),
        }
        for btn in self.nav_buttons.values():
            btn.pack(fill="x", padx=16, pady=6)
        self.language_button = ctk.CTkButton(sidebar, text="العربية", command=self.toggle_language, height=34, fg_color="#1B3040", hover_color="#26485A")
        self.language_button.pack(fill="x", padx=16, pady=(18, 8), side="bottom")

        self.content = ctk.CTkFrame(self, fg_color="#090A0F")
        self.content.grid(row=0, column=1, sticky="nsew", padx=22, pady=22)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.tabs = {
            "live": self.build_live_tab(),
            "yara": self.build_yara_tab(),
            "mitre": self.build_mitre_tab(),
            "ml": self.build_ml_tab(),
            "logs": self.build_logs_tab(),
            "settings": self.build_settings_tab(),
            "about": self.build_about_tab(),
        }
        self.show_tab(self.current_tab)
        self.apply_language_to_widgets()

    def show_tab(self, name: str):
        for frame in self.tabs.values():
            frame.grid_forget()
        self.tabs[name].grid(row=0, column=0, sticky="nsew")
        self.current_tab = name

    def tr(self, text: str) -> str:
        return translate_text(text, self.language)

    def apply_language_to_widgets(self) -> None:
        def visit(widget):
            try:
                text = widget.cget("text")
            except (AttributeError, TypeError, ValueError, tk.TclError):
                text = None
            if isinstance(text, str):
                translated = AR_TRANSLATIONS.get(text, text) if self.language == "ar" else text
                if text[:2].isdigit() and "  " in text:
                    prefix, stage = text.split("  ", 1)
                    translated = f"{prefix}  {AR_TRANSLATIONS.get(stage, stage)}" if self.language == "ar" else text
                if translated != text:
                    try:
                        widget.configure(text=translated)
                    except (AttributeError, TypeError, ValueError, tk.TclError):
                        pass
            if isinstance(widget, ctk.CTkEntry):
                try:
                    placeholder = widget.cget("placeholder_text")
                    if self.language == "ar":
                        widget.configure(placeholder_text=AR_TRANSLATIONS.get(placeholder, placeholder), justify="right")
                    else:
                        widget.configure(justify="left")
                except (AttributeError, TypeError, ValueError, tk.TclError):
                    pass
            if isinstance(widget, ctk.CTkTextbox):
                state = widget.cget("state")
                content = widget.get("0.0", "end").rstrip("\n")
                localized = self.tr(content)
                if localized != content:
                    widget.configure(state="normal")
                    widget.delete("0.0", "end")
                    widget.insert("0.0", localized)
                    widget.configure(state=state)
                try:
                    widget._textbox.tag_configure("language_alignment", justify="right" if self.language == "ar" else "left")
                    widget._textbox.tag_add("language_alignment", "1.0", "end")
                except (AttributeError, tk.TclError):
                    pass
            if self.language == "ar" and isinstance(widget, ctk.CTkLabel):
                try:
                    widget.configure(justify="right", anchor="e")
                except tk.TclError:
                    pass
            for child in widget.winfo_children():
                visit(child)

        self.title(self.tr("CyberScan | Hybrid Threat Detection"))
        visit(self)

    def toggle_language(self) -> None:
        target_text = self.target_entry.get()
        selected_path = self.selected_file_path
        audit_log = self.audit_log_box.get("0.0", "end") if hasattr(self, "audit_log_box") else ""
        next_language = "ar" if self.language == "en" else "en"
        for widget in self.winfo_children():
            widget.destroy()
        self.language = next_language
        self.build_ui()
        if target_text:
            self.target_entry.insert(0, target_text)
        self.selected_file_path = selected_path
        if selected_path:
            self.file_label.configure(text=os.path.basename(selected_path))
        if audit_log:
            self.audit_log_box.configure(state="normal")
            self.audit_log_box.delete("0.0", "end")
            self.audit_log_box.insert("0.0", self.tr(audit_log))
            self.audit_log_box.configure(state="disabled")
        if self._scan_busy:
            self.scan_button.configure(state="disabled", text=self.tr("Analyzing..."))
        self.restore_last_scan_view()

    def restore_last_scan_view(self) -> None:
        if not (self.last_result and self.last_nextgen and self.last_osint and self.last_vector is not None and self.last_scan_bytes is not None):
            return
        centroid = self.embedding_engine.compare(self.last_vector)
        prediction = self.embedding_engine.classify(self.last_vector)
        self.update_result_panel(self.last_result, self.last_nextgen, centroid, prediction, self.last_osint, self.last_scan_bytes)
        self.entropy_data = self.last_nextgen["entropy_topography"]
        self.update_entropy_chart()
        self.update_embedding_matrix(self.last_vector, centroid, prediction)
        self.update_intelligence_panel(self.last_osint)
        self.render_mitre_matrix(self.last_result.mitre_techniques)
        self.update_ml_status(self.last_result)
        self.update_yara_pe(self.last_result)

    def build_live_tab(self):
        frame = ctk.CTkScrollableFrame(
            self.content,
            fg_color="#090D16",
            corner_radius=12,
            orientation="vertical",
        )
        frame.grid_columnconfigure((0, 1), weight=1, uniform="dashboard_columns")

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(18, 14))
        ctk.CTkLabel(header, text="CYBERSCAN / LIVE ANALYSIS", font=ctk.CTkFont(size=24, weight="bold"), text_color="#E9F2FF").pack(anchor="w")
        ctk.CTkLabel(header, text="Static evidence · incremental local model · bounded public IOC lookups", font=ctk.CTkFont(size=12), text_color="#8292A8").pack(anchor="w", pady=(4, 0))
        self.verdict_badge = ctk.CTkLabel(header, text="READY · AWAITING TARGET", text_color="#61D6C5", font=ctk.CTkFont(size=12, weight="bold"))
        self.verdict_badge.pack(anchor="e", pady=(0, 4))

        input_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        input_panel.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        input_panel.grid_columnconfigure(0, weight=1)
        self.target_entry = ctk.CTkEntry(input_panel, placeholder_text="Choose a local file or enter text / URL / IOC", height=42, border_color="#41DCC6")
        self.target_entry.grid(row=0, column=0, sticky="ew", padx=16, pady=(15, 10))
        self.target_entry.bind("<KeyRelease>", self._manual_target_changed)
        self.select_file_button = ctk.CTkButton(input_panel, text="Browse file", command=self.select_file, fg_color="#1B3040", hover_color="#26485A", width=110)
        self.select_file_button.grid(row=0, column=1, padx=(0, 8), pady=(15, 10))
        self.scan_button = ctk.CTkButton(input_panel, text="Run analysis", command=self.run_scan, fg_color="#0D8F82", hover_color="#10A99A", width=140)
        self.scan_button.grid(row=0, column=2, padx=(0, 16), pady=(15, 10))
        self.file_label = ctk.CTkLabel(input_panel, text="No file selected", text_color="#8292A8", anchor="w")
        self.file_label.grid(row=1, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 12))

        pipeline = ctk.CTkFrame(frame, fg_color="#101722", corner_radius=10, border_width=1, border_color="#233446")
        pipeline.grid(row=2, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        pipeline.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="pipeline")
        ctk.CTkLabel(pipeline, text="INSPECTION PIPELINE", font=ctk.CTkFont(size=12, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, columnspan=4, sticky="w", padx=14, pady=(12, 8))
        stage_names = (
            "Entropy Topography & Thermodynamic Discontinuity Analysis",
            "Control Flow Graph Disassembly & Obfuscation Extraction",
            "4096-Dimensional Spatial Embedding Projection",
            "Global Async OSINT Intelligence Cross-Referencing",
        )
        self.stage_widgets: list[tuple[ctk.CTkLabel, ctk.CTkProgressBar]] = []
        for index, name in enumerate(stage_names):
            stage = ctk.CTkFrame(pipeline, fg_color="#141F2D", corner_radius=8)
            stage.grid(row=1, column=index, sticky="ew", padx=7, pady=(0, 12))
            title = ctk.CTkLabel(stage, text=f"0{index + 1}  {name}", text_color="#9EADBE", anchor="w", justify="left", wraplength=220, height=52, font=ctk.CTkFont(size=10, weight="bold"))
            title.pack(fill="x", padx=10, pady=(9, 5))
            progress = ctk.CTkProgressBar(stage, height=5, progress_color="#41DCC6")
            progress.set(0)
            progress.pack(fill="x", padx=10, pady=(0, 9))
            self.stage_widgets.append((title, progress))

        metrics = ctk.CTkFrame(frame, fg_color="transparent")
        metrics.grid(row=3, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        metrics.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="metric")
        self.metric_values: dict[str, ctk.CTkLabel] = {}
        metric_specs = (("RISK SCORE", "—", "#FFB454"), ("MEAN ENTROPY", "—", "#41DCC6"), ("CFG COMPLEXITY", "—", "#6FA8FF"), ("VECTOR NORM", "—", "#E27A9A"))
        for index, (title, value, color) in enumerate(metric_specs):
            card = ctk.CTkFrame(metrics, fg_color="#111A27", corner_radius=9, border_width=1, border_color="#233446")
            card.grid(row=0, column=index, sticky="ew", padx=5)
            ctk.CTkLabel(card, text=title, text_color="#8292A8", font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=12, pady=(11, 3))
            value_label = ctk.CTkLabel(card, text=value, text_color=color, font=ctk.CTkFont(size=21, weight="bold"))
            value_label.pack(anchor="w", padx=12, pady=(0, 11))
            self.metric_values[title] = value_label

        vector_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        vector_panel.grid(row=4, column=0, sticky="nsew", padx=(18, 7), pady=(0, 14))
        ctk.CTkLabel(vector_panel, text="4096-D STRUCTURAL SPACE", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").pack(anchor="w", padx=14, pady=(13, 3))
        ctk.CTkLabel(vector_panel, text="64 × 64 signed feature-hash projection", font=ctk.CTkFont(size=11), text_color="#8292A8").pack(anchor="w", padx=14, pady=(0, 8))
        self.vector_canvas = tk.Canvas(vector_panel, width=320, height=240, bg="#0B111A", highlightthickness=0)
        self.vector_canvas.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.embedding_detail = ctk.CTkLabel(vector_panel, text="No labeled centroids loaded · model starts untrained", text_color="#8292A8", justify="left", anchor="w", wraplength=500)
        self.embedding_detail.pack(fill="x", padx=14, pady=(0, 7))
        learning_controls = ctk.CTkFrame(vector_panel, fg_color="transparent")
        learning_controls.pack(fill="x", padx=12, pady=(0, 12))
        learning_values = ["مراجعة", "سليم", "ضار"] if self.language == "ar" else ["review", "benign", "malicious"]
        self.learning_label = ctk.CTkOptionMenu(learning_controls, values=learning_values, width=130, fg_color="#1B3040", button_color="#23645E")
        self.learning_label.set(learning_values[0])
        self.learning_label.pack(side="left", padx=(0, 8))
        self.learn_button = ctk.CTkButton(learning_controls, text="Add human label", command=self.learn_current_sample, fg_color="#1B3040", hover_color="#26485A", width=140, state="disabled")
        self.learn_button.pack(side="left")
        ctk.CTkLabel(vector_panel, text="Labels are user-supplied; neighbor agreement is not calibrated confidence.", text_color="#73849A", font=ctk.CTkFont(size=10)).pack(anchor="w", padx=14, pady=(0, 10))

        entropy_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        entropy_panel.grid(row=4, column=1, sticky="nsew", padx=(7, 18), pady=(0, 14))
        ctk.CTkLabel(entropy_panel, text="ENTROPY TOPOGRAPHY", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").pack(anchor="w", padx=14, pady=(13, 3))
        self.entropy_detail = ctk.CTkLabel(entropy_panel, text="Windowed Shannon entropy · anomaly spans shaded", text_color="#8292A8", font=ctk.CTkFont(size=11), anchor="w")
        self.entropy_detail.pack(anchor="w", padx=14, pady=(0, 7))
        self.entropy_canvas = tk.Canvas(entropy_panel, width=520, height=240, bg="#0B111A", highlightthickness=0)
        self.vector_canvas.bind("<Configure>", lambda _event: self._redraw_embedding_matrix())
        self.entropy_canvas.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.entropy_canvas.bind("<Configure>", lambda _event: self.draw_entropy_chart())
        self.entropy_canvas.bind("<Motion>", self.inspect_entropy_point)
        self.entropy_data: dict[str, Any] | None = None

        intel_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        intel_panel.grid(row=5, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        intel_panel.grid_columnconfigure((0, 1, 2), weight=1, uniform="feeds")
        ctk.CTkLabel(intel_panel, text="GLOBAL THREAT INTELLIGENCE RADAR", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(13, 3))
        self.osint_summary = ctk.CTkLabel(intel_panel, text="Lookup starts after analysis · a feed miss is not proof of safety", text_color="#8292A8", anchor="w")
        self.osint_summary.grid(row=1, column=0, columnspan=3, sticky="ew", padx=14, pady=(0, 8))
        self.feed_status_labels: dict[str, ctk.CTkLabel] = {}
        self.feed_detail_labels: dict[str, ctk.CTkLabel] = {}
        for index, feed in enumerate(("ThreatFox", "URLhaus", "AlienVault OTX")):
            card = ctk.CTkFrame(intel_panel, fg_color="#141F2D", corner_radius=8)
            card.grid(row=2, column=index, sticky="ew", padx=7, pady=(0, 12))
            ctk.CTkLabel(card, text=feed, text_color="#DCE8F6", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=11, pady=(10, 3))
            status = ctk.CTkLabel(card, text="NOT QUERIED", text_color="#8292A8", font=ctk.CTkFont(size=10, weight="bold"))
            status.pack(anchor="w", padx=11)
            detail = ctk.CTkLabel(card, text="Waiting for indicator", text_color="#8292A8", wraplength=260, justify="left", anchor="w")
            detail.pack(fill="x", padx=11, pady=(3, 10))
            self.feed_status_labels[feed] = status
            self.feed_detail_labels[feed] = detail

        story_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        story_panel.grid(row=6, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        story_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(story_panel, text="FORENSIC STORYBOARD", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, sticky="w", padx=14, pady=(13, 8))
        self.story_lines_frame = ctk.CTkFrame(story_panel, fg_color="transparent")
        self.story_lines_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.story_lines_frame.grid_columnconfigure(0, weight=1)
        self.story_lines: list[ctk.CTkLabel] = []
        self._render_storyboard(["Awaiting target evidence. Narrative will be generated from observed metrics."])

        result_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        result_panel.grid(row=7, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 18))
        result_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(result_panel, text="EVIDENCE & VERDICT", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, sticky="w", padx=14, pady=(13, 8))
        self.result_text = ctk.CTkTextbox(result_panel, height=190, fg_color="#0B111A", text_color="#DCE8F6", font=ctk.CTkFont(family="Consolas", size=11), wrap="word")
        self.result_text.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.result_text.insert("0.0", "No analysis has been performed.")
        self.result_text.configure(state="disabled")
        ctk.CTkButton(result_panel, text="Export report", command=self.export_txt_report, fg_color="#1B3040", hover_color="#26485A", width=130).grid(row=2, column=0, sticky="e", padx=12, pady=(0, 12))
        return frame

    def build_yara_tab(self):
        frame = ctk.CTkFrame(self.content, fg_color="#0B1020", corner_radius=18)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="YARA & PE Inspector", font=ctk.CTkFont(size=24, weight="bold"), text_color="#DDE7FF").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 10))
        self.yara_box = ctk.CTkTextbox(frame, height=240, fg_color="#121B2C", text_color="#DDE7FF", font=ctk.CTkFont(family="Consolas", size=11))
        self.yara_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 12))
        self.yara_box.insert("0.0", "YARA status: no file inspected yet.\n")
        self.yara_box.configure(state="disabled")
        self.pe_box = ctk.CTkTextbox(frame, height=240, fg_color="#121B2C", text_color="#DDE7FF", font=ctk.CTkFont(family="Consolas", size=11))
        self.pe_box.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.pe_box.insert("0.0", "PE status: no file inspected yet.\n")
        self.pe_box.configure(state="disabled")
        return frame

    def build_mitre_tab(self):
        frame = ctk.CTkFrame(self.content, fg_color="#0B1020", corner_radius=18)
        frame.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(frame, text="MITRE ATT&CK Matrix", font=ctk.CTkFont(size=24, weight="bold"), text_color="#DDE7FF")
        title.grid(row=0, column=0, sticky="w", padx=18, pady=(18, 12))
        self.mitre_matrix = ctk.CTkFrame(frame, fg_color="#121B2C", corner_radius=16)
        self.mitre_matrix.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.mitre_matrix.grid_columnconfigure((0, 1, 2), weight=1)
        self.mitre_matrix.grid_rowconfigure((0, 1), weight=1)
        self.render_mitre_matrix([])
        return frame

    def build_ml_tab(self):
        frame = ctk.CTkFrame(self.content, fg_color="#0B1020", corner_radius=18)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="ML Model Status", font=ctk.CTkFont(size=24, weight="bold"), text_color="#DDE7FF").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 12))
        self.ml_status_box = ctk.CTkTextbox(frame, height=420, fg_color="#121B2C", text_color="#DDE7FF", font=ctk.CTkFont(family="Consolas", size=11))
        self.ml_status_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.ml_status_box.insert("0.0", "4096-D embedding model starts untrained.\n\nAdd only human-reviewed labels. Neighbor agreement is not calibrated confidence, and no accuracy or zero-day claim is made.\n")
        self.ml_status_box.configure(state="disabled")
        return frame

    def build_settings_tab(self):
        frame = ctk.CTkFrame(self.content, fg_color="#0B1020", corner_radius=12)
        frame.grid_columnconfigure(0, weight=1)
        card = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        card.grid(row=0, column=0, sticky="new", padx=18, pady=18)
        ctk.CTkLabel(card, text="Analysis Settings", font=ctk.CTkFont(size=20, weight="bold"), text_color="#DCE8F6").pack(anchor="w", padx=18, pady=(18, 12))
        self.settings_vars = {
            key: tk.BooleanVar(value=bool(self.settings.get(key, False)))
            for key in ("entropy_analysis", "heuristic_rules", "ml_analysis", "osint_lookup", "monitoring_enabled")
        }
        for key, label in (
            ("entropy_analysis", "Entropy analysis"),
            ("heuristic_rules", "Heuristic rules"),
            ("ml_analysis", "Existing ML analysis"),
            ("osint_lookup", "Online IOC lookup (sends hash/URL to public feeds)"),
            ("monitoring_enabled", "Downloads monitoring"),
        ):
            ctk.CTkSwitch(card, text=label, variable=self.settings_vars[key], progress_color="#41DCC6").pack(anchor="w", padx=18, pady=7)
        ctk.CTkButton(card, text="Apply settings", command=self.apply_settings, fg_color="#0D8F82", hover_color="#10A99A").pack(anchor="w", padx=18, pady=(16, 10))
        ctk.CTkLabel(card, text="Online lookup is off by default. When enabled it needs network access and API keys from the environment: ABUSECH_AUTH_KEY (or THREATFOX_API_KEY / URLHAUS_API_KEY) and OTX_API_KEY.", text_color="#8292A8", wraplength=650, justify="left").pack(anchor="w", padx=18, pady=(0, 18))
        return frame

    def build_about_tab(self):
        frame = ctk.CTkScrollableFrame(self.content, fg_color="#090D16", corner_radius=12, orientation="vertical")
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="About CyberScan", font=ctk.CTkFont(size=26, weight="bold"), text_color="#E9F2FF").grid(row=0, column=0, sticky="w", padx=22, pady=(22, 4))
        ctk.CTkLabel(frame, text="Project theory · defensive static analysis", font=ctk.CTkFont(size=13), text_color="#41DCC6").grid(row=1, column=0, sticky="w", padx=22, pady=(0, 18))

        sections = (
            ("Project purpose", "CyberScan is a defensive static-analysis research prototype. It combines file structure and byte statistics, heuristic rules, optional YARA/PE inspection, an explainable risk view, a 4096-dimensional structural embedding, and bounded public IOC lookups. It analyzes evidence without executing the target."),
            ("How the analysis works", "1. Extract byte-level and structural features, including entropy windows and (for binary input) x86 control-flow indicators.\n\n2. Build a deterministic normalized vector and compare it only with centroids learned from user-provided labels.\n\n3. Query public intelligence feeds for the target hash or supplied URL and show each source's response state.\n\n4. Present measured evidence, limitations, and a chronological forensic summary for analyst review."),
            ("Research limitations", "This project is not a replacement for endpoint protection. It does not claim zero-day discovery, complete malware coverage, calibrated model confidence, or that a feed miss proves a file is safe. Internet lookups depend on provider availability and credentials; model labels require human review."),
        )
        for row, (heading, body) in enumerate(sections, start=2):
            panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
            panel.grid(row=row, column=0, sticky="ew", padx=22, pady=(0, 14))
            panel.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(panel, text=heading, font=ctk.CTkFont(size=16, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, sticky="w", padx=18, pady=(16, 8))
            ctk.CTkLabel(panel, text=body, font=ctk.CTkFont(size=12), text_color="#B7C6D8", justify="left", anchor="w", wraplength=860).grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 16))

        credits = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        credits.grid(row=5, column=0, sticky="ew", padx=22, pady=(0, 22))
        ctk.CTkLabel(credits, text="Developed by", font=ctk.CTkFont(size=12), text_color="#8292A8").pack(anchor="w", padx=18, pady=(13, 2))
        ctk.CTkLabel(credits, text="m6no5 and Ainex", font=ctk.CTkFont(size=19, weight="bold"), text_color="#41DCC6").pack(anchor="w", padx=18, pady=(0, 14))
        return frame

    def build_logs_tab(self):
        frame = ctk.CTkFrame(self.content, fg_color="#0B1020", corner_radius=18)
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="Audit Logs", font=ctk.CTkFont(size=24, weight="bold"), text_color="#DDE7FF").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 12))
        self.audit_log_box = ctk.CTkTextbox(frame, height=500, fg_color="#121B2C", text_color="#DDE7FF", font=ctk.CTkFont(family="Consolas", size=11))
        self.audit_log_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.audit_log_box.insert("0.0", "[System] CyberScan initialized. Static analysis active / ML unavailable.\n")
        self.audit_log_box.configure(state="disabled")
        return frame

    def render_mitre_matrix(self, techniques):
        for widget in self.mitre_matrix.winfo_children():
            widget.destroy()
        if not techniques:
            placeholder = ctk.CTkLabel(self.mitre_matrix, text="No MITRE mappings detected yet. Run a scan to populate this matrix.", text_color="#A0A5B5")
            placeholder.grid(row=0, column=0, sticky="w", padx=18, pady=18)
            return
        for index, technique in enumerate(techniques[:6]):
            row = index // 3
            col = index % 3
            badge = ctk.CTkButton(
                self.mitre_matrix,
                text=f"{technique.get('id', 'N/A')}\n{technique.get('name', 'Technique')}",
                height=52,
                fg_color="#131B2B",
                hover_color="#1C2940",
                text_color="#41DCC6",
            )
            badge.grid(row=row, column=col, padx=14, pady=12, sticky="nsew")

    def select_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self.selected_file_path = path
        self.file_label.configure(text=os.path.basename(path))
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, path)

    def _manual_target_changed(self, _event=None) -> None:
        if self.selected_file_path and self.target_entry.get().strip() != self.selected_file_path:
            self.selected_file_path = None
            self.file_label.configure(text="Manual target")

    def run_scan(self):
        if self._scan_busy:
            return
        target = self.target_entry.get().strip()
        if not target and not self.selected_file_path:
            messagebox.showwarning(self.tr("Input required"), self.tr("Please provide a file path, URL, or suspicious pattern to scan."))
            return
        candidate = self.selected_file_path or target
        if not self.selected_file_path and target and not target.startswith(("http://", "https://")):
            try:
                if Path(target).is_file():
                    candidate = str(Path(target).resolve())
            except OSError:
                pass
        self._scan_busy = True
        self.scan_button.configure(state="disabled", text=self.tr("Analyzing..."))
        self.learn_button.configure(state="disabled")
        for stage_index in range(len(self.stage_widgets)):
            self._set_stage(stage_index, "waiting")
        self._set_stage(0, "running")
        self._append_log("Analysis started; processing remains static and non-executing.")
        threading.Thread(target=self._scan_worker, args=(candidate,), daemon=True, name="CyberScanAnalysis").start()

    @staticmethod
    def _looks_like_text(data: bytes) -> bool:
        return NextGenCyberEngine.looks_like_text(data)

    @staticmethod
    def _text_cfg_summary() -> dict[str, Any]:
        return {
            "basic_block_count": 0,
            "cyclomatic_complexity": 0,
            "graph_density": 0.0,
            "detected_patterns": [],
            "opcode_frequency": {name: 0.0 for name in ("XOR", "MOV", "PUSH", "CALL", "JMP", "NOP")},
            "edge_count": 0,
            "adjacency": {},
            "architecture": "text-content-skipped",
            "disassembly_available": False,
            "instruction_count": 0,
            "back_edge_count": 0,
            "back_edge_density": 0.0,
            "raw_byte_frequency": {},
        }

    @staticmethod
    def _score_artifacts(entropy: dict[str, Any], cfg: dict[str, Any]) -> float:
        entropy_score = (entropy["mean_entropy"] / 8.0) * 20.0 + (entropy["peak_entropy"] / 8.0) * 15.0
        anomaly_score = min(len(entropy["anomalies"]) / 3.0, 1.0) * 20.0
        gradient_score = min(math.sqrt(entropy["gradient_variance"]) / 4.0, 1.0) * 10.0
        complexity_score = min(cfg["cyclomatic_complexity"] / 20.0, 1.0) * 15.0
        pattern_score = min(len(cfg["detected_patterns"]) / 3.0, 1.0) * 20.0
        return round(max(0.0, min(100.0, entropy_score + anomaly_score + gradient_score + complexity_score + pattern_score)), 2)

    def _scan_worker(self, candidate: str) -> None:
        try:
            is_url = candidate.startswith(("http://", "https://"))
            path = Path(candidate) if not is_url else None
            is_file = bool(path and path.is_file())
            if is_file:
                file_size = path.stat().st_size
                maximum = int(self.settings.get("maximum_file_size", 50 * 1024 * 1024))
                if file_size > maximum:
                    raise ValueError(f"File size {file_size} exceeds the configured limit of {maximum} bytes")
                # Only the leading window is used for entropy/embedding (pure-Python, so unbounded
                # 50 MB reads made the UI worker very slow); the SHA-256 still covers the whole file.
                with path.open("rb") as handle:
                    raw_data = handle.read(int(self.settings.get("max_analysis_bytes", 1_000_000)))
                filename = path.name
                scan_result = scan_target(str(path), is_file=True, settings=self.settings)
            elif is_url:
                raw_data = candidate.encode("utf-8")
                filename = "url-indicator.txt"
                scan_result = scan_target(candidate, is_file=False, settings=self.settings)
            else:
                raw_data = candidate.encode("utf-8", errors="replace")
                filename = "text-indicator.txt"
                scan_result = scan_target(candidate, is_file=False, settings=self.settings)

            self._set_stage(0, "complete")
            self._append_log(f"Entropy stage: analyzing {len(raw_data):,} bytes in overlapping windows.")
            entropy = NextGenCyberEngine.analyze_entropy_topography(raw_data)

            self._set_stage(1, "running")
            text_input = self._looks_like_text(raw_data)
            if text_input:
                cfg = self._text_cfg_summary()
                self._append_log("CFG stage: text-like input detected; x86 disassembly skipped.")
            else:
                cfg = NextGenCyberEngine.extract_cfg_topology(raw_data)
                self._append_log(f"CFG stage: {cfg.get('instruction_count', 0)} instructions decoded; {cfg.get('basic_block_count', 0)} blocks measured.")
            score = self._score_artifacts(entropy, cfg)
            nextgen = {
                "status": "SUCCESS",
                "filename": filename,
                "file_size": len(raw_data),
                "entropy_topography": entropy,
                "cfg_topology": cfg,
                "forensic_storyboard": NextGenCyberEngine.generate_forensic_storyline(filename, len(raw_data), entropy, cfg, score),
                "composite_innovation_score": score,
                "input_profile": "text-content" if text_input else "binary-content",
            }

            self._set_stage(1, "complete")
            self._set_stage(2, "running")
            vector = self.embedding_engine.embed_bytes(raw_data, entropy_topography=entropy, cfg_topology=cfg)
            centroid = self.embedding_engine.compare(vector)
            prediction = self.embedding_engine.classify(vector)
            self._append_log(f"Embedding stage: projected {len(vector):,} normalized coordinates; model state is {self.embedding_engine.summary()['trained'] and 'trained from user labels' or 'untrained'}.")
            self._set_stage(2, "complete")

            self._set_stage(3, "running")
            if not self.settings.get("osint_lookup", False):
                intelligence = self._skipped_intelligence("Online lookups are switched off in Settings.")
                self._append_log("OSINT stage skipped: online lookup is disabled (nothing was sent to third-party feeds).")
            else:
                if is_url:
                    indicator = candidate
                elif is_file:
                    indicator = scan_result.sha256 or hashlib.sha256(raw_data).hexdigest()
                elif GlobalIntelligenceEngine._infer_indicator_type(candidate):
                    indicator = candidate  # the user typed a hash / IP / domain IOC
                else:
                    indicator = ""  # free text: hashing arbitrary text for a feed lookup is meaningless
                if indicator:
                    intelligence = asyncio.run(GlobalIntelligenceEngine().query_indicator(indicator))
                else:
                    intelligence = self._skipped_intelligence("Free text is not an indicator that feeds can look up.")
            self._append_log(f"OSINT stage: {intelligence['status']} after {intelligence['elapsed_ms']:.1f} ms for {intelligence['indicator_type'] or 'unsupported indicator'}.")
            self._set_stage(3, "complete")
            self.ui_queue.put(("complete", scan_result, nextgen, vector, centroid, prediction, intelligence, raw_data))
        except Exception as exc:
            self.ui_queue.put(("failed", f"{type(exc).__name__}: {exc}"))

    @staticmethod
    def _skipped_intelligence(reason: str) -> dict[str, Any]:
        feeds = {
            name: {"status": "lookup_disabled", "error": reason, "records": [], "match_count": 0}
            for name in ("ThreatFox", "URLhaus", "AlienVault OTX")
        }
        return {
            "status": "lookup_disabled",
            "indicator": "",
            "indicator_type": None,
            "elapsed_ms": 0.0,
            "latency_budget_ms": 0.0,
            "feeds": feeds,
            "matches": [],
            "attributions": [],
            "classifications": [],
            "interpretation": reason,
        }

    def _set_stage(self, index: int, state: str) -> None:
        self.ui_queue.put(("stage", index, state))

    def _apply_stage(self, index: int, state: str) -> None:
        if index >= len(self.stage_widgets):
            return
        title, progress = self.stage_widgets[index]
        label = title.cget("text").split("  ", 1)[-1]
        colors = {"waiting": "#8292A8", "running": "#41DCC6", "complete": "#76D69A", "failed": "#FF667D"}
        title.configure(text=f"{index + 1:02d}  {label}", text_color=colors.get(state, "#8292A8"))
        if state == "running":
            progress.start()
        else:
            progress.stop()
            progress.set(1.0 if state == "complete" else 0.0)
        progress.configure(progress_color=colors.get(state, "#41DCC6"))

    def _append_log(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self.ui_queue.put(("log", f"[{timestamp}] {message}"))

    def _drain_ui_queue(self) -> None:
        try:
            event = self.ui_queue.get_nowait()
        except queue.Empty:
            event = None
        if event is not None:
            try:
                event_type = event[0]
                if event_type == "stage":
                    self._apply_stage(event[1], event[2])
                elif event_type == "log":
                    self.write_log(event[1])
                elif event_type == "failed":
                    self._scan_failed(event[1])
                elif event_type == "complete":
                    self._complete_scan(*event[1:])
            except Exception as exc:
                self._scan_failed(f"UI update failed: {type(exc).__name__}: {exc}")
        self.after(40, self._drain_ui_queue)

    def _redraw_embedding_matrix(self) -> None:
        if self.last_vector is not None:
            self.update_embedding_matrix(
                self.last_vector,
                self.embedding_engine.compare(self.last_vector),
                self.embedding_engine.classify(self.last_vector),
            )

    def _scan_failed(self, message: str) -> None:
        self._scan_busy = False
        self.scan_button.configure(state="normal", text="Run analysis")
        self.learn_button.configure(state="normal" if self.last_vector is not None else "disabled")
        for index in range(len(self.stage_widgets)):
            self._apply_stage(index, "failed")
        self.verdict_badge.configure(text="ANALYSIS ERROR", text_color="#FF667D")
        self._append_log(f"Analysis failed: {message}")
        self.result_text.configure(state="normal")
        self.result_text.delete("0.0", "end")
        self.result_text.insert("0.0", f"{self.tr('Analysis did not complete.')}\n\n{self.tr(message)}")
        self.result_text.configure(state="disabled")

    def _complete_scan(self, result, nextgen, vector, centroid, prediction, intelligence, raw_data: bytes) -> None:
        self._scan_busy = False
        self.scan_button.configure(state="normal", text="Run analysis")
        self.last_result = result
        self.last_nextgen = nextgen
        self.last_vector = vector
        self.last_osint = intelligence
        self.last_scan_bytes = raw_data
        self.entropy_data = nextgen["entropy_topography"]
        self.learn_button.configure(state="normal")
        self.update_result_panel(result, nextgen, centroid, prediction, intelligence, raw_data)
        self.update_entropy_chart()
        self.update_embedding_matrix(vector, centroid, prediction)
        self.update_intelligence_panel(intelligence)
        self.render_mitre_matrix(result.mitre_techniques)
        self.update_ml_status(result)
        self.update_yara_pe(result)

    def update_result_panel(self, result, nextgen, centroid, prediction, intelligence, raw_data: bytes):
        self.result_text.configure(state="normal")
        self.result_text.delete("0.0", "end")
        evidence_items = [
            f"[{item.severity.upper()}] {item.evidence}: {item.explanation}"
            for item in result.evidence
        ]
        for match in result.yara_matches:
            evidence_items.append(f"[HIGH] YARA match: {match.get('rule_name', 'unnamed rule')}")
        for anomaly in nextgen["entropy_topography"].get("anomalies", []):
            evidence_items.append(
                f"[{anomaly['severity'].upper()}] Entropy discontinuity at "
                f"0x{anomaly['offset_start']:X}-0x{anomaly['offset_end']:X} (ΔH {anomaly['delta']:+.3f})"
            )
        for pattern in nextgen["cfg_topology"].get("detected_patterns", []):
            evidence_items.append(f"[MEDIUM] Structural indicator: {pattern}")
        eicar_match = EICAR_TEST_SIGNATURE in raw_data
        if eicar_match:
            evidence_items.append("[TEST SIGNATURE] EICAR standard anti-malware test marker detected; this marker is benign and is not a virus.")
        if intelligence.get("status") == "matched":
            evidence_items.append(f"[HIGH] External threat-intelligence match for {intelligence.get('indicator', '')}")
        evidence = "\n".join(evidence_items) if evidence_items else "No direct static evidence recorded."
        unique_evidence = list(dict.fromkeys(evidence_items))
        evidence = "\n".join(self.tr(item) for item in unique_evidence) if unique_evidence else self.tr("No direct static evidence recorded.")
        finding_contributions = sum(max(0, int(item.contribution)) for item in result.evidence)
        if result.yara_matches or intelligence.get("status") == "matched":
            finding_contributions = max(finding_contributions, 70)
        if eicar_match:
            finding_contributions = max(finding_contributions, 25)
        ui_risk = max(float(result.combined_score), float(nextgen["composite_innovation_score"]), min(100.0, float(finding_contributions)))
        if intelligence.get("status") == "matched" or ui_risk >= 70:
            verdict = "HIGH RISK"
            verdict_color = "#FF667D"
        elif eicar_match:
            verdict = "TEST SIGNATURE"
            verdict_color = "#FFB454"
        elif ui_risk >= 25 or evidence_items:
            verdict = "SUSPICIOUS"
            verdict_color = "#FFB454"
        elif ui_risk > 0:
            verdict = "REVIEW"
            verdict_color = "#6FA8FF"
        else:
            verdict = "NO INDICATORS OBSERVED"
            verdict_color = "#61D6C5"
        ml_value = self.tr("not available") if result.ml_anomaly_score is None else f"{result.ml_anomaly_score:.2f}"
        centroid_cosine = centroid.get("cosine_similarity")
        centroid_distance = centroid.get("euclidean_distance")
        nearest_label = centroid.get("nearest_label")
        osint_status = intelligence.get("status", "unavailable")
        osint_status = self.tr(osint_status) if self.language == "ar" else osint_status.replace("_", " ")
        osint_line = f"{self.tr('OSINT: ')}{osint_status} ({intelligence.get('elapsed_ms', 0):.1f} {self.tr('ms')})"
        if intelligence.get("attributions"):
            osint_line += self.tr(" | reported attribution: ") + ", ".join(intelligence["attributions"])
        if intelligence.get("classifications"):
            osint_line += self.tr(" | feed labels: ") + ", ".join(intelligence["classifications"])
        embedding_line = self.tr("Embedding model: untrained; no centroid match claimed.")
        if centroid_cosine is not None:
            embedding_line = f"{self.tr('Nearest labeled centroid: ')}{nearest_label};{self.tr('; cosine ')}{centroid_cosine:.4f};{self.tr('; Euclidean distance ')}{centroid_distance:.4f}."
        if prediction.get("status") in {"classified", "abstained"}:
            embedding_line += f"{self.tr(' k-NN status: ')}{self.tr(prediction['status'])};{self.tr('; neighbor agreement ')}{prediction['confidence']:.3f}{self.tr(' (uncalibrated).')}"
        profile = nextgen.get("input_profile", "binary-content")
        profile_display = self.tr(profile)
        mitre_text = "\n".join(
            f"- {item.get('id', 'N/A')}: {self.tr(item.get('name', 'Unknown'))}"
            for item in (result.mitre_techniques or [])
        ) or self.tr("No mapped techniques")
        integrity_text = ""
        if result.integrity_report:
            integrity_text = (
                f"{self.tr('Integrity checks:\n')}"
                + "\n".join(
                    f"- [{check['status'].upper()}] {check['name']}: {check['detail']}"
                    for check in result.integrity_report["checks"]
                )
                + "\n"
            )
            if result.integrity_report["limitations"]:
                integrity_text += (
                    f"{self.tr('Integrity limitations: ')}"
                    + "; ".join(result.integrity_report["limitations"])
                    + "\n"
                )
        verdict_display = self.tr(verdict)
        text = (
            f"{self.tr('CYBERSCAN ANALYSIS / ')}{verdict_display}\n\n"
            f"{self.tr('Target: ')}{result.target}\n"
            f"{self.tr('Input profile: ')}{profile_display}\n"
            f"{self.tr('Existing scanner classification: ')}{self.tr(result.classification)}\n"
            f"{self.tr('Display risk index: ')}{ui_risk:.2f}/100{self.tr(' (max of existing score, static structural score, and evidence contributions; not a probability)')}\n"
            f"{self.tr('Existing heuristic score: ')}{result.heuristic_score}/100\n"
            f"{self.tr('ML Anomaly: ')}{ml_value}\n"
            f"{self.tr('NextGen structural score: ')}{nextgen['composite_innovation_score']:.2f}/100\n"
            f"{self.tr('SHA-256: ')}{result.sha256 or hashlib.sha256(raw_data).hexdigest()}\n"
            f"{self.tr('File integrity verification: ')}"
            f"{self.tr(result.integrity_report['status']) if result.integrity_report else self.tr('not applicable')}\n"
            f"{self.tr('Detected format: ')}{result.integrity_report['format'] if result.integrity_report else self.tr('not applicable')}\n"
            f"{osint_line}\n"
            f"{embedding_line}\n\n"
            f"{self.tr('Observed evidence:\n')}{evidence}\n\n"
            f"{self.tr('EICAR marker: ')}{self.tr('matched (benign test string)' if eicar_match else 'not present')}\n"
            f"{self.tr('MITRE ATT&CK:\n')}{mitre_text}\n\n"
            f"{self.tr('Model status: ')}{self.tr(result.model_status)}\n"
            f"{self.tr('Limitations: ')}{self.tr(result.limitations)}\n"
            f"{integrity_text}"
            f"{self.tr('Interpretation: static indicators and public feed results are evidence for review, not proof of malware.')}\n"
        )
        self.result_text.insert("0.0", text)
        self.result_text.configure(state="disabled")
        self.verdict_badge.configure(text=verdict_display, text_color=verdict_color)
        self.metric_values["RISK SCORE"].configure(text=f"{ui_risk:.1f}/100", text_color=verdict_color)
        self.metric_values["MEAN ENTROPY"].configure(text=f"{nextgen['entropy_topography']['mean_entropy']:.2f}/8")
        self.metric_values["CFG COMPLEXITY"].configure(text=self.tr("TEXT") if profile == "text-content" else str(nextgen["cfg_topology"]["cyclomatic_complexity"]))
        vector_norm = math.sqrt(math.fsum(value * value for value in self.last_vector or ()))
        self.metric_values["VECTOR NORM"].configure(text=f"{vector_norm:.3f}")
        self._render_storyboard(nextgen["forensic_storyboard"], verdict)

    def update_entropy_chart(self) -> None:
        canvas = self.entropy_canvas
        canvas.delete("all")
        data = self.entropy_data or {}
        values = data.get("trajectory", [])
        offsets = data.get("window_offsets", [])
        if not values:
            canvas.create_text(20, 25, text=self.tr("No entropy windows"), fill="#8292A8", anchor="nw")
            return
        width = max(100, canvas.winfo_width())
        height = max(100, canvas.winfo_height())
        left, right, top, bottom = 42, width - 16, 16, height - 30
        canvas.create_line(left, bottom, right, bottom, fill="#354458")
        canvas.create_line(left, top, left, bottom, fill="#354458")
        canvas.create_text(left - 8, top, text="8", fill="#8292A8", anchor="e")
        canvas.create_text(left - 8, bottom, text="0", fill="#8292A8", anchor="e")
        file_size = max(1, self.last_nextgen.get("file_size", len(values)) if self.last_nextgen else len(values))
        for anomaly in data.get("anomalies", []):
            x1 = left + (right - left) * anomaly["offset_start"] / file_size
            x2 = left + (right - left) * anomaly["offset_end"] / file_size
            canvas.create_rectangle(x1, top, x2, bottom, fill="#6F3441", stipple="gray25", outline="")
        points: list[float] = []
        for index, value in enumerate(values):
            x = left if len(values) == 1 else left + (right - left) * index / (len(values) - 1)
            y = bottom - (bottom - top) * max(0.0, min(8.0, float(value))) / 8.0
            points.extend((x, y))
        if len(points) >= 4:
            canvas.create_line(*points, fill="#41DCC6", width=2, smooth=True)
        else:
            canvas.create_oval(points[0] - 3, points[1] - 3, points[0] + 3, points[1] + 3, fill="#41DCC6", outline="")
        for threshold in (3.5, 7.2):
            y = bottom - (bottom - top) * threshold / 8.0
            canvas.create_line(left, y, right, y, fill="#536579", dash=(3, 4))

    def draw_entropy_chart(self) -> None:
        if self.entropy_data:
            self.update_entropy_chart()

    def inspect_entropy_point(self, event) -> None:
        values = (self.entropy_data or {}).get("trajectory", [])
        if not values:
            return
        left, right = 42, max(43, self.entropy_canvas.winfo_width() - 16)
        ratio = max(0.0, min(1.0, (event.x - left) / (right - left)))
        index = round(ratio * max(0, len(values) - 1))
        offset = (self.entropy_data or {}).get("window_offsets", [0] * len(values))[index]
        if self.language == "ar":
            detail = f"النافذة {index + 1}/{len(values)} · الإزاحة 0x{offset:X} · إنتروبيا Shannon {values[index]:.4f} بت/بايت"
        else:
            detail = f"Window {index + 1}/{len(values)} · offset 0x{offset:X} · Shannon entropy {values[index]:.4f} bits/byte"
        self.entropy_detail.configure(text=detail)

    @staticmethod
    def _vector_color(value: float, scale: float) -> str:
        strength = min(1.0, abs(value) / scale) if scale else 0.0
        if value >= 0:
            red, green, blue = 12, int(40 + 170 * strength), int(48 + 155 * strength)
        else:
            red, green, blue = int(45 + 190 * strength), int(36 + 50 * strength), int(40 + 45 * strength)
        return f"#{red:02x}{green:02x}{blue:02x}"

    def update_embedding_matrix(self, vector, centroid, prediction) -> None:
        canvas = self.vector_canvas
        canvas.delete("all")
        width = max(100, canvas.winfo_width())
        height = max(100, canvas.winfo_height())
        cell = max(1, min((width - 16) // 64, (height - 16) // 64))
        matrix_width = cell * 64
        matrix_height = cell * 64
        x_offset = (width - matrix_width) / 2
        y_offset = (height - matrix_height) / 2
        scale = max((abs(value) for value in vector), default=0.0)
        for index, value in enumerate(vector):
            row, column = divmod(index, 64)
            x1 = x_offset + column * cell
            y1 = y_offset + row * cell
            canvas.create_rectangle(x1, y1, x1 + cell, y1 + cell, fill=self._vector_color(value, scale), outline="")
        magnitude = math.sqrt(math.fsum(value * value for value in vector))
        cosine = centroid.get("cosine_similarity")
        distance = centroid.get("euclidean_distance")
        if cosine is None:
            detail = f"Magnitude {magnitude:.4f} · no learned centroids; comparison unavailable"
        else:
            detail = f"Magnitude {magnitude:.4f} · nearest {centroid['nearest_label']} · cosine {cosine:.4f} · Euclidean {distance:.4f}"
        detail += f" · classifier {prediction.get('status', 'untrained')}"
        self.embedding_detail.configure(text=self.tr(detail))

    def _render_storyboard(self, lines: list[str], verdict: str = "READY") -> None:
        for widget in self.story_lines:
            widget.destroy()
        self.story_lines.clear()
        palette = {
            "HIGH RISK": ("#FF667D", "#311820"),
            "SUSPICIOUS": ("#FFB454", "#302719"),
            "TEST SIGNATURE": ("#FFB454", "#302719"),
            "SAFE": ("#61D6C5", "#142A2A"),
            "INFO": ("#AFC0D3", "#151F2C"),
            "ANALYSIS ERROR": ("#FF667D", "#311820"),
        }
        for row, line in enumerate(lines):
            normalized = line.lower()
            if any(token in normalized for token in ("external threat-intelligence match", "critical", "yara match", "identified xor", "high-risk")):
                severity = "HIGH RISK"
            elif any(token in normalized for token in ("discontinu", "elevated", "obfuscation", "decryption loop", "entropy was 7.")):
                severity = "SUSPICIOUS"
            elif any(token in normalized for token in ("no sharp", "no configured", "no bytes", "lower indicator", "no match", "benign")):
                severity = "SAFE"
            elif verdict == "ANALYSIS ERROR":
                severity = verdict
            else:
                severity = "INFO"
            line = self.tr(line)
            text_color, background = palette.get(severity, palette["INFO"])
            label = ctk.CTkLabel(self.story_lines_frame, text=f"{self.tr(severity)}  /  {line}", text_color=text_color, fg_color=background, anchor="e" if self.language == "ar" else "w", justify="right" if self.language == "ar" else "left", wraplength=850, height=34, corner_radius=5)
            label.grid(row=row, column=0, sticky="ew", pady=3)
            self.story_lines.append(label)

    def update_intelligence_panel(self, intelligence: dict[str, Any]) -> None:
        raw_status = intelligence.get("status", "unavailable")
        status = self.tr(raw_status) if self.language == "ar" else raw_status.replace("_", " ").upper()
        summary_parts = [
            status,
            f"{intelligence.get('elapsed_ms', 0):.1f} {self.tr('ms')} / {intelligence.get('latency_budget_ms', 1500):.0f} {self.tr('ms')} {self.tr('budget')}",
            f"{self.tr('indicator ')}{self.tr(intelligence.get('indicator_type') or 'unsupported indicator')}",
        ]
        if intelligence.get("attributions"):
            summary_parts.append(self.tr("reported actors: ") + ", ".join(intelligence["attributions"][:3]))
        if intelligence.get("classifications"):
            summary_parts.append(self.tr("feed classifications: ") + ", ".join(intelligence["classifications"][:3]))
        self.osint_summary.configure(text=" · ".join(summary_parts))
        status_colors = {"matched": "#FF667D", "no_match": "#61D6C5", "timeout": "#FFB454", "authentication_required": "#6FA8FF", "error": "#FF667D", "dependency_missing": "#FFB454", "unsupported_indicator": "#8292A8"}
        for feed_name, label in self.feed_status_labels.items():
            feed = intelligence.get("feeds", {}).get(feed_name, {})
            feed_status = feed.get("status", "unavailable")
            feed_status_display = self.tr(feed_status) if self.language == "ar" else feed_status.replace("_", " ").upper()
            label.configure(text=feed_status_display, text_color=status_colors.get(feed_status, "#8292A8"))
            records = feed.get("records", [])
            detail_parts = [f"{len(records)} {self.tr('record(s)')}"] if records else []
            record_tags = sorted({
                item
                for record in records
                for key in ("attributions", "classification", "campaigns", "tags")
                for item in record.get(key, [])
                if isinstance(item, str) and item
            })
            if record_tags:
                detail_parts.append(", ".join(record_tags[:5]))
            if feed.get("error"):
                detail_parts.append(self.tr(feed["error"]))
            label_widget = self.feed_detail_labels[feed_name]
            label_widget.configure(text=" · ".join(detail_parts) or self.tr("No match reported"))

    def update_yara_pe(self, result) -> None:
        yara_lines = [f"YARA matches: {len(result.yara_matches)}"]
        for match in result.yara_matches:
            yara_lines.append(f"- {match.get('rule_name', 'unnamed')}: {match.get('description', 'No description')}")
        if not result.yara_matches:
            yara_lines.append("No configured YARA rule matched this target.")
        self.yara_box.configure(state="normal")
        self.yara_box.delete("0.0", "end")
        self.yara_box.insert("0.0", "\n".join(self.tr(line) for line in yara_lines))
        self.yara_box.configure(state="disabled")
        pe = result.pe_analysis or {}
        pe_lines = [f"PE status: {pe.get('status', 'not_run')}", f"Is PE: {bool(pe.get('is_pe', False))}"]
        if pe.get("error"):
            pe_lines.append(f"Detail: {pe['error']}")
        pe_lines.extend(str(item) for item in pe.get("findings", []))
        self.pe_box.configure(state="normal")
        self.pe_box.delete("0.0", "end")
        self.pe_box.insert("0.0", "\n".join(self.tr(line) for line in pe_lines))
        self.pe_box.configure(state="disabled")

    def update_ml_status(self, result):
        model = self.embedding_engine.summary()
        self.ml_status_box.configure(state="normal")
        self.ml_status_box.delete("0.0", "end")
        counts = ", ".join(f"{label}: {count}" for label, count in model["training_examples"].items()) or "none"
        ml_text = f"Embedding dimension: {model['dimension']}\nTraining state: {'trained from human labels' if model['trained'] else 'untrained'}\nTraining examples seen: {counts}\n\nClassifier agreement threshold: {model['confidence_threshold']:.3f}\nAgreement is uncalibrated and is not probability/confidence. No model accuracy or zero-day detection claim is made.\n\nExisting scanner ML: {result.model_status}\nMITRE ATT&CK techniques: {len(result.mitre_techniques)}\nYARA matches: {len(result.yara_matches)}\nPE analysis status: {result.pe_analysis.get('status', 'not_run')}\n"
        self.ml_status_box.insert("0.0", self.tr(ml_text))
        self.ml_status_box.configure(state="disabled")

    def write_log(self, message: str):
        self.audit_log_box.configure(state="normal")
        self.audit_log_box.insert("end", self.tr(message) + "\n")
        self.audit_log_box.configure(state="disabled")

    def apply_settings(self):
        self.settings["entropy_analysis"] = self.settings_vars["entropy_analysis"].get()
        self.settings["heuristic_rules"] = self.settings_vars["heuristic_rules"].get()
        self.settings["ml_analysis"] = self.settings_vars["ml_analysis"].get()
        self.settings["osint_lookup"] = self.settings_vars["osint_lookup"].get()
        self.settings["monitoring_enabled"] = self.settings_vars["monitoring_enabled"].get()
        if self.settings["monitoring_enabled"]:
            if self.monitor is None or not self.monitor.is_running():
                self.monitor = DownloadMonitor(self.settings["monitoring_directory"], callback=self.handle_download_event)
            self.monitor.start()
            self._append_log("Downloads monitoring enabled.")
        elif self.monitor:
            self.monitor.stop()
            self._append_log("Downloads monitoring disabled.")
        messagebox.showinfo(self.tr("Settings updated"), self.tr("The active settings have been applied to the scan pipeline."))

    def learn_current_sample(self):
        if self.last_vector is None:
            messagebox.showwarning("No vector", "Analyze a target before adding a human label.")
            return
        label = self.learning_label.get().strip()
        label = {"مراجعة": "review", "سليم": "benign", "ضار": "malicious"}.get(label, label)
        if not label:
            return
        self.embedding_engine.partial_fit([self.last_vector], [label])
        self._append_log(f"Human label added to in-memory model: {label}; this is not an independent validation result.")
        if self.last_vector is not None:
            centroid = self.embedding_engine.compare(self.last_vector)
            prediction = self.embedding_engine.classify(self.last_vector)
            self.update_embedding_matrix(self.last_vector, centroid, prediction)
        if self.last_result is not None:
            self.update_ml_status(self.last_result)

    def close_app(self):
        if self.monitor:
            self.monitor.stop()
        self.destroy()

    def export_txt_report(self):
        if not self.last_result:
            messagebox.showwarning("No report", "Run a scan before exporting the report.")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt")])
        if output_path:
            export_report(self.last_result, output_path, "txt")
            if self.last_nextgen and self.last_osint:
                comparison = self.embedding_engine.compare(self.last_vector) if self.last_vector else {"status": "untrained"}
                with Path(output_path).open("a", encoding="utf-8") as report_file:
                    report_file.write("\n\nCYBERSCAN NEXTGEN ANALYSIS\n")
                    report_file.write(f"Structural score: {self.last_nextgen['composite_innovation_score']:.2f}/100 (heuristic, not probability)\n")
                    report_file.write(f"Input profile: {self.last_nextgen.get('input_profile', 'unknown')}\n")
                    report_file.write(f"Mean entropy: {self.last_nextgen['entropy_topography']['mean_entropy']:.6f}/8\n")
                    report_file.write(f"Peak entropy: {self.last_nextgen['entropy_topography']['peak_entropy']:.6f}/8\n")
                    report_file.write(f"CFG architecture: {self.last_nextgen['cfg_topology']['architecture']}\n")
                    report_file.write(f"CFG complexity: {self.last_nextgen['cfg_topology']['cyclomatic_complexity']}\n")
                    report_file.write(f"Embedding model: {comparison.get('status', 'untrained')}\n")
                    if comparison.get("nearest_label") is not None:
                        report_file.write(f"Nearest labeled centroid: {comparison['nearest_label']}\n")
                        report_file.write(f"Cosine similarity: {comparison['cosine_similarity']:.6f}\n")
                        report_file.write(f"Euclidean distance: {comparison['euclidean_distance']:.6f}\n")
                    report_file.write(f"OSINT status: {self.last_osint['status']} in {self.last_osint['elapsed_ms']:.3f} ms\n")
                    for source, feed in self.last_osint.get("feeds", {}).items():
                        report_file.write(f"- {source}: {feed.get('status')} ({feed.get('match_count', 0)} matches)\n")
                    if self.last_osint.get("attributions"):
                        report_file.write("Reported attributions: " + ", ".join(self.last_osint["attributions"]) + "\n")
                    report_file.write("\nForensic storyboard:\n")
                    for line in self.last_nextgen["forensic_storyboard"]:
                        report_file.write(f"- {line}\n")
            messagebox.showinfo("Export complete", f"Report saved to {output_path}")

    def handle_download_event(self, path):
        self._append_log(f"[Monitoring] New file detected: {path}")

    def create_demo_sample(self, name: str, content: bytes, suffix: str):
        demo_dir = SAMPLE_DIR
        demo_dir.mkdir(parents=True, exist_ok=True)
        path = demo_dir / f"{name}{suffix}"
        path.write_bytes(content)
        return str(path)

    def run_safe_pdf_demo(self):
        sample = self.create_demo_sample("safe_pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n", ".pdf")
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, sample)
        self.selected_file_path = sample
        self.file_label.configure(text="safe_pdf.pdf")
        self.run_scan()

    def run_spoofed_exe_demo(self):
        sample = self.create_demo_sample("spoofed_exe", b"MZ\x00\x00\x00\x00" + b"some text data", ".txt")
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, sample)
        self.selected_file_path = sample
        self.file_label.configure(text="spoofed_exe.txt")
        self.run_scan()

    def run_encoded_powershell_demo(self):
        payload = "powershell -enc ZgBiAHQAaAB0AHMAdABvAHIAaQBuAGcA"
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, payload)
        self.selected_file_path = None
        self.file_label.configure(text="No file selected")
        self.run_scan()

    def run_packed_pe_demo(self):
        data = b"MZ" + b"\x00" * 400 + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00" + bytes(range(256)) * 12
        sample = self.create_demo_sample("packed_pe_demo", data, ".exe")
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, sample)
        self.selected_file_path = sample
        self.file_label.configure(text="packed_pe_demo.exe")
        self.run_scan()


if __name__ == "__main__":
    app = CyberScanApp()
    app.mainloop()
