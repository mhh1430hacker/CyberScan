from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import queue
import shutil
import threading
import time
import tkinter as tk
import uuid
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any
from urllib.parse import urlsplit

import customtkinter as ctk

from config import DATA_DIR, DEFAULT_SETTINGS, REPORT_DIR, ensure_directories
from core.deep_embedding import HighDimensionalEmbedding
from core.global_intelligence import GlobalIntelligenceEngine
from core.models import Finding, ScanResult
from core.nextgen_engine import NextGenCyberEngine
from core.risk_engine import finalize_result
from core.scanner import scan_target
from monitoring.downloads_monitor import DownloadMonitor
from reports.exporter import export_report
from ui.translations import AR_TRANSLATIONS, shape_arabic_text, translate_text
from ui.persistence import LocalUiStore

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

EICAR_TEST_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class CyberScanApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ensure_directories()
        self.title("CyberScan | Hybrid Threat Detection")
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = min(1320, max(720, screen_width - 48))
        window_height = min(880, max(560, screen_height - 88))
        self.geometry(
            f"{window_width}x{window_height}+"
            f"{max(0, (screen_width - window_width) // 2)}+"
            f"{max(0, (screen_height - window_height) // 2)}"
        )
        self.minsize(min(980, window_width), min(640, window_height))
        self.ui_store = LocalUiStore(DATA_DIR / "ui_settings.json", DATA_DIR / "scan_history.json")
        self._startup_warnings: list[str] = []
        try:
            persisted_settings = self.ui_store.load_settings(
                {**DEFAULT_SETTINGS, "ui_language": "en"}
            )
        except ValueError as exc:
            persisted_settings = {**DEFAULT_SETTINGS, "ui_language": "en"}
            self._startup_warnings.append(str(exc))
        preferred_language = persisted_settings.pop("ui_language", "en")
        self.language = preferred_language if preferred_language in {"en", "ar"} else "en"
        self.settings = {
            key: persisted_settings[key]
            for key in DEFAULT_SETTINGS
            if key in persisted_settings
        }
        try:
            self.scan_history = self.ui_store.load_history()
        except ValueError as exc:
            self.scan_history = []
            self._startup_warnings.append(str(exc))
        self.current_tab = "live"
        self.input_mode = "File"
        self.selected_file_path: str | None = None
        self.last_result = None
        self.last_nextgen: dict[str, Any] | None = None
        self.last_osint: dict[str, Any] | None = None
        self.last_vector: tuple[float, ...] | None = None
        self.last_scan_bytes: bytes | None = None
        self.structural_encoder = HighDimensionalEmbedding()
        self._scan_busy = False
        self._pending_monitor_files: queue.Queue[str] = queue.Queue()
        self._stage_states: list[str] = []
        self._visual_tick_id: str | None = None
        self._result_animation_id: str | None = None
        self._score_animation_id: str | None = None
        self._reveal_queue: list[Any] = []
        self._animation_phase = 0.0
        self._result_visual_last_draw = 0.0
        self.audit_log_entries = [
            "[System] CyberScan initialized. Static analysis active / ML unavailable."
        ]
        self.ui_queue: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.monitor = DownloadMonitor(self.settings["monitoring_directory"], callback=self.handle_download_event)
        self.configure(fg_color="#090A0F")
        ctk.set_widget_scaling(1.12 if self.settings.get("large_text", False) else 1.0)
        self._nav_state = {"live": "active"}
        self.build_ui()
        self.bind("<Control-o>", self._shortcut_select_file)
        self.bind("<Control-l>", self._shortcut_focus_target)
        self.bind("<Control-Return>", self._shortcut_run_scan)
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.after(40, self._drain_ui_queue)
        self.after(900, self._pulse_verdict_badge)
        if self._startup_warnings:
            self.after(300, self._show_startup_warnings)

    def build_ui(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        sidebar = ctk.CTkFrame(self, width=286, corner_radius=0, fg_color="#0E1320")
        self.sidebar = sidebar
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            sidebar,
            text="CYBERSCAN",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#56F1D6",
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(22, 3))
        ctk.CTkLabel(
            sidebar,
            text="Recent scans",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#DCE8F6",
        ).grid(row=1, column=0, sticky="w", padx=20, pady=(12, 9))
        self.sidebar_history = ctk.CTkScrollableFrame(
            sidebar,
            fg_color="transparent",
            corner_radius=0,
        )
        self.sidebar_history.grid(row=2, column=0, sticky="nsew", padx=9, pady=(0, 8))
        self.sidebar_history.grid_columnconfigure(0, weight=1)
        self.nav_buttons: dict[str, ctk.CTkButton] = {}
        sidebar_actions = ctk.CTkFrame(sidebar, fg_color="transparent")
        sidebar_actions.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 10))
        sidebar_actions.grid_columnconfigure((0, 1), weight=1, uniform="sidebar_actions")
        self.view_history_button = ctk.CTkButton(
            sidebar_actions,
            text="View full history",
            command=lambda: self.show_tab("history"),
            fg_color="#1B3040",
            hover_color="#26485A",
            height=34,
            width=120,
        )
        self.view_history_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.tools_menu = ctk.CTkOptionMenu(
            sidebar_actions,
            values=[],
            command=self._select_tool,
            width=112,
            fg_color="#1B3040",
            button_color="#23645E",
            dropdown_fg_color="#111A27",
        )
        self.tools_menu.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self._sync_tools_menu()
        project_card = ctk.CTkFrame(sidebar, fg_color="#111A27", corner_radius=10)
        project_card.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 8))
        ctk.CTkLabel(
            project_card,
            text="Static file analysis · targets are never executed",
            text_color="#9AABBE",
            font=ctk.CTkFont(size=10),
            justify="left",
            wraplength=230,
        ).pack(anchor="w", padx=11, pady=(10, 4))
        ctk.CTkLabel(
            project_card,
            text="Developed by m6no5 and Ainex",
            text_color="#56DCC7",
            font=ctk.CTkFont(size=10, weight="bold"),
        ).pack(anchor="w", padx=11, pady=(0, 10))
        self.language_button = ctk.CTkButton(
            sidebar,
            text="العربية",
            command=self.toggle_language,
            height=34,
            fg_color="#1B3040",
            hover_color="#26485A",
        )
        self.language_button.grid(row=5, column=0, sticky="ew", padx=14, pady=(0, 12))
        self.refresh_sidebar_history()

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
            "history": self.build_history_tab(),
            "settings": self.build_settings_tab(),
            "about": self.build_about_tab(),
        }
        self.show_tab(self.current_tab)
        self.apply_language_to_widgets()
        self._schedule_visual_tick()

    def show_tab(self, name: str):
        for frame in self.tabs.values():
            frame.grid_forget()
        self.tabs[name].grid(row=0, column=0, sticky="nsew")
        self.current_tab = name
        if name == "live" and not self._scan_busy and self.last_result is None:
            self.welcome_panel.grid()
        elif hasattr(self, "welcome_panel"):
            self.welcome_panel.grid_remove()
        self._set_active_nav(name)

    def _tool_tabs(self) -> tuple[tuple[str, str], ...]:
        return (
            ("YARA & PE", "yara"),
            ("MITRE ATT&CK", "mitre"),
            ("Structural Classifier", "ml"),
            ("Audit Logs", "logs"),
            ("Settings", "settings"),
            ("About", "about"),
        )

    def _sync_tools_menu(self) -> None:
        if not hasattr(self, "tools_menu"):
            return
        self.tools_menu.configure(
            values=[self.tr(label) for label, _ in self._tool_tabs()]
        )
        self.tools_menu.set(self.tr("More tools"))

    def _select_tool(self, selected: str) -> None:
        target = next(
            (
                tab
                for label, tab in self._tool_tabs()
                if selected in {label, self.tr(label)}
            ),
            None,
        )
        if target is not None:
            self.show_tab(target)
        self._sync_tools_menu()

    def _choose_welcome_action(self, mode: str) -> None:
        self._change_input_mode(self.tr(mode))
        if mode == "File":
            self.select_file()
        else:
            self.target_entry.focus_set()

    def _shortcut_select_file(self, _event=None):
        self.select_file()
        return "break"

    def _shortcut_focus_target(self, _event=None):
        self.show_tab("live")
        self.target_entry.focus_set()
        return "break"

    def _shortcut_run_scan(self, _event=None):
        self.show_tab("live")
        self.run_scan()
        return "break"

    def _set_active_nav(self, name: str) -> None:
        for tab_name, button in self.nav_buttons.items():
            active = tab_name == name
            button.configure(
                fg_color="#1B3040" if not active else "#1D7F78",
                hover_color="#26485A" if not active else "#2A9A8B",
                text_color="#E7F8FF" if not active else "#F3FFFE",
                border_width=1 if active else 0,
                border_color="#4AE3D3" if active else "#1B3040",
            )

    def _sidebar_record_status(self, record: dict[str, Any]) -> tuple[str, str, str]:
        classification = str(record.get("classification", "")).upper()
        if classification == "SUSPICIOUS":
            return "HIGH RISK", "#4A202A", "#FF7386"
        if classification == "REVIEW":
            return "REVIEW", "#48351B", "#FFC06B"
        if classification == "NO_INDICATORS_OBSERVED":
            return "NO INDICATORS", "#17372F", "#68D9A4"
        return "UNKNOWN", "#283342", "#AFC0D3"

    def _open_sidebar_history(self, record_id: str) -> None:
        self.show_tab("history")
        if not hasattr(self, "history_tree") or not self.history_tree.exists(record_id):
            return
        self.history_tree.selection_set(record_id)
        self.history_tree.focus(record_id)
        self.history_tree.see(record_id)
        self._select_history_record()

    def refresh_sidebar_history(self) -> None:
        if not hasattr(self, "sidebar_history"):
            return
        for child in self.sidebar_history.winfo_children():
            child.destroy()
        if not self.scan_history:
            ctk.CTkLabel(
                self.sidebar_history,
                text="No scans yet",
                text_color="#8292A8",
                font=ctk.CTkFont(size=12),
            ).grid(row=0, column=0, sticky="ew", padx=8, pady=14)
            return
        for row, record in enumerate(reversed(self.scan_history)):
            item = ctk.CTkFrame(
                self.sidebar_history,
                fg_color="#111A27",
                corner_radius=10,
                border_width=1,
                border_color="#202F40",
            )
            item.grid(row=row, column=0, sticky="ew", padx=3, pady=4)
            item.grid_columnconfigure(0, weight=1)
            target = str(record.get("target", ""))
            target_path = Path(target)
            title = target_path.name if target_path.is_absolute() else target
            if not title:
                title = self.tr("Unknown target")
            target_label = ctk.CTkLabel(
                item,
                text=title,
                text_color="#E3EDF8",
                anchor="w",
                font=ctk.CTkFont(size=11, weight="bold"),
                wraplength=155,
            )
            self._install_arabic_rendering(target_label)
            target_label.grid(row=0, column=0, sticky="ew", padx=(9, 3), pady=(7, 1))
            status, badge_color, text_color = self._sidebar_record_status(record)
            badge_label = ctk.CTkLabel(
                item,
                text=self.tr(status),
                fg_color=badge_color,
                text_color=text_color,
                corner_radius=9,
                font=ctk.CTkFont(size=9, weight="bold"),
                padx=7,
                pady=4,
            )
            self._install_arabic_rendering(badge_label)
            badge_label.grid(row=0, column=1, sticky="e", padx=(0, 7), pady=(5, 1))
            timestamp = str(record.get("timestamp", ""))[:16].replace("T", " ")
            timestamp_label = ctk.CTkLabel(
                item,
                text=f"{timestamp}  ·  {record.get('score', 0)}/100",
                text_color="#8292A8",
                font=ctk.CTkFont(size=9),
                anchor="w",
            )
            self._install_arabic_rendering(timestamp_label)
            timestamp_label.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 7))
            select_record = lambda _event=None, record_id=record["id"]: self._open_sidebar_history(record_id)
            for widget in (item, target_label, badge_label, timestamp_label):
                widget.bind("<Button-1>", select_record)
                widget.bind("<Enter>", lambda _event, card=item: card.configure(fg_color="#172333"))
                widget.bind("<Leave>", lambda _event, card=item: card.configure(fg_color="#111A27"))

    def tr(self, text: str) -> str:
        return translate_text(text, self.language)

    def _display_text(self, text: str) -> str:
        return shape_arabic_text(text) if self.language == "ar" else text

    def _show_message(self, kind: str, title: str, message: str) -> Any:
        dialog = getattr(messagebox, kind)
        return dialog(
            self._display_text(title),
            self._display_text(message),
            parent=self,
        )

    def _install_arabic_rendering(self, widget) -> None:
        label = getattr(widget, "_label", None) or getattr(widget, "_text_label", None)
        if label is not None and not getattr(label, "_cyberscan_arabic_rendering", False):
            configure = label.configure

            def configure_label(*args, **kwargs):
                if self.language == "ar" and isinstance(kwargs.get("text"), str):
                    kwargs["text"] = self._display_text(kwargs["text"])
                return configure(*args, **kwargs)

            label.configure = configure_label
            label._cyberscan_arabic_rendering = True
            try:
                configure_label(text=widget.cget("text"))
            except (AttributeError, TypeError, ValueError, tk.TclError):
                pass

        textbox = getattr(widget, "_textbox", None)
        if textbox is not None and not getattr(textbox, "_cyberscan_arabic_rendering", False):
            insert = textbox.insert

            def insert_text(index, text, *args, **kwargs):
                if self.language == "ar" and isinstance(text, str):
                    text = self._display_text(text)
                return insert(index, text, *args, **kwargs)

            textbox.insert = insert_text
            textbox._cyberscan_arabic_rendering = True
            if self.language == "ar":
                content = textbox.get("1.0", "end-1c")
                if any("\u0600" <= character <= "\u06FF" for character in content):
                    state = textbox.cget("state")
                    textbox.configure(state="normal")
                    textbox.delete("1.0", "end")
                    insert_text("1.0", content)
                    textbox.configure(state=state)

    def apply_language_to_widgets(self) -> None:
        def visit(widget):
            self._install_arabic_rendering(widget)
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
                    is_technical = widget is getattr(self, "target_entry", None)
                    if self.language == "ar":
                        widget.configure(
                            placeholder_text=shape_arabic_text(
                                AR_TRANSLATIONS.get(placeholder, placeholder)
                            ),
                            justify="left" if is_technical else "right",
                        )
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
                    widget._textbox.tag_configure(
                        "language_alignment",
                        justify="right" if self.language == "ar" else "left",
                    )
                    widget._textbox.tag_add("language_alignment", "1.0", "end")
                except (AttributeError, tk.TclError):
                    pass
            if self.language == "ar" and isinstance(widget, ctk.CTkLabel):
                try:
                    technical_labels = [
                        getattr(self, "file_label", None),
                        getattr(self, "history_detail", None),
                        *getattr(self, "feed_detail_labels", {}).values(),
                    ]
                    is_technical = widget in technical_labels
                    widget.configure(
                        justify="left" if is_technical else "right",
                        anchor="w" if is_technical else "e",
                    )
                except tk.TclError:
                    pass
            for child in widget.winfo_children():
                visit(child)

        self.title(self.tr("CyberScan | Hybrid Threat Detection"))
        visit(self)
        self._apply_layout_direction()
        self._sync_input_mode_menu()
        self._sync_tools_menu()

    def _sync_target_alignment(self) -> None:
        if not hasattr(self, "target_entry"):
            return
        value = self.target_entry.get().strip()
        is_rtl_text = bool(value) and self.input_mode == "Indicator / text" and not value.isascii()
        self.target_entry.configure(
            justify="right" if self.language == "ar" and (not value or is_rtl_text) else "left"
        )

    @staticmethod
    def _swap_horizontal_padding(value):
        if isinstance(value, (tuple, list)) and len(value) == 2:
            return value[1], value[0]
        return value

    @staticmethod
    def _swap_horizontal_anchor(value: str) -> str:
        if value == "center":
            return value
        return value.translate(str.maketrans({"e": "w", "w": "e"}))

    def _apply_layout_direction(self) -> None:
        rtl = self.language == "ar"

        def mirror_children(parent) -> None:
            children = parent.winfo_children()
            grid_children = []
            for child in children:
                try:
                    info = child.grid_info()
                except tk.TclError:
                    continue
                if info:
                    grid_children.append((child, info))
            if rtl and grid_children:
                column_count = max(
                    int(info.get("column", 0)) + int(info.get("columnspan", 1))
                    for _, info in grid_children
                )
                try:
                    configurations = [
                        parent.grid_columnconfigure(column)
                        for column in range(column_count)
                    ]
                    for column, configuration in enumerate(configurations):
                        parent.grid_columnconfigure(
                            column_count - column - 1,
                            **configuration,
                        )
                except (tk.TclError, TypeError, ValueError):
                    pass
                for child, info in grid_children:
                    try:
                        column = int(info.get("column", 0))
                        span = int(info.get("columnspan", 1))
                        sticky = str(info.get("sticky", "")).translate(
                            str.maketrans({"e": "w", "w": "e"})
                        )
                        child.grid_configure(
                            column=column_count - column - span,
                            sticky=sticky,
                            padx=self._swap_horizontal_padding(info.get("padx", 0)),
                        )
                    except (tk.TclError, TypeError, ValueError):
                        continue

            container_types = (ctk.CTk, ctk.CTkFrame, ctk.CTkScrollableFrame)
            for child in children:
                if rtl:
                    try:
                        info = child.pack_info()
                    except tk.TclError:
                        info = {}
                    if info:
                        side = info.get("side", "top")
                        if side == "left":
                            side = "right"
                        elif side == "right":
                            side = "left"
                        child.pack_configure(
                            side=side,
                            anchor=self._swap_horizontal_anchor(info.get("anchor", "center")),
                            padx=self._swap_horizontal_padding(info.get("padx", 0)),
                        )
                if isinstance(child, container_types):
                    mirror_children(child)

        mirror_children(self)
        if hasattr(self, "verdict_badge"):
            self.verdict_badge.place_configure(
                relx=0.03 if rtl else 0.97,
                anchor="nw" if rtl else "ne",
            )

    def toggle_language(self) -> None:
        self._cancel_visual_callbacks()
        target_text = self.target_entry.get()
        selected_path = self.selected_file_path
        audit_log = "\n".join(self.audit_log_entries)
        result_height = int(self.result_text.cget("height")) if hasattr(self, "result_text") else 100
        next_language = "ar" if self.language == "en" else "en"
        persistence_error = None
        try:
            self.ui_store.save_settings(
                {**self.settings, "ui_language": next_language}
            )
        except (OSError, TypeError, ValueError) as exc:
            persistence_error = exc
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
        self.result_text.configure(height=result_height)
        self.result_details_button.configure(
            text=self.tr("Collapse report") if result_height >= 200 else self.tr("Expand report")
        )
        if self._scan_busy:
            self.scan_button.configure(state="disabled", text=self.tr("Analyzing..."))
            self.input_panel.grid_remove()
            self.processing_panel.grid()
            for section in self.technical_detail_sections:
                section.grid_remove()
            self.verdict_summary_panel.grid_remove()
            self.result_panel.grid_remove()
            self.technical_details_button.grid_remove()
        self.restore_last_scan_view()
        if self.last_result is not None and not self._scan_busy:
            self._show_scan_results()
        self.refresh_history()
        if persistence_error is not None:
            self._show_message(
                "showerror",
                self.tr("Settings could not be saved"),
                str(persistence_error),
            )

    def _show_startup_warnings(self) -> None:
        self._show_message(
            "showwarning",
            self.tr("Local data warning"),
            "\n\n".join(self._startup_warnings),
        )

    def _cancel_visual_callbacks(self) -> None:
        for callback_id in (
            self._visual_tick_id,
            self._result_animation_id,
            self._score_animation_id,
        ):
            if callback_id is not None:
                try:
                    self.after_cancel(callback_id)
                except tk.TclError:
                    pass
        self._visual_tick_id = None
        self._result_animation_id = None
        self._score_animation_id = None

    def _schedule_visual_tick(self, delay: int = 45) -> None:
        self._visual_tick_id = self.after(delay, self._animate_visuals)

    def _animate_visuals(self) -> None:
        if not self.winfo_exists():
            return
        self._animation_phase = (self._animation_phase + 0.045) % (math.tau)
        if self.current_tab == "live":
            self._draw_hero_background()
            if self._scan_busy:
                self._draw_processing_animation()
            elif getattr(self, "visual_results_panel", None) and self.visual_results_panel.winfo_ismapped():
                now = time.monotonic()
                if now - self._result_visual_last_draw >= 0.16:
                    self._draw_result_visualization()
                    self._result_visual_last_draw = now
        self._schedule_visual_tick(45 if self.current_tab == "live" else 250)

    def _draw_hero_background(self) -> None:
        canvas = getattr(self, "hero_canvas", None)
        if canvas is None or not canvas.winfo_exists():
            return
        width = max(1, canvas.winfo_width())
        height = max(1, canvas.winfo_height())
        canvas.delete("all")
        canvas.configure(background="#0B1420")
        phase = self._animation_phase
        nodes: list[tuple[float, float]] = []
        for index in range(20):
            x = ((index * 0.61803398875 + phase * (0.025 + index % 3 * 0.008)) % 1.0) * width
            y = (0.18 + ((index * 0.41421356237 + math.sin(phase + index) * 0.025) % 0.68)) * height
            nodes.append((x, y))
        for index, (x1, y1) in enumerate(nodes):
            for x2, y2 in nodes[index + 1:index + 5]:
                distance = math.hypot(x2 - x1, y2 - y1)
                if distance < min(width, height) * 0.24:
                    canvas.create_line(x1, y1, x2, y2, fill="#132C3D", width=1)
        for index, (x, y) in enumerate(nodes):
            pulse = 1.3 + (math.sin(phase * 1.7 + index) + 1.0) * 1.2
            color = "#2A897F" if index % 4 == 0 else "#2A5368"
            canvas.create_oval(x - pulse, y - pulse, x + pulse, y + pulse, fill=color, outline="")
        sweep_x = (phase / math.tau) * width
        canvas.create_line(sweep_x, 0, sweep_x - width * 0.12, height, fill="#10363B", width=2)

    def _draw_processing_animation(self) -> None:
        canvas = getattr(self, "processing_canvas", None)
        if canvas is None or not canvas.winfo_exists():
            return
        width = max(1, canvas.winfo_width())
        height = max(1, canvas.winfo_height())
        canvas.delete("all")
        center_x, center_y = width / 2, height * 0.43
        radius = min(width * 0.36, height * 0.34)
        for scale in (1.0, 0.76, 0.5):
            ring = radius * scale
            canvas.create_oval(
                center_x - ring, center_y - ring, center_x + ring, center_y + ring,
                outline="#1D4654" if scale != 0.5 else "#24645E", width=1,
            )
        angle = self._animation_phase * 2.8
        canvas.create_arc(
            center_x - radius,
            center_y - radius,
            center_x + radius,
            center_y + radius,
            start=math.degrees(angle),
            extent=88,
            style="arc",
            outline="#56F1D6",
            width=3,
        )
        canvas.create_arc(
            center_x - radius * 0.76,
            center_y - radius * 0.76,
            center_x + radius * 0.76,
            center_y + radius * 0.76,
            start=-math.degrees(angle * 0.7),
            extent=-54,
            style="arc",
            outline="#638CFF",
            width=2,
        )
        end_x = center_x + math.cos(angle) * radius
        end_y = center_y + math.sin(angle) * radius
        canvas.create_line(center_x, center_y, end_x, end_y, fill="#46E4CE", width=2)
        pulse = 4 + (math.sin(self._animation_phase * 3) + 1) * 2
        canvas.create_oval(center_x - pulse, center_y - pulse, center_x + pulse, center_y + pulse, fill="#A1FFF1", outline="")
        for index in range(16):
            orbit_angle = angle - index * 0.18
            x = center_x + math.cos(orbit_angle) * radius
            y = center_y + math.sin(orbit_angle) * radius
            size = max(1, 3 - index * 0.12)
            color = "#45D8C7" if index < 4 else "#23645E"
            canvas.create_oval(x - size, y - size, x + size, y + size, fill=color, outline="")

        stage_count = max(1, len(self._stage_states))
        stage_width = (width - 32) / stage_count
        active = next(
            (index for index, state in enumerate(self._stage_states) if state == "running"),
            None,
        )
        for index, state in enumerate(self._stage_states):
            x = 16 + stage_width * (index + 0.5)
            y = height - 15
            radius_dot = 4.5 if index == active else 3.5
            if state == "complete":
                color = "#76D69A"
            elif state == "running":
                color = "#56F1D6" if int(self._animation_phase * 8) % 2 else "#638CFF"
            elif state == "failed":
                color = "#FF667D"
            else:
                color = "#36495A"
            canvas.create_oval(
                x - radius_dot, y - radius_dot,
                x + radius_dot, y + radius_dot,
                fill=color, outline="",
            )
            if index < stage_count - 1:
                next_x = x + stage_width
                canvas.create_line(x + radius_dot + 2, y, next_x - radius_dot - 2, y, fill="#263A4C")

    def _draw_result_visualization(self) -> None:
        canvas = getattr(self, "result_visual_canvas", None)
        if canvas is None or not canvas.winfo_exists() or self.last_result is None:
            return
        canvas.delete("all")
        width = max(320, canvas.winfo_width())
        height = max(160, canvas.winfo_height())
        phase = self._animation_phase

        risk = max(0, min(100, self.last_result.combined_score))
        center_x, center_y = 92, height / 2
        radius = min(58, height * 0.34)
        canvas.create_oval(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            outline="#26394A", width=7,
        )
        color = "#FF667D" if risk >= 50 else "#FFB454" if risk > 0 else "#48D7BC"
        sweep = min(359, max(3, risk * 3.6 * (0.96 + math.sin(phase * 2) * 0.015)))
        canvas.create_arc(
            center_x - radius, center_y - radius,
            center_x + radius, center_y + radius,
            start=90, extent=-sweep, style="arc", outline=color, width=7,
        )
        canvas.create_text(center_x, center_y - 7, text=f"{risk}", fill="#F1F6FF", font=("Segoe UI", 24, "bold"))
        canvas.create_text(center_x, center_y + 21, text="/ 100", fill="#8292A8", font=("Segoe UI", 9, "bold"))
        canvas.create_text(center_x, center_y + radius + 19, text=self._display_text(self.tr("Evidence risk index")), fill="#8292A8", font=("Segoe UI", 9))

        separator_x = 178
        canvas.create_line(separator_x, 20, separator_x, height - 20, fill="#26394A")
        sample = self.last_scan_bytes or b""
        bar_left = 205
        bar_right = max(bar_left + 20, width - 20)
        bar_width = (bar_right - bar_left) / 64
        bar_baseline = height * 0.67
        canvas.create_text(bar_left, 20, text=self._display_text(self.tr("Byte structure · sampled from the scanned file")), fill="#AFC0D3", anchor="nw", font=("Segoe UI", 10, "bold"))
        for index in range(64):
            if sample:
                byte_index = round(index * (len(sample) - 1) / 63)
                value = sample[byte_index]
            else:
                value = 0
            normalized = value / 255
            amplitude = 12 + normalized * height * 0.34
            x1 = bar_left + index * bar_width + 1
            x2 = bar_left + (index + 1) * bar_width - 1
            hue = "#46DCC5" if normalized < 0.67 else "#638CFF" if normalized < 0.88 else "#FFB454"
            canvas.create_rectangle(x1, bar_baseline - amplitude, max(x1 + 1, x2), bar_baseline, fill=hue, outline="")
        canvas.create_line(bar_left, bar_baseline, bar_right, bar_baseline, fill="#26394A")

        trajectory = (self.entropy_data or {}).get("trajectory", [])
        graph_top = height * 0.79
        graph_bottom = height - 18
        canvas.create_text(bar_left, graph_top - 4, text=self._display_text(self.tr("Entropy profile")), fill="#8292A8", anchor="sw", font=("Segoe UI", 9))
        if trajectory:
            points: list[float] = []
            count = min(len(trajectory), max(2, int(bar_right - bar_left)))
            for index in range(count):
                source_index = round(index * (len(trajectory) - 1) / max(1, count - 1))
                x = bar_left + (bar_right - bar_left) * index / max(1, count - 1)
                value = max(0.0, min(8.0, float(trajectory[source_index])))
                y = graph_bottom - (graph_bottom - graph_top) * value / 8
                points.extend((x, y))
            if len(points) >= 4:
                canvas.create_line(*points, fill="#8A9EFF", width=2, smooth=True)
                for index in range(0, len(points), 2 * max(1, len(points) // 30)):
                    x, y = points[index:index + 2]
                    canvas.create_oval(x - 1.5, y - 1.5, x + 1.5, y + 1.5, fill="#D6DDFF", outline="")
        else:
            canvas.create_line(bar_left, graph_bottom, bar_right, graph_bottom, fill="#536579", dash=(3, 4))

    def _animate_result_reveal(self, widget, step: int = 0) -> None:
        if not widget.winfo_exists():
            return
        if step == 0:
            widget.grid()
            widget.update_idletasks()
            self._result_reveal_height = max(widget.winfo_reqheight(), 72)
            widget.grid_propagate(False)
            widget.configure(height=8)
        height = min(self._result_reveal_height, 8 + (step + 1) * 28)
        widget.configure(height=height)
        if height < self._result_reveal_height:
            self._result_animation_id = self.after(
                14, lambda: self._animate_result_reveal(widget, step + 1)
            )
        else:
            widget.grid_propagate(True)
            if self._reveal_queue:
                next_widget = self._reveal_queue.pop(0)
                self._result_animation_id = self.after(
                    70, lambda: self._animate_result_reveal(next_widget)
                )
            else:
                self._result_animation_id = None

    def _animate_risk_score(self, step: int = 0) -> None:
        target = int(getattr(self, "_risk_score_target", 0))
        progress = min(1.0, (step + 1) / 18)
        eased = 1 - (1 - progress) ** 3
        current = round(target * eased)
        self.verdict_summary_score.configure(
            text=f"{self.tr('Risk index: ')}{current}/100 · {self.tr('not a malware probability')}"
        )
        if progress < 1:
            self._score_animation_id = self.after(24, lambda: self._animate_risk_score(step + 1))

    def _show_scan_transition(self) -> None:
        self.input_panel.grid_remove()
        self.welcome_panel.grid_remove()
        self.verdict_summary_panel.grid_remove()
        self.visual_results_panel.grid_remove()
        self.result_panel.grid_remove()
        self.technical_details_button.grid_remove()
        self.processing_title.configure(text=self.tr("Reading the file's structure"))
        self.processing_status.configure(
            text=self.tr("Following signals through bytes, structure, and evidence.")
        )
        self._stage_states = ["waiting"] * len(self._stage_states)
        self._stage_started_at.clear()
        for marker, label in self.live_stage_widgets:
            marker.configure(text="○", text_color="#586B7E")
            label.configure(text_color="#8FA1B5")
        self.processing_panel.grid()

    def _show_scan_results(self) -> None:
        self.processing_panel.grid_remove()
        self.welcome_panel.grid_remove()
        self.input_panel.grid()
        self.verdict_summary_panel.grid()
        self.visual_results_panel.grid()
        self.technical_details_button.grid()
        if self.technical_details_visible:
            for section in self.technical_detail_sections:
                section.grid()
        self.verdict_summary_score.configure(
            text=f"{self.tr('Risk index: ')}0/100 · {self.tr('not a malware probability')}"
        )
        self._reveal_queue = [self.visual_results_panel, self.result_panel]
        self._animate_result_reveal(self.verdict_summary_panel)
        self._score_animation_id = self.after(160, self._animate_risk_score)

    def _change_input_mode(self, selected: str) -> None:
        modes = ("File", "URL", "Indicator / text")
        next_mode = next(
            (mode for mode in modes if selected in {mode, self.tr(mode)}),
            "File",
        )
        if next_mode != "File":
            if (
                self.selected_file_path
                and self.target_entry.get().strip() == self.selected_file_path
            ):
                self.target_entry.delete(0, tk.END)
            self.selected_file_path = None
            self.file_label.configure(text=self.tr("Manual target"))
        elif self.input_mode != "File":
            self.file_label.configure(text=self.tr("No file selected"))
        self.input_mode = next_mode
        self._sync_input_mode_menu()

    def _sync_input_mode_menu(self) -> None:
        if not hasattr(self, "input_mode_menu"):
            return
        modes = ("File", "URL", "Indicator / text")
        self.input_mode_menu.configure(values=[self.tr(mode) for mode in modes])
        self.input_mode_menu.set(self.tr(self.input_mode))
        self.select_file_button.configure(state="normal" if self.input_mode == "File" else "disabled")
        placeholders = {
            "File": "Choose a local file or paste a file path",
            "URL": "Paste a complete http:// or https:// URL",
            "Indicator / text": "Paste a hash, domain, IP, or suspicious text",
        }
        placeholder = self.tr(placeholders[self.input_mode])
        self.target_entry.configure(
            placeholder_text=shape_arabic_text(placeholder)
            if self.language == "ar"
            else placeholder
        )
        self._sync_target_alignment()

    def toggle_technical_details(self) -> None:
        self.technical_details_visible = not self.technical_details_visible
        for section in self.technical_detail_sections:
            if self.technical_details_visible:
                section.grid()
            else:
                section.grid_remove()
        self.technical_details_button.configure(
            text=self.tr("Hide technical details")
            if self.technical_details_visible
            else self.tr("Show technical details")
        )

    def toggle_result_details(self) -> None:
        current_height = int(self.result_text.cget("height"))
        expanded = current_height < 200
        self.result_text.configure(height=260 if expanded else 150)
        self.result_details_button.configure(text=self.tr("Collapse report") if expanded else self.tr("Expand report"))

    def restore_last_scan_view(self) -> None:
        if not (self.last_result and self.last_nextgen and self.last_osint and self.last_vector is not None and self.last_scan_bytes is not None):
            return
        prediction = self.last_result.structural_prediction
        self.update_result_panel(self.last_result, self.last_nextgen, prediction, self.last_osint, self.last_scan_bytes)
        self.entropy_data = self.last_nextgen["entropy_topography"]
        self.update_entropy_chart()
        self.update_embedding_matrix(self.last_vector, prediction)
        self.update_intelligence_panel(self.last_osint)
        self.render_mitre_matrix(self.last_result.mitre_techniques)
        self.update_ml_status(self.last_result)
        self.update_yara_pe(self.last_result)

    def _pulse_verdict_badge(self):
        if not hasattr(self, "verdict_badge"):
            self.after(900, self._pulse_verdict_badge)
            return
        current = self.verdict_badge.cget("text")
        if "READY" in current or "AWAITING" in current:
            self.verdict_badge.configure(text_color="#6EF2D0")
        elif "ANALYSIS ERROR" in current:
            self.verdict_badge.configure(text_color="#FF6B7F")
        else:
            self.verdict_badge.configure(text_color="#7BF1D2")
        self.after(1200, self._pulse_verdict_badge)

    def build_live_tab(self):
        frame = ctk.CTkScrollableFrame(
            self.content,
            fg_color="#080D14",
            corner_radius=12,
            orientation="vertical",
        )
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0, minsize=0)

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(18, 14))
        header.configure(height=148)
        header.pack_propagate(False)
        self.hero_canvas = tk.Canvas(header, height=148, bg="#0B1420", highlightthickness=0)
        self.hero_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        ctk.CTkLabel(header, text="CYBERSCAN", font=ctk.CTkFont(size=13, weight="bold"), text_color="#56F1D6").pack(anchor="w", padx=28, pady=(19, 0))
        ctk.CTkLabel(header, text="See what your file is made of.", font=ctk.CTkFont(size=30, weight="bold"), text_color="#E9F2FF").pack(anchor="w", padx=28, pady=(5, 0))
        ctk.CTkLabel(header, text="A clear answer first. Forensic depth when you want it.", font=ctk.CTkFont(size=13), text_color="#A0AFC1").pack(anchor="w", padx=30, pady=(2, 0))
        self.verdict_badge = ctk.CTkLabel(header, text="READY · AWAITING TARGET", text_color="#61D6C5", font=ctk.CTkFont(size=11, weight="bold"), fg_color="#10231F", corner_radius=20)
        self.verdict_badge.place(relx=0.97, rely=0.18, anchor="ne")

        input_panel = ctk.CTkFrame(frame, fg_color="#101A27", corner_radius=18, border_width=1, border_color="#263B4D")
        self.input_panel = input_panel
        input_panel.grid(row=1, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 16))
        input_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(input_panel, text="What would you like me to inspect?", font=ctk.CTkFont(size=15, weight="bold"), text_color="#DCE8F6").grid(
            row=0, column=0, sticky="w", padx=20, pady=(16, 8)
        )
        self.target_entry = ctk.CTkEntry(input_panel, placeholder_text="Choose a local file or enter text / URL / IOC", height=50, border_color="#30485C", corner_radius=11, font=ctk.CTkFont(size=14), fg_color="#0B121D")
        self.target_entry.grid(row=1, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 10))
        self.target_entry.bind("<KeyRelease>", self._manual_target_changed)
        self.target_entry.bind("<Return>", self._shortcut_run_scan)
        self.input_mode_menu = ctk.CTkOptionMenu(
            input_panel,
            values=["File", "URL", "Indicator / text"],
            command=self._change_input_mode,
            width=145,
            fg_color="#1B3040",
            button_color="#23645E",
        )
        self.input_mode_menu.set(self.tr(self.input_mode))
        self.input_mode_menu.grid(row=2, column=0, sticky="w", padx=(16, 8), pady=(0, 13))
        self.select_file_button = ctk.CTkButton(input_panel, text="Browse file", command=self.select_file, fg_color="#1B3040", hover_color="#26485A", width=120, height=38)
        self.select_file_button.grid(row=2, column=1, padx=(0, 8), pady=(0, 13))
        self.scan_button = ctk.CTkButton(input_panel, text="Run analysis", command=self.run_scan, fg_color="#12A991", hover_color="#19BEA5", text_color="#061713", width=155, height=38, corner_radius=10, font=ctk.CTkFont(size=13, weight="bold"))
        self.scan_button.grid(row=2, column=2, padx=(0, 16), pady=(0, 13))
        self.file_label = ctk.CTkLabel(input_panel, text="No file selected", text_color="#8292A8", anchor="w")
        self.file_label.grid(row=3, column=0, columnspan=3, sticky="ew", padx=20, pady=(0, 10))
        self.input_shortcut_hint = ctk.CTkLabel(
            input_panel,
            text="Enter / Ctrl+Enter analyze  ·  Ctrl+O file  ·  Ctrl+L input",
            text_color="#718399",
            font=ctk.CTkFont(size=10),
            anchor="w",
        )
        self.input_shortcut_hint.grid(
            row=4,
            column=0,
            columnspan=3,
            sticky="ew",
            padx=20,
            pady=(0, 12),
        )

        self.welcome_panel = ctk.CTkFrame(
            frame,
            fg_color="#0E1723",
            corner_radius=18,
            border_width=1,
            border_color="#1D3041",
        )
        self.welcome_panel.grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=18,
            pady=(4, 18),
        )
        self.welcome_panel.grid_columnconfigure((0, 1, 2), weight=1, uniform="welcome")
        welcome_heading = ctk.CTkLabel(
            self.welcome_panel,
            text="Start with a file, link, or indicator",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#E9F2FF",
        )
        welcome_heading.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky="w",
            padx=22,
            pady=(20, 4),
        )
        welcome_detail = ctk.CTkLabel(
            self.welcome_panel,
            text="Choose a path below. CyberScan inspects evidence without executing the target.",
            text_color="#9AABBE",
            font=ctk.CTkFont(size=12),
        )
        welcome_detail.grid(
            row=1,
            column=0,
            columnspan=3,
            sticky="w",
            padx=22,
            pady=(0, 14),
        )
        welcome_actions = (
            ("Scan a local file", "File", "#142B32", "#2B615E"),
            ("Check a URL", "URL", "#151F31", "#304B70"),
            ("Inspect text or an IOC", "Indicator / text", "#231F32", "#51436B"),
        )
        self.welcome_action_buttons: list[ctk.CTkButton] = []
        for column, (label, mode, fill, hover) in enumerate(welcome_actions):
            action = ctk.CTkButton(
                self.welcome_panel,
                text=label,
                command=lambda selected_mode=mode: self._choose_welcome_action(selected_mode),
                fg_color=fill,
                hover_color=hover,
                text_color="#E9F2FF",
                height=54,
                corner_radius=12,
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
            )
            self.welcome_action_buttons.append(action)
        self._welcome_actions_compact: bool | None = None
        self.welcome_panel.bind("<Configure>", self._layout_welcome_actions, add="+")

        self.processing_panel = ctk.CTkFrame(frame, fg_color="#0D1723", corner_radius=18, border_width=1, border_color="#23525A")
        self.processing_panel.grid(row=2, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        self.processing_panel.grid_columnconfigure(1, weight=1)
        self.processing_canvas = tk.Canvas(self.processing_panel, width=190, height=190, bg="#0D1723", highlightthickness=0)
        self.processing_canvas.grid(row=0, column=0, rowspan=2, padx=(18, 12), pady=(10, 2))
        self.processing_title = ctk.CTkLabel(self.processing_panel, text="Reading the file's structure", font=ctk.CTkFont(size=23, weight="bold"), text_color="#E9F2FF", anchor="w")
        self.processing_title.grid(row=0, column=1, sticky="sw", padx=12, pady=(34, 4))
        self.processing_status = ctk.CTkLabel(self.processing_panel, text="Following signals through bytes, structure, and evidence.", text_color="#AFC0D3", anchor="w", justify="left", wraplength=650)
        self.processing_status.grid(row=1, column=1, sticky="nw", padx=12, pady=(0, 16))
        self.live_stage_widgets: list[tuple[ctk.CTkLabel, ctk.CTkLabel]] = []
        live_stage_frame = ctk.CTkFrame(self.processing_panel, fg_color="transparent")
        live_stage_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        live_stage_frame.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="live_stages")
        live_stage_names = ("Read bytes", "Map structure", "Classify pattern", "Cross-check")
        for index, name in enumerate(live_stage_names):
            stage_card = ctk.CTkFrame(live_stage_frame, fg_color="#111F2D", corner_radius=10)
            stage_card.grid(row=0, column=index, sticky="ew", padx=4)
            marker = ctk.CTkLabel(stage_card, text="○", text_color="#586B7E", font=ctk.CTkFont(size=16, weight="bold"))
            marker.pack(side="left", padx=(10, 6), pady=8)
            stage_label = ctk.CTkLabel(stage_card, text=name, text_color="#8FA1B5", font=ctk.CTkFont(size=10, weight="bold"))
            stage_label.pack(side="left", padx=(0, 8), pady=8)
            self.live_stage_widgets.append((marker, stage_label))
        self.processing_panel.grid_remove()

        self.verdict_summary_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=16, border_width=1, border_color="#294255")
        self.verdict_summary_panel.grid(row=3, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        self.verdict_summary_panel.grid_columnconfigure(0, weight=1)
        self.verdict_summary_title = ctk.CTkLabel(
            self.verdict_summary_panel,
            text="Awaiting analysis",
            font=ctk.CTkFont(size=21, weight="bold"),
            text_color="#61D6C5",
        )
        self.verdict_summary_title.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))
        self.verdict_summary_detail = ctk.CTkLabel(
            self.verdict_summary_panel,
            text="Choose a file or indicator to see a concise verdict and the strongest findings.",
            text_color="#DCE8F6",
            justify="left",
            anchor="w",
            wraplength=820,
        )
        self.verdict_summary_detail.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))
        self.verdict_summary_score = ctk.CTkLabel(
            self.verdict_summary_panel,
            text="Risk index appears after analysis",
            text_color="#AFC0D3",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.verdict_summary_score.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 14))
        self.verdict_summary_panel.grid_remove()

        self.visual_results_panel = ctk.CTkFrame(frame, fg_color="#0F1825", corner_radius=16, border_width=1, border_color="#243749")
        self.visual_results_panel.grid(row=4, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        self.visual_results_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self.visual_results_panel,
            text="A visual fingerprint of this scan",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#DCE8F6",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 0))
        self.result_visual_canvas = tk.Canvas(
            self.visual_results_panel,
            height=230,
            bg="#0F1825",
            highlightthickness=0,
        )
        self.result_visual_canvas.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 10))
        self.result_visual_canvas.bind("<Configure>", lambda _event: self._draw_result_visualization())
        self.visual_results_panel.grid_remove()

        pipeline = ctk.CTkFrame(frame, fg_color="#101722", corner_radius=10, border_width=1, border_color="#233446")
        pipeline.grid(row=7, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        pipeline.grid_columnconfigure((0, 1, 2, 3), weight=1, uniform="pipeline")
        ctk.CTkLabel(pipeline, text="INSPECTION PIPELINE", font=ctk.CTkFont(size=12, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, columnspan=4, sticky="w", padx=14, pady=(12, 8))
        stage_names = (
            "File structure and entropy",
            "Executable structure",
            "Feature extraction",
            "Public threat lookup (optional)",
        )
        self.stage_widgets: list[tuple[ctk.CTkLabel, ctk.CTkProgressBar, ctk.CTkLabel]] = []
        self._stage_started_at: dict[int, float] = {}
        self._stage_states = ["waiting"] * len(stage_names)
        for index, name in enumerate(stage_names):
            stage = ctk.CTkFrame(pipeline, fg_color="#141F2D", corner_radius=8)
            stage.grid(row=1, column=index, sticky="ew", padx=7, pady=(0, 12))
            title = ctk.CTkLabel(stage, text=f"0{index + 1}  {name}", text_color="#DCE8F6", anchor="w", justify="left", wraplength=220, height=38, font=ctk.CTkFont(size=11, weight="bold"))
            title.pack(fill="x", padx=10, pady=(9, 3))
            progress = ctk.CTkProgressBar(stage, height=5, progress_color="#41DCC6")
            progress.set(0)
            progress.pack(fill="x", padx=10, pady=(0, 4))
            status = ctk.CTkLabel(stage, text="Waiting", text_color="#AFC0D3", font=ctk.CTkFont(size=10))
            status.pack(anchor="w", padx=10, pady=(0, 8))
            self.stage_widgets.append((title, progress, status))

        metrics = ctk.CTkFrame(frame, fg_color="transparent")
        metrics.grid(row=8, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 10))
        metrics.grid_columnconfigure((0, 1, 2), weight=1, uniform="metric")
        self.metric_values: dict[str, ctk.CTkLabel] = {}
        metric_specs = (("MEAN ENTROPY", "—", "#41DCC6"), ("CFG COMPLEXITY", "—", "#6FA8FF"), ("FILE SIZE", "—", "#E27A9A"))
        for index, (title, value, color) in enumerate(metric_specs):
            card = ctk.CTkFrame(metrics, fg_color="#111A27", corner_radius=9, border_width=1, border_color="#233446")
            card.grid(row=0, column=index, sticky="ew", padx=5)
            ctk.CTkLabel(card, text=title, text_color="#8292A8", font=ctk.CTkFont(size=10, weight="bold")).pack(anchor="w", padx=12, pady=(11, 3))
            value_label = ctk.CTkLabel(card, text=value, text_color=color, font=ctk.CTkFont(size=21, weight="bold"))
            value_label.pack(anchor="w", padx=12, pady=(0, 11))
            self.metric_values[title] = value_label

        self.technical_details_visible = getattr(self, "technical_details_visible", False)
        self.technical_details_button = ctk.CTkButton(
            frame,
            text="Show technical details",
            command=self.toggle_technical_details,
            fg_color="#1B3040",
            hover_color="#26485A",
            width=180,
        )
        self.technical_details_button.grid(row=6, column=0, sticky="w", padx=18, pady=(0, 12))
        self.technical_details_button.grid_remove()
        technical_details = ctk.CTkFrame(frame, fg_color="transparent")
        technical_details.grid(row=9, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        technical_details.grid_columnconfigure((0, 1), weight=1, uniform="technical")
        self.technical_details_frame = technical_details

        vector_panel = ctk.CTkFrame(technical_details, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        vector_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        ctk.CTkLabel(vector_panel, text="4096-D STRUCTURAL SPACE", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").pack(anchor="w", padx=14, pady=(13, 3))
        ctk.CTkLabel(vector_panel, text="4 × 1024: bytes/opcodes · entropy · CFG · PE/imports", font=ctk.CTkFont(size=11), text_color="#8292A8").pack(anchor="w", padx=14, pady=(0, 8))
        self.vector_canvas = tk.Canvas(vector_panel, width=320, height=240, bg="#0B111A", highlightthickness=0)
        self.vector_canvas.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        self.embedding_detail = ctk.CTkLabel(vector_panel, text="No trained classifier loaded · structural vector is deterministic", text_color="#8292A8", justify="left", anchor="w", wraplength=500)
        self.embedding_detail.pack(fill="x", padx=14, pady=(0, 7))
        ctk.CTkLabel(vector_panel, text="Training uses a reviewed manifest: clean · suspicious · malware. Class scores are uncalibrated.", text_color="#73849A", font=ctk.CTkFont(size=10), wraplength=500, justify="left").pack(anchor="w", padx=14, pady=(0, 10))

        entropy_panel = ctk.CTkFrame(technical_details, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        entropy_panel.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
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
        intel_panel.grid(row=10, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        intel_panel.grid_columnconfigure((0, 1, 2), weight=1, uniform="feeds")
        ctk.CTkLabel(intel_panel, text="GLOBAL THREAT INTELLIGENCE RADAR", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, columnspan=3, sticky="w", padx=14, pady=(13, 3))
        self.osint_summary = ctk.CTkLabel(intel_panel, text="OSINT is off by default. Enable it in Settings to submit indicators to public services.", text_color="#8292A8", anchor="w", justify="left", wraplength=850)
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
        story_panel.grid(row=11, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 14))
        story_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(story_panel, text="FORENSIC STORYBOARD", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, sticky="w", padx=14, pady=(13, 8))
        self.story_lines_frame = ctk.CTkFrame(story_panel, fg_color="transparent")
        self.story_lines_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.story_lines_frame.grid_columnconfigure(0, weight=1)
        self.story_lines: list[ctk.CTkLabel] = []
        self._render_storyboard(["Awaiting target evidence. Narrative will be generated from observed metrics."])

        result_panel = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10, border_width=1, border_color="#233446")
        self.result_panel = result_panel
        result_panel.grid(row=5, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 18))
        result_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(result_panel, text="EVIDENCE & VERDICT", font=ctk.CTkFont(size=13, weight="bold"), text_color="#DCE8F6").grid(row=0, column=0, sticky="w", padx=14, pady=(13, 8))
        self.result_text = ctk.CTkTextbox(result_panel, height=150, fg_color="#0B111A", text_color="#DCE8F6", font=ctk.CTkFont(family="Segoe UI", size=12), wrap="word")
        self.result_text.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 12))
        self.result_text.insert("0.0", "No analysis has been performed.")
        self.result_text.configure(state="disabled")
        result_panel.grid_remove()
        result_actions = ctk.CTkFrame(result_panel, fg_color="transparent")
        result_actions.grid(row=2, column=0, sticky="e", padx=12, pady=(0, 12))
        self.result_details_button = ctk.CTkButton(result_actions, text="Expand report", command=self.toggle_result_details, fg_color="#1B3040", hover_color="#26485A", width=120)
        self.result_details_button.pack(side="left", padx=(0, 8))
        ctk.CTkButton(result_actions, text="Export report", command=self.export_txt_report, fg_color="#1B3040", hover_color="#26485A", width=130).pack(side="left")
        self.technical_detail_sections = (pipeline, metrics, technical_details, intel_panel, story_panel)
        if not self.technical_details_visible:
            for section in self.technical_detail_sections:
                section.grid_remove()
        else:
            self.technical_details_button.configure(text=self.tr("Hide technical details"))
        return frame

    def _layout_welcome_actions(self, event=None) -> None:
        width = event.width if event is not None else self.welcome_panel.winfo_width()
        compact = width < 700
        if compact == self._welcome_actions_compact:
            return
        self._welcome_actions_compact = compact
        for column in range(3):
            self.welcome_panel.grid_columnconfigure(
                column,
                weight=1 if not compact or column == 0 else 0,
            )
        for index, action in enumerate(self.welcome_action_buttons):
            column = 0 if compact else (2 - index if self.language == "ar" else index)
            action.grid_configure(
                row=2,
                column=column,
                sticky="ew",
                padx=(18, 18)
                if compact
                else (18 if index == 0 else 7, 7 if index < 2 else 18),
                pady=(
                    0,
                    8
                    if compact and index < len(self.welcome_action_buttons) - 1
                    else 18,
                ),
            )

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
        ctk.CTkLabel(frame, text="Structural Classifier Status", font=ctk.CTkFont(size=24, weight="bold"), text_color="#DDE7FF").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 12))
        self.ml_status_box = ctk.CTkTextbox(frame, height=420, fg_color="#121B2C", text_color="#DDE7FF", font=ctk.CTkFont(family="Consolas", size=11))
        self.ml_status_box.grid(row=1, column=0, sticky="nsew", padx=18, pady=(0, 18))
        self.ml_status_box.insert(
            "0.0",
            "The supervised three-class structural classifier starts unavailable. "
            "Train it from a reviewed manifest with clean, suspicious, and malware samples. "
            "Class scores are uncalibrated; no accuracy or zero-day claim is made.\n",
        )
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
            for key in ("entropy_analysis", "heuristic_rules", "ml_analysis", "monitoring_enabled", "osint_enabled", "large_text")
        }
        for key, label in (
            ("entropy_analysis", "Entropy analysis"),
            ("heuristic_rules", "Heuristic rules"),
            ("ml_analysis", "Structural classifier analysis"),
            ("monitoring_enabled", "Downloads monitoring"),
            ("osint_enabled", "Send indicators to public OSINT feeds"),
            ("large_text", "Larger text and controls"),
        ):
            ctk.CTkSwitch(card, text=label, variable=self.settings_vars[key], progress_color="#41DCC6").pack(anchor="w", padx=18, pady=7)
        ctk.CTkButton(card, text="Apply settings", command=self.apply_settings, fg_color="#0D8F82", hover_color="#10A99A").pack(anchor="w", padx=18, pady=(16, 10))
        ctk.CTkLabel(card, text="OSINT is off by default. Enabling it sends the selected URL or indicator/hash to public services. Set URLHAUS_API_KEY, OTX_API_KEY, and optionally THREATFOX_API_KEY.", text_color="#8292A8", wraplength=650, justify="left").pack(anchor="w", padx=18, pady=(0, 18))
        return frame

    def build_about_tab(self):
        frame = ctk.CTkScrollableFrame(self.content, fg_color="#090D16", corner_radius=12, orientation="vertical")
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="About CyberScan", font=ctk.CTkFont(size=26, weight="bold"), text_color="#E9F2FF").grid(row=0, column=0, sticky="w", padx=22, pady=(22, 4))
        ctk.CTkLabel(frame, text="Project theory · defensive static analysis", font=ctk.CTkFont(size=13), text_color="#41DCC6").grid(row=1, column=0, sticky="w", padx=22, pady=(0, 18))

        sections = (
            ("Project purpose", "CyberScan is a defensive static-analysis research prototype. It combines file structure and byte statistics, heuristic rules, optional YARA/PE inspection, an explainable risk view, a 4096-dimensional structural embedding, and bounded public IOC lookups. It analyzes evidence without executing the target."),
            ("How the analysis works", "1. Extract byte-level and structural features, including entropy windows and (for binary input) x86 control-flow indicators.\n\n2. Project the observed structure into a deterministic 4096-D vector and classify it with a supervised three-class model only when trained from a reviewed manifest.\n\n3. If explicitly enabled, query public intelligence feeds for a supported indicator and show each source's response state.\n\n4. Present measured evidence, uncalibrated model scores, limitations, and a forensic summary for analyst review. The scanned file is not automatically modified."),
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

    def build_history_tab(self):
        frame = ctk.CTkFrame(self.content, fg_color="#0B1020", corner_radius=18)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        ctk.CTkLabel(frame, text="Scan History", font=ctk.CTkFont(size=24, weight="bold"), text_color="#DDE7FF").grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))
        ctk.CTkLabel(
            frame,
            text="Saved locally on this computer. Removing a history entry never deletes the original scanned file.",
            text_color="#AFC0D3",
            wraplength=850,
            justify="left",
        ).grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 10))
        self.history_filter = ctk.CTkEntry(frame, placeholder_text="Search by file, indicator, hash, or result")
        self.history_filter.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 10))
        self.history_filter.bind("<KeyRelease>", lambda _event: self.refresh_history())

        table_frame = ctk.CTkFrame(frame, fg_color="#111A27", corner_radius=10)
        table_frame.grid(row=3, column=0, sticky="nsew", padx=18, pady=(0, 10))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        columns = ("timestamp", "target", "classification", "score")
        style = ttk.Style(self)
        style.configure(
            "CyberScan.Treeview",
            background="#111A27",
            foreground="#DCE8F6",
            fieldbackground="#111A27",
            rowheight=36,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "CyberScan.Treeview.Heading",
            background="#172536",
            foreground="#B8C7D8",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 9),
        )
        style.map(
            "CyberScan.Treeview",
            background=[("selected", "#1D625B")],
            foreground=[("selected", "#FFFFFF")],
        )
        self.history_tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.history_tree.configure(style="CyberScan.Treeview")
        self.history_tree.tag_configure("risk_high", foreground="#FF8190")
        self.history_tree.tag_configure("risk_review", foreground="#FFC06B")
        self.history_tree.tag_configure("risk_clear", foreground="#75DCAA")
        self.history_tree.tag_configure("risk_unknown", foreground="#AFC0D3")
        for column, heading, width in (
            ("timestamp", "Time", 120),
            ("target", "File / indicator", 300),
            ("classification", "Result", 170),
            ("score", "Score", 90),
        ):
            self.history_tree.heading(column, text=heading)
            self.history_tree.column(column, width=width, anchor="w" if column != "score" else "center")
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        self.history_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.history_tree.bind("<<TreeviewSelect>>", self._select_history_record)
        self.history_tree.bind("<Double-1>", lambda _event: self.open_history_report())
        self.history_detail = ctk.CTkLabel(frame, text="Select an entry to view its hash and report.", text_color="#AFC0D3", anchor="w", justify="left", wraplength=850)
        self.history_detail.grid(row=4, column=0, sticky="ew", padx=18, pady=(0, 10))
        actions = ctk.CTkFrame(frame, fg_color="transparent")
        actions.grid(row=5, column=0, sticky="w", padx=18, pady=(0, 18))
        ctk.CTkButton(actions, text="Open report", command=self.open_history_report, fg_color="#1B3040", hover_color="#26485A").pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Export selected", command=self.export_history_report, fg_color="#1B3040", hover_color="#26485A").pack(side="left", padx=(0, 8))
        ctk.CTkButton(actions, text="Remove from history", command=self.remove_history_record, fg_color="#512B35", hover_color="#733744").pack(side="left")
        self.refresh_history()
        return frame

    def _record_scan_history(self, result) -> None:
        history_directory = Path(REPORT_DIR) / "history"
        history_directory.mkdir(parents=True, exist_ok=True)
        record_id = uuid.uuid4().hex
        report_path = history_directory / f"scan_{record_id}.json"
        export_report(result, report_path, "json")
        record = {
            "id": record_id,
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "target": str(result.target),
            "classification": result.classification,
            "score": result.combined_score,
            "sha256": result.feature_summary.get("sha256", ""),
            "report_path": str(report_path.resolve()),
        }
        updated_history = [*self.scan_history, record][-200:]
        removed_records = [*self.scan_history, record][:-200]
        try:
            self.ui_store.save_history(updated_history)
        except OSError:
            report_path.unlink(missing_ok=True)
            raise
        self.scan_history = updated_history
        for removed in removed_records:
            try:
                self._validated_history_report(removed).unlink()
            except (OSError, ValueError) as exc:
                self._append_log(f"Unable to remove expired history report: {exc}")
                continue
        self.refresh_history()

    def refresh_history(self) -> None:
        self.refresh_sidebar_history()
        if not hasattr(self, "history_tree"):
            return
        headings = {
            "timestamp": "Time",
            "target": "File / indicator",
            "classification": "Result",
            "score": "Score",
        }
        for column, heading in headings.items():
            self.history_tree.heading(
                column,
                text=self._display_text(self.tr(heading)),
            )
            anchor = "center" if column == "score" else "w" if self.language == "ar" and column == "target" else "e" if self.language == "ar" else "w"
            self.history_tree.column(column, anchor=anchor)
        if self.language == "ar":
            self.history_tree.configure(displaycolumns=("score", "classification", "target", "timestamp"))
        else:
            self.history_tree.configure(displaycolumns="#all")
        for item_id in self.history_tree.get_children():
            self.history_tree.delete(item_id)
        query = self.history_filter.get().strip().casefold() if hasattr(self, "history_filter") else ""
        for record in reversed(self.scan_history):
            searchable = " ".join((
                record.get("target", ""),
                record.get("classification", ""),
                record.get("sha256", ""),
            )).casefold()
            if query and query not in searchable:
                continue
            target = record.get("target", "")
            shown_target = Path(target).name if Path(target).is_absolute() else target
            shown_target = self._display_text(shown_target)
            classification = str(record.get("classification", "")).upper()
            risk_tag = {
                "SUSPICIOUS": "risk_high",
                "REVIEW": "risk_review",
                "NO_INDICATORS_OBSERVED": "risk_clear",
            }.get(classification, "risk_unknown")
            self.history_tree.insert(
                "",
                "end",
                iid=record["id"],
                values=(
                    record.get("timestamp", ""),
                    shown_target,
                    self._display_text(self.tr(record.get("classification", ""))),
                    f"{record.get('score', 0)}/100",
                ),
                tags=(risk_tag,),
            )

    def _selected_history_record(self) -> dict[str, Any] | None:
        selection = self.history_tree.selection()
        if not selection:
            return None
        record_id = selection[0]
        return next((item for item in self.scan_history if item["id"] == record_id), None)

    def _select_history_record(self, _event=None) -> None:
        record = self._selected_history_record()
        if record is None:
            return
        digest = record.get("sha256") or self.tr("not available")
        self.history_detail.configure(
            text=f"{record.get('target', '')}\nSHA-256: {digest}"
        )

    def _validated_history_report(self, record: dict[str, Any]) -> Path:
        history_directory = (Path(REPORT_DIR) / "history").resolve()
        report_path = Path(record["report_path"]).resolve()
        if report_path.parent != history_directory or not report_path.is_file():
            raise ValueError(self.tr("The saved report is missing or outside the local history folder."))
        return report_path

    def open_history_report(self) -> None:
        record = self._selected_history_record()
        if record is None:
            self._show_message("showinfo", self.tr("Scan History"), self.tr("Select a history entry first."))
            return
        try:
            report_path = self._validated_history_report(record)
        except (OSError, ValueError) as exc:
            self._show_message("showerror", self.tr("Report unavailable"), str(exc))
            return
        open_file = getattr(os, "startfile", None)
        if open_file is None:
            self._show_message("showerror", self.tr("Report unavailable"), self.tr("Opening reports is only supported on Windows."))
            return
        try:
            open_file(str(report_path))
        except OSError as exc:
            self._show_message("showerror", self.tr("Report unavailable"), str(exc))

    def export_history_report(self) -> None:
        record = self._selected_history_record()
        if record is None:
            self._show_message("showinfo", self.tr("Scan History"), self.tr("Select a history entry first."))
            return
        try:
            source = self._validated_history_report(record)
        except (OSError, ValueError) as exc:
            self._show_message("showerror", self.tr("Report unavailable"), str(exc))
            return
        output_path = filedialog.asksaveasfilename(
            title=self._display_text(self.tr("Export report")),
            defaultextension=".json",
            filetypes=[
                (self._display_text(self.tr("JSON report")), "*.json"),
                (self._display_text(self.tr("Text report")), "*.txt"),
            ],
        )
        if not output_path:
            return
        destination = Path(output_path)
        try:
            if destination.suffix.casefold() == ".txt":
                payload = json.loads(source.read_text(encoding="utf-8"))
                dictionary_fields = (
                    "feature_summary",
                    "engine_status",
                    "nextgen_analysis",
                    "pe_analysis",
                    "osint_summary",
                )
                list_fields = ("evidence", "yara_matches", "mitre_techniques")
                if not isinstance(payload, dict):
                    raise ValueError("The saved report must contain a JSON object.")
                if any(not isinstance(payload.get(key, {}), dict) for key in dictionary_fields):
                    raise ValueError("The saved report contains an invalid analysis section.")
                if any(not isinstance(payload.get(key, []), list) for key in list_fields):
                    raise ValueError("The saved report contains an invalid list section.")
                if not isinstance(payload.get("structural_prediction", {}), dict):
                    raise ValueError("The saved report contains an invalid structural prediction.")
                if any(not isinstance(item, dict) for key in list_fields for item in payload.get(key, [])):
                    raise ValueError("The saved report contains a malformed record.")
                nextgen = payload.get("nextgen_analysis", {})
                if any(
                    not isinstance(nextgen.get(key, {}), dict)
                    for key in ("entropy_topography", "cfg_topology")
                ):
                    raise ValueError("The saved report contains invalid structural analysis.")
                intelligence = payload.get("osint_summary", {})
                if any(
                    not isinstance(intelligence.get(key, []), list)
                    for key in ("matches", "attributions", "classifications")
                ):
                    raise ValueError("The saved report contains invalid intelligence results.")
                evidence = [
                    Finding(
                        category=str(item.get("category", "unknown")),
                        severity=str(item.get("severity", "unknown")),
                        evidence=str(item.get("evidence", "")),
                        explanation=str(item.get("explanation", "")),
                        contribution=int(item.get("contribution", 0)),
                    )
                    for item in payload.get("evidence", [])
                    if isinstance(item, dict)
                ]
                result = ScanResult(
                    target=str(payload.get("target", "")),
                    heuristic_score=int(payload.get("heuristic_score", 0)),
                    ml_risk_score=payload.get("ml_risk_score", payload.get("ml_anomaly_score")),
                    combined_score=int(payload.get("combined_score", 0)),
                    classification=str(payload.get("classification", "UNKNOWN")),
                    evidence=evidence,
                    feature_summary=payload.get("feature_summary", {}),
                    model_status=str(payload.get("model_status", "")),
                    limitations=str(payload.get("limitations", "")),
                    summary=str(payload.get("summary", "")),
                    yara_matches=payload.get("yara_matches", []),
                    engine_status=payload.get("engine_status", {}),
                    nextgen_analysis=payload.get("nextgen_analysis", {}),
                    pe_analysis=payload.get("pe_analysis", {}),
                    mitre_techniques=payload.get("mitre_techniques", []),
                    osint_summary=payload.get("osint_summary", {}),
                    structural_prediction=payload.get("structural_prediction", {}),
                )
                export_report(result, destination, "txt")
            else:
                shutil.copy2(source, destination)
        except (OSError, TypeError, ValueError) as exc:
            self._show_message("showerror", self.tr("Export failed"), str(exc))
            return
        self._show_message("showinfo", self.tr("Export complete"), str(destination))

    def remove_history_record(self) -> None:
        record = self._selected_history_record()
        if record is None:
            self._show_message("showinfo", self.tr("Scan History"), self.tr("Select a history entry first."))
            return
        if not self._show_message(
            "askyesno",
            self.tr("Remove history entry"),
            self.tr("Remove this saved history entry and its generated report? The original scanned file will not be deleted."),
        ):
            return
        updated_history = [item for item in self.scan_history if item["id"] != record["id"]]
        try:
            self.ui_store.save_history(updated_history)
        except OSError as exc:
            self._show_message("showerror", self.tr("History could not be saved"), str(exc))
            return
        self.scan_history = updated_history
        try:
            report_path = self._validated_history_report(record)
            report_path.unlink()
        except (OSError, ValueError) as exc:
            self._append_log(f"History entry removed but generated report cleanup failed: {exc}")
        self.history_detail.configure(text=self.tr("Select an entry to view its hash and report."))
        self.refresh_history()

    def render_mitre_matrix(self, techniques):
        for widget in self.mitre_matrix.winfo_children():
            widget.destroy()
        if not techniques:
            placeholder = ctk.CTkLabel(self.mitre_matrix, text="No MITRE mappings detected yet. Run a scan to populate this matrix.", text_color="#A0A5B5")
            self._install_arabic_rendering(placeholder)
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
            self._install_arabic_rendering(badge)
            badge.grid(row=row, column=col, padx=14, pady=12, sticky="nsew")

    def select_file(self):
        if self.input_mode != "File":
            self.input_mode = "File"
            self._sync_input_mode_menu()
        path = filedialog.askopenfilename(title=self._display_text(self.tr("Select a file")))
        if not path:
            return
        self.selected_file_path = path
        self.input_mode = "File"
        self._sync_input_mode_menu()
        self.file_label.configure(text=os.path.basename(path))
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, path)
        self._sync_target_alignment()

    def _manual_target_changed(self, _event=None) -> None:
        if self.selected_file_path and self.target_entry.get().strip() != self.selected_file_path:
            self.selected_file_path = None
            self.file_label.configure(text="Manual target")
        self._sync_target_alignment()

    def run_scan(self):
        if self._scan_busy:
            return
        target = self.target_entry.get().strip()
        if not target and not self.selected_file_path:
            self._show_message("showwarning", self.tr("Input required"), self.tr("Please provide a file path, URL, or suspicious pattern to scan."))
            return
        candidate = target
        if self.input_mode == "File":
            candidate = self.selected_file_path or target
            try:
                resolved = Path(candidate).resolve()
                if not resolved.is_file():
                    self._show_message("showwarning", self.tr("File not found"), self.tr("Choose an existing file to analyze."))
                    return
                candidate = str(resolved)
            except OSError:
                self._show_message("showwarning", self.tr("File not found"), self.tr("The selected file cannot be accessed."))
                return
        elif self.input_mode == "URL":
            parsed = urlsplit(target)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                self._show_message("showwarning", self.tr("Invalid URL"), self.tr("Enter a complete http:// or https:// URL."))
                return
        self._scan_busy = True
        if self._result_animation_id is not None:
            self.after_cancel(self._result_animation_id)
            self._result_animation_id = None
        if self._score_animation_id is not None:
            self.after_cancel(self._score_animation_id)
            self._score_animation_id = None
        settings_snapshot = self.settings.copy()
        self._show_scan_transition()
        self.verdict_summary_title.configure(text=self.tr("Analyzing target..."), text_color="#41DCC6")
        self.verdict_summary_detail.configure(text=self.tr("Static analysis is running. The target will not be executed."))
        self.verdict_summary_score.configure(text=self.tr("Risk index appears after analysis"))
        self.scan_button.configure(state="disabled", text=self.tr("Analyzing..."))
        for stage_index in range(len(self.stage_widgets)):
            self._set_stage(stage_index, "waiting")
        self._set_stage(0, "running")
        self._append_log("Analysis started; processing remains static and non-executing.")
        threading.Thread(target=self._scan_worker, args=(candidate, settings_snapshot, self.input_mode), daemon=True, name="CyberScanAnalysis").start()

    @staticmethod
    def _looks_like_text(data: bytes) -> bool:
        sample = data[:8192]
        if not sample:
            return True
        if b"\x00" in sample:
            return False
        printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 160 for byte in sample)
        return printable / len(sample) >= 0.90

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

    def _scan_worker(
        self,
        candidate: str,
        settings: dict[str, Any] | None = None,
        input_mode: str = "File",
    ) -> None:
        try:
            settings = self.settings.copy() if settings is None else settings
            started_at = time.monotonic()
            timeout = float(settings.get("analysis_timeout", DEFAULT_SETTINGS["analysis_timeout"]))
            if not math.isfinite(timeout) or timeout <= 0:
                raise ValueError("analysis_timeout must be a finite positive number.")

            def check_deadline() -> None:
                if time.monotonic() - started_at > timeout:
                    raise TimeoutError(f"Analysis exceeded the configured {timeout:g}-second deadline.")

            is_url = input_mode == "URL"
            path = Path(candidate) if not is_url else None
            is_file = input_mode == "File" and bool(path and path.is_file())
            if is_file:
                file_size = path.stat().st_size
                maximum = int(settings.get("maximum_file_size", 50 * 1024 * 1024))
                if file_size > maximum:
                    raise ValueError(f"File size {file_size} exceeds the configured limit of {maximum} bytes")
                raw_data = path.read_bytes()
                if len(raw_data) > maximum:
                    raise ValueError(f"File grew beyond the configured limit of {maximum} bytes during reading")
                filename = path.name
                scan_result = scan_target(str(path), is_file=True, settings=settings, file_data=raw_data)
            elif is_url:
                raw_data = candidate.encode("utf-8")
                filename = "url-indicator.txt"
                scan_result = scan_target(candidate, is_file=False, settings=settings)
            else:
                raw_data = candidate.encode("utf-8", errors="replace")
                filename = "text-indicator.txt"
                scan_result = scan_target(candidate, is_file=False, settings=settings)

            check_deadline()
            self._set_stage(0, "complete")
            self._append_log(f"Entropy stage: analyzing {len(raw_data):,} bytes in overlapping windows.")
            if is_file and settings.get("entropy_analysis", True):
                entropy = scan_result.feature_summary["entropy_topography"]
            elif settings.get("entropy_analysis", True):
                entropy = NextGenCyberEngine.analyze_entropy_topography(raw_data)
            else:
                entropy = {
                    "trajectory": [],
                    "window_offsets": [],
                    "gradients": [],
                    "mean_entropy": 0.0,
                    "peak_entropy": 0.0,
                    "gradient_variance": 0.0,
                    "anomalies": [],
                    "window_size": 0,
                    "step_size": 0,
                }
            check_deadline()

            self._set_stage(1, "running")
            text_input = self._looks_like_text(raw_data)
            if text_input:
                cfg = self._text_cfg_summary()
                self._append_log("CFG stage: text-like input detected; x86 disassembly skipped.")
            else:
                cfg = NextGenCyberEngine.extract_cfg_topology(raw_data)
                self._append_log(f"CFG stage: {cfg.get('instruction_count', 0)} instructions decoded; {cfg.get('basic_block_count', 0)} blocks measured.")
            check_deadline()
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
                "heuristic_weight": float(settings.get("heuristic_weight", 1.0)),
                "ml_weight": float(settings.get("ml_weight", 0.0)),
            }
            if text_input:
                nextgen["cfg_topology"] = cfg
                nextgen["forensic_storyboard"] = NextGenCyberEngine.generate_forensic_storyline(
                    filename,
                    len(raw_data),
                    entropy,
                    cfg,
                    score,
                )

            self._set_stage(1, "complete")
            self._set_stage(2, "running")
            vector = scan_result.structural_embedding or self.structural_encoder.embed_bytes(
                raw_data,
                entropy_topography=entropy,
                cfg_topology=cfg,
                pe_features=scan_result.pe_analysis,
            )
            prediction = scan_result.structural_prediction or {
                "status": "untrained",
                "label": None,
                "class_scores": {},
                "infection_score": None,
                "scores_are_calibrated": False,
            }
            self._append_log(
                f"Structural stage: projected {len(vector):,} normalized coordinates; "
                f"classifier state is {prediction.get('status', 'untrained')}."
            )
            self._set_stage(2, "complete")

            self._set_stage(3, "running")
            if settings.get("osint_enabled", False):
                indicator = candidate if is_url or not is_file else hashlib.sha256(raw_data).hexdigest()
                intelligence = asyncio.run(GlobalIntelligenceEngine().query_indicator(indicator))
            else:
                intelligence = {
                    "status": "disabled",
                    "indicator": None,
                    "indicator_type": None,
                    "elapsed_ms": 0.0,
                    "latency_budget_ms": 0.0,
                    "feeds": {
                        name: {"status": "disabled", "error": None, "records": [], "match_count": 0}
                        for name in ("ThreatFox", "URLhaus", "AlienVault OTX")
                    },
                    "matches": [],
                    "attributions": [],
                    "classifications": [],
                }
            check_deadline()
            self._append_log(f"OSINT stage: {intelligence['status']} after {intelligence['elapsed_ms']:.1f} ms for {intelligence['indicator_type'] or 'unsupported indicator'}.")
            self._set_stage(3, "complete")
            self.ui_queue.put(("complete", scan_result, nextgen, vector, prediction, intelligence, raw_data))
        except Exception as exc:
            self.ui_queue.put(("failed", f"{type(exc).__name__}: {exc}"))

    def _set_stage(self, index: int, state: str) -> None:
        self.ui_queue.put(("stage", index, state))

    def _apply_stage(self, index: int, state: str) -> None:
        if index >= len(self.stage_widgets):
            return
        self._stage_states[index] = state
        title, progress, status = self.stage_widgets[index]
        label = title.cget("text").split("  ", 1)[-1]
        colors = {"waiting": "#8292A8", "running": "#41DCC6", "complete": "#76D69A", "failed": "#FF667D"}
        title.configure(text=f"{index + 1:02d}  {label}", text_color=colors.get(state, "#8292A8"))
        if state == "running":
            self._stage_started_at[index] = time.monotonic()
            status.configure(text=self.tr("Working..."), text_color=colors["running"])
            if hasattr(self, "processing_status"):
                self.processing_status.configure(text=self.tr(label))
            progress.start()
        else:
            progress.stop()
            progress.set(1.0 if state == "complete" else 0.0)
            if state == "complete":
                elapsed = time.monotonic() - self._stage_started_at.pop(index, time.monotonic())
                status.configure(text=f"{self.tr('Complete')} · {elapsed:.2f} s", text_color=colors["complete"])
            elif state == "failed":
                status.configure(text=self.tr("Needs attention"), text_color=colors["failed"])
            else:
                status.configure(text=self.tr("Waiting"), text_color=colors["waiting"])
        progress.configure(progress_color=colors.get(state, "#41DCC6"))
        if index < len(self.live_stage_widgets):
                marker, live_label = self.live_stage_widgets[index]
                marker_text = {"waiting": "○", "running": "◉", "complete": "✓", "failed": "!"}.get(state, "○")
                marker.configure(text=marker_text, text_color=colors.get(state, "#8292A8"))
                live_label.configure(text_color=colors.get(state, "#8FA1B5"))
        if state == "running":
                self.processing_title.configure(text=self.tr(label))

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
                elif event_type == "monitor_file":
                    self._pending_monitor_files.put(event[1])
                    self._start_next_monitor_scan()
            except Exception as exc:
                self._scan_failed(f"UI update failed: {type(exc).__name__}: {exc}")
        self.after(40, self._drain_ui_queue)

    def _redraw_embedding_matrix(self) -> None:
        if self.last_vector is not None:
            self.update_embedding_matrix(
                self.last_vector,
                self.last_result.structural_prediction if self.last_result else {},
            )

    def _scan_failed(self, message: str) -> None:
        self._scan_busy = False
        self.processing_panel.grid_remove()
        self.input_panel.grid()
        self.verdict_summary_panel.grid()
        self.visual_results_panel.grid_remove()
        self.result_panel.grid()
        self.technical_details_button.grid()
        self.scan_button.configure(state="normal", text="Run analysis")
        active_stages = [index for index, state in enumerate(self._stage_states) if state == "running"]
        for index, state in enumerate(self._stage_states):
            if index in active_stages:
                self._apply_stage(index, "failed")
            elif state != "complete":
                self._apply_stage(index, "waiting")
        self.verdict_badge.configure(text="ANALYSIS ERROR", text_color="#FF667D")
        self.verdict_summary_title.configure(text=self.tr("Analysis failed"), text_color="#FF667D")
        self.verdict_summary_detail.configure(text=self.tr(message))
        self.verdict_summary_score.configure(text=self.tr("No result was produced"))
        self._append_log(f"Analysis failed: {message}")
        self.result_text.configure(state="normal")
        self.result_text.delete("0.0", "end")
        self.result_text.insert("0.0", f"{self.tr('Analysis did not complete.')}\n\n{self.tr(message)}")
        self.result_text.configure(state="disabled")
        self._reveal_queue = [self.result_panel]
        self._animate_result_reveal(self.verdict_summary_panel)
        self.after(0, self._start_next_monitor_scan)

    def _complete_scan(self, result, nextgen, vector, prediction, intelligence, raw_data: bytes) -> None:
        self._scan_busy = False
        self.scan_button.configure(state="normal", text="Run analysis")
        self.last_result = result
        self.last_nextgen = nextgen
        self.last_vector = vector
        self.last_osint = intelligence
        result.osint_summary = intelligence
        for anomaly in nextgen["entropy_topography"].get("anomalies", []):
            result.evidence.append(Finding(
                "statistical",
                str(anomaly.get("severity", "medium")),
                "Entropy discontinuity",
                (
                    f"Entropy changed by {float(anomaly.get('delta', 0)):+.3f} bits/byte across "
                    f"offsets 0x{int(anomaly.get('offset_start', 0)):X}-0x{int(anomaly.get('offset_end', 0)):X}."
                ),
                12,
            ))
        detected_patterns = nextgen["cfg_topology"].get("detected_patterns", [])
        if detected_patterns:
            result.evidence.append(Finding(
                "structural",
                "medium",
                "Static decoding indicator",
                ", ".join(str(pattern) for pattern in detected_patterns),
                15,
            ))
        if intelligence.get("status") == "matched":
            result.evidence.append(Finding(
                "osint",
                "high",
                "External threat-intelligence match",
                "A public feed reported this indicator; correlation is not proof that the file is malicious.",
                70,
            ))
        finalize_result(
            result,
            heuristic_weight=float(nextgen["heuristic_weight"]),
            ml_weight=float(nextgen["ml_weight"]),
        )
        result.engine_status["OSINT"] = str(intelligence.get("status", "unknown"))
        result.nextgen_analysis = nextgen
        self.last_scan_bytes = raw_data
        self.entropy_data = nextgen["entropy_topography"]
        self.update_result_panel(result, nextgen, prediction, intelligence, raw_data)
        self.update_entropy_chart()
        self.update_embedding_matrix(vector, prediction)
        self.update_intelligence_panel(intelligence)
        self.render_mitre_matrix(result.mitre_techniques)
        self.update_ml_status(result)
        self.update_yara_pe(result)
        try:
            self._record_scan_history(result)
        except (OSError, ValueError, TypeError) as exc:
            self._append_log(f"Unable to save scan history: {type(exc).__name__}: {exc}")
            self._show_message("showwarning", self.tr("History could not be saved"), str(exc))
        self._show_scan_results()
        self.after(0, self._start_next_monitor_scan)

    def update_result_panel(self, result, nextgen, prediction, intelligence, raw_data: bytes):
        self.result_text.configure(state="normal")
        self.result_text.delete("0.0", "end")
        evidence_items = [
            f"• [{self.tr(item.severity.upper())}] {self.tr(item.evidence)} — {self.tr(item.explanation)}"
            for item in result.evidence
        ]
        eicar_match = EICAR_TEST_SIGNATURE in raw_data
        if eicar_match:
            evidence_items.append(self.tr("[TEST SIGNATURE] EICAR standard anti-malware test marker detected; this marker is benign and is not a virus."))
        unique_evidence = list(dict.fromkeys(evidence_items))
        evidence = "\n".join(unique_evidence) if unique_evidence else self.tr("No direct static evidence recorded.")
        ui_risk = float(result.combined_score)
        if result.classification == "SUSPICIOUS":
            verdict = "HIGH RISK"
            verdict_color = "#FF667D"
        elif eicar_match:
            verdict = "TEST SIGNATURE"
            verdict_color = "#FFB454"
        elif result.classification == "REVIEW":
            verdict = "REVIEW"
            verdict_color = "#FFB454"
        else:
            verdict = "NO INDICATORS OBSERVED"
            verdict_color = "#61D6C5"
        self.verdict_summary_title.configure(text=self.tr(verdict), text_color=verdict_color)
        if eicar_match:
            summary_detail = self.tr("EICAR is a harmless test marker; it is not malware.")
        elif result.evidence:
            strongest = sorted(result.evidence, key=lambda item: item.contribution, reverse=True)[:2]
            summary_detail = self.tr("Main evidence: ") + "; ".join(item.evidence for item in strongest)
        else:
            summary_detail = self.tr("No indicators were observed. This does not prove that the target is safe.")
        self.verdict_summary_detail.configure(text=summary_detail)
        self._risk_score_target = int(round(ui_risk))
        self.verdict_summary_score.configure(text=f"{self.tr('Risk index: ')}{self._risk_score_target}/100 · {self.tr('not a malware probability')}")
        ml_value = self.tr("not available") if result.ml_risk_score is None else f"{result.ml_risk_score:.2f}/100"
        osint_status = intelligence.get("status", "unavailable")
        osint_status = self.tr(osint_status) if self.language == "ar" else osint_status.replace("_", " ")
        osint_line = f"{self.tr('OSINT: ')}{osint_status} ({intelligence.get('elapsed_ms', 0):.1f} {self.tr('milliseconds')})"
        if intelligence.get("attributions"):
            osint_line += self.tr(" | reported attribution: ") + ", ".join(intelligence["attributions"])
        if intelligence.get("classifications"):
            osint_line += self.tr(" | feed labels: ") + ", ".join(intelligence["classifications"])
        if prediction.get("status") == "classified":
            class_name = self.tr(prediction.get("label", "unknown"))
            class_scores = prediction.get("class_scores", {})
            score_text = ", ".join(
                f"{self.tr(label)} {value:.1f}%"
                for label, value in class_scores.items()
            )
            embedding_line = (
                f"{self.tr('Structural classifier: ')}{class_name}; "
                f"{self.tr('class scores (uncalibrated): ')}{score_text}"
            )
        else:
            embedding_line = self.tr("No trained three-class structural classifier is available.")
        profile = nextgen.get("input_profile", "binary-content")
        profile_display = self.tr(profile)
        mitre_text = "\n".join(
            f"- {item.get('id', 'N/A')}: {self.tr(item.get('name', 'Unknown'))}"
            for item in (result.mitre_techniques or [])
        ) or self.tr("No mapped techniques")
        verdict_display = self.tr(verdict)
        text = "\n".join((
            self.tr("SCAN RESULT"),
            f"{self.tr('Verdict: ')}{verdict_display}",
            f"{self.tr('Risk score: ')}{ui_risk:.0f}/100 {self.tr('(not a malware probability)')}",
            f"{self.tr('Scanner classification: ')}{self.tr(result.classification)}",
            "",
            self.tr("TARGET"),
            f"{self.tr('Target: ')}{result.target}",
            f"{self.tr('Input profile: ')}{profile_display}",
            f"{self.tr('SHA-256: ')}{hashlib.sha256(raw_data).hexdigest()}",
            "",
            self.tr("OBSERVED EVIDENCE"),
            evidence,
            "",
            self.tr("ANALYSIS SUMMARY"),
            f"{self.tr('Heuristic score: ')}{result.heuristic_score}/100",
            f"{self.tr('ML infection score (uncalibrated): ')}{ml_value}",
            f"{self.tr('Structural indicator score: ')}{nextgen['composite_innovation_score']:.2f}/100",
            f"{self.tr('OSINT: ')}{osint_status} ({intelligence.get('elapsed_ms', 0):.1f} {self.tr('milliseconds')})",
            embedding_line,
            f"{self.tr('EICAR marker: ')}{self.tr('matched (benign test string)' if eicar_match else 'not present')}",
            "",
            self.tr("MITRE ATT&CK"),
            mitre_text,
            "",
            self.tr("ENGINE STATUS AND LIMITATIONS"),
            f"{self.tr('Model status: ')}{self.tr(result.model_status)}",
            f"{self.tr('YARA status: ')}{self.tr(result.engine_status.get('YARA', 'unknown'))}",
            f"{self.tr('PE status: ')}{self.tr((result.pe_analysis or {}).get('status', 'unknown'))}",
            f"{self.tr('Limitations: ')}{self.tr(result.limitations)}",
            self.tr("Repair is not automatic. Any restoration requires explicit approval and a trusted clean source; the scanned original is left unchanged."),
            self.tr("Static indicators and public feed results are evidence for review, not proof of malware."),
        ))
        self.result_text.insert("0.0", text)
        self.result_text.configure(state="disabled")
        self.verdict_badge.configure(text=verdict_display, text_color=verdict_color)
        self.metric_values["MEAN ENTROPY"].configure(text=f"{nextgen['entropy_topography']['mean_entropy']:.2f}/8")
        self.metric_values["CFG COMPLEXITY"].configure(text=self.tr("TEXT") if profile == "text-content" else str(nextgen["cfg_topology"]["cyclomatic_complexity"]))
        file_size = result.feature_summary.get("file_size", len(raw_data))
        self.metric_values["FILE SIZE"].configure(text=self._format_file_size(int(file_size)))
        self._render_storyboard(nextgen["forensic_storyboard"], verdict)

    @staticmethod
    def _format_file_size(size: int) -> str:
        if size >= 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MiB"
        if size >= 1024:
            return f"{size / 1024:.1f} KiB"
        return f"{size} B"

    def update_entropy_chart(self) -> None:
        canvas = self.entropy_canvas
        canvas.delete("all")
        data = self.entropy_data or {}
        values = data.get("trajectory", [])
        offsets = data.get("window_offsets", [])
        if not values:
            canvas.create_text(20, 25, text=self._display_text(self.tr("No entropy windows")), fill="#8292A8", anchor="nw")
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

    def update_embedding_matrix(self, vector, prediction) -> None:
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
        detail = (
            f"Magnitude {magnitude:.4f} · 4096 deterministic structural coordinates · "
            f"classifier {prediction.get('status', 'untrained')}"
        )
        if prediction.get("label"):
            detail += (
                f" · class {prediction['label']} · "
                f"score {prediction.get('infection_score', 0):.1f}/100 (uncalibrated)"
            )
        self.embedding_detail.configure(text=self.tr(detail))

    def _render_storyboard(self, lines: list[str], verdict: str = "READY") -> None:
        for widget in self.story_lines:
            widget.destroy()
        self.story_lines.clear()
        palette = {
            "HIGH RISK": ("#FF667D", "#311820"),
            "SUSPICIOUS": ("#FFB454", "#302719"),
            "TEST SIGNATURE": ("#FFB454", "#302719"),
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
                severity = "INFO"
            elif verdict == "ANALYSIS ERROR":
                severity = verdict
            else:
                severity = "INFO"
            line = self.tr(line)
            text_color, background = palette.get(severity, palette["INFO"])
            label = ctk.CTkLabel(self.story_lines_frame, text=f"{self.tr(severity)}  /  {line}", text_color=text_color, fg_color=background, anchor="e" if self.language == "ar" else "w", justify="right" if self.language == "ar" else "left", wraplength=850, height=34, corner_radius=5)
            self._install_arabic_rendering(label)
            label.grid(row=row, column=0, sticky="ew", pady=3)
            self.story_lines.append(label)

    def update_intelligence_panel(self, intelligence: dict[str, Any]) -> None:
        if intelligence.get("status") == "disabled":
            self.osint_summary.configure(
                text=self.tr("OSINT disabled. No indicators were sent to external services.")
            )
            for label in self.feed_status_labels.values():
                label.configure(text=self.tr("DISABLED"), text_color="#8292A8")
            for label in self.feed_detail_labels.values():
                label.configure(text=self.tr("No external lookup was performed."))
            return
        raw_status = intelligence.get("status", "unavailable")
        status = self.tr(raw_status) if self.language == "ar" else raw_status.replace("_", " ").upper()
        summary_parts = [
            status,
            f"{intelligence.get('elapsed_ms', 0):.1f} {self.tr('milliseconds')} / {intelligence.get('latency_budget_ms', 1500):.0f} {self.tr('milliseconds')} {self.tr('budget')}",
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
        yara_lines = [
            f"YARA status: {result.engine_status.get('YARA', 'unknown')}",
            f"YARA matches: {len(result.yara_matches)}",
        ]
        for match in result.yara_matches:
            yara_lines.append(f"- {match.get('rule_name', 'unnamed')}: {match.get('description', 'No description')}")
        if not result.yara_matches and result.engine_status.get("YARA", "").startswith("available;"):
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
        self.ml_status_box.configure(state="normal")
        self.ml_status_box.delete("0.0", "end")
        prediction = result.structural_prediction
        class_scores = prediction.get("class_scores", {})
        scores_text = (
            ", ".join(f"{label}: {score:.1f}%" for label, score in class_scores.items())
            or "not available"
        )
        ml_text = (
            f"Model: supervised three-class Random Forest\n"
            f"Embedding: deterministic {self.structural_encoder.DIMENSION}-D structural representation\n"
            f"Training state: {prediction.get('status', 'untrained')}\n"
            f"Predicted class: {prediction.get('label') or 'not available'}\n"
            f"Uncalibrated class scores: {scores_text}\n"
            f"Uncalibrated combined infection score: "
            f"{prediction.get('infection_score') if prediction.get('infection_score') is not None else 'not available'}\n"
            "Automated repair: not available; scores never authorize file changes\n\n"
            f"{result.model_status}\n"
            "The 4096-D projection is not lossless. Packed or encrypted content may hide semantics. "
            "Scores are not calibrated probabilities and do not guarantee detection.\n"
            "Repair is not automatic; explicit approval and a trusted clean source are required. "
            "The scanned original is never modified.\n\n"
            f"MITRE ATT&CK techniques: {len(result.mitre_techniques)}\n"
            f"YARA matches: {len(result.yara_matches)}\n"
            f"PE analysis status: {result.pe_analysis.get('status', 'not_run')}\n"
        )
        self.ml_status_box.insert("0.0", self.tr(ml_text))
        self.ml_status_box.configure(state="disabled")

    def write_log(self, message: str):
        self.audit_log_entries.append(message)
        self.audit_log_box.configure(state="normal")
        self.audit_log_box.insert("end", self.tr(message) + "\n")
        self.audit_log_box.configure(state="disabled")

    def apply_settings(self):
        updated_settings = self.settings.copy()
        for key in ("entropy_analysis", "heuristic_rules", "ml_analysis", "monitoring_enabled", "osint_enabled", "large_text"):
            updated_settings[key] = self.settings_vars[key].get()
        try:
            self.ui_store.save_settings(
                {**updated_settings, "ui_language": self.language}
            )
        except (OSError, TypeError, ValueError) as exc:
            for key, variable in self.settings_vars.items():
                variable.set(bool(self.settings.get(key, False)))
            self._show_message("showerror", self.tr("Settings could not be saved"), str(exc))
            return
        self.settings = updated_settings
        ctk.set_widget_scaling(1.12 if self.settings["large_text"] else 1.0)
        if self.settings["monitoring_enabled"]:
            if self.monitor is None or not self.monitor._thread or not self.monitor._thread.is_alive():
                self.monitor = DownloadMonitor(self.settings["monitoring_directory"], callback=self.handle_download_event)
            self.monitor.start()
            self._append_log("Downloads monitoring enabled.")
        elif self.monitor:
            self.monitor.stop()
            self._append_log("Downloads monitoring disabled.")
        self._show_message("showinfo", self.tr("Settings updated"), self.tr("The active settings have been applied to the scan pipeline."))

    def close_app(self):
        if self.monitor:
            self.monitor.stop()
        self.destroy()

    def export_txt_report(self):
        if not self.last_result:
            self._show_message("showwarning", self.tr("No report"), self.tr("Run a scan before exporting a report."))
            return
        output_path = filedialog.asksaveasfilename(
            title=self._display_text(self.tr("Export report")),
            defaultextension=".txt",
            filetypes=[
                (self._display_text(self.tr("Text report")), "*.txt"),
                (self._display_text(self.tr("JSON report")), "*.json"),
            ],
        )
        if output_path:
            try:
                format_name = "json" if Path(output_path).suffix.casefold() == ".json" else "txt"
                export_report(self.last_result, output_path, format_name)
            except (OSError, ValueError, TypeError) as exc:
                self._show_message("showerror", self.tr("Export failed"), str(exc))
                return
            self._show_message("showinfo", self.tr("Export complete"), f"{self.tr('Report saved to ')}{output_path}")

    def handle_download_event(self, path):
        self._append_log(f"[Monitoring] New file detected: {path}")
        self.ui_queue.put(("monitor_file", path))

    def _start_next_monitor_scan(self) -> None:
        if self._scan_busy or self._pending_monitor_files.empty():
            return
        path = self._pending_monitor_files.get()
        if not Path(path).is_file():
            self._append_log(f"[Monitoring] File is no longer available; skipped: {path}")
            self.after(0, self._start_next_monitor_scan)
            return
        self.input_mode = "File"
        self._sync_input_mode_menu()
        self.selected_file_path = path
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, path)
        self.file_label.configure(text=os.path.basename(path))
        self._append_log(f"[Monitoring] Starting automatic static scan: {path}")
        self.run_scan()

    def create_demo_sample(self, name: str, content: bytes, suffix: str):
        demo_dir = Path("data") / "demo_samples"
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
