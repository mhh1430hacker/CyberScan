from __future__ import annotations

from tkinter import ttk
from typing import Any

import customtkinter as ctk


class ModernThreatDashboard:
    def __init__(self, parent: ctk.CTkBaseClass, app: Any):
        self.parent = parent
        self.app = app

    def create_risk_gauge(self, title: str, value: int, accent: str) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.parent, fg_color="#101724", corner_radius=16)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color="#A0A5B5").pack(anchor="w", padx=14, pady=(12, 4))
        ctk.CTkLabel(frame, text=f"{value}/100", font=ctk.CTkFont(size=24, weight="bold"), text_color=accent).pack(anchor="w", padx=14)
        bar = ctk.CTkProgressBar(frame, width=220, height=12, progress_color=accent)
        bar.set(max(0.0, min(1.0, value / 100)))
        bar.pack(fill="x", padx=14, pady=(8, 12))
        return frame

    def create_feature_bar(
        self,
        label: str,
        value: int,
        color: str,
        parent: ctk.CTkBaseClass | None = None,
    ) -> ctk.CTkFrame:
        row = ctk.CTkFrame(parent or self.parent, fg_color="#101724", corner_radius=12)
        ctk.CTkLabel(row, text=label, text_color="#DDE5F3", width=140, anchor="w").pack(side="left", padx=(12, 8), pady=8)
        bar = ctk.CTkProgressBar(row, width=220, height=10, progress_color=color)
        bar.set(value / 100)
        bar.pack(side="left")
        ctk.CTkLabel(row, text=f"{value}%", text_color="#A0A5B5").pack(side="left", padx=10, pady=8)
        return row

    def create_mitre_badge(self, technique_id: str, technique_name: str) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            self.parent,
            text=f"{technique_id}\n{technique_name}",
            width=150,
            height=52,
            corner_radius=12,
            fg_color="#131B2B",
            hover_color="#1C2940",
            text_color="#00F0FF",
        )
        return btn

    def create_demo_button(self, label: str, command) -> ctk.CTkButton:
        btn = ctk.CTkButton(
            self.parent,
            text=label,
            width=180,
            height=34,
            fg_color="#1C2B3F",
            hover_color="#233A5B",
            command=command,
        )
        return btn
