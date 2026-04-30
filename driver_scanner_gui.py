#!/usr/bin/env python3
"""
Driver Scanner GUI — LOLDrivers Research Tool
Drag a folder onto the window or click Browse to scan recursively for .sys files.

Requirements:
    pip install pefile tkinterdnd2
"""

import os
import csv
import sys
import json
import time
import uuid
import hashlib
import threading
import urllib.request
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime, timezone

try:
    import pefile
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile", "--break-system-packages"])
    import pefile

# Optional drag-and-drop support
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_AVAILABLE = False

# ── Palette ────────────────────────────────────────────────────────────────────
BG        = "#0d0f14"
BG2       = "#13161e"
BG3       = "#1a1e28"
BORDER    = "#2a2f3d"
ACCENT    = "#00e5ff"
ACCENT2   = "#ff3d6b"
GOLD      = "#ffd166"
GREEN     = "#06d6a0"
TEXT      = "#c8d0e0"
TEXT_DIM  = "#5a6070"
FONT_MONO = ("Courier New", 10)
FONT_UI   = ("Courier New", 11)
FONT_HEAD = ("Courier New", 14, "bold")

DANGEROUS_IMPORTS = [
    "MmMapIoSpace", "MmGetPhysicalAddress", "MmAllocateContiguousMemory",
    "ZwMapViewOfSection", "HalTranslateBusAddress", "ZwOpenSection",
    "ObReferenceObjectByName", "KeServiceDescriptorTable",
    "READ_PORT_UCHAR", "WRITE_PORT_UCHAR", "READ_PORT_ULONG", "WRITE_PORT_ULONG",
]

LOLDRIVERS_API_URL = "https://www.loldrivers.io/api/drivers.json"

# ── Analysis logic ─────────────────────────────────────────────────────────────

def hash_file(path):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def extract_unicode_strings(data, min_len=5):
    results = []
    i = 0
    while i < len(data) - 4:
        if data[i] == ord("\\") and data[i + 1] == 0:
            s, j = "", i
            while j + 1 < len(data):
                char = data[j] | (data[j + 1] << 8)
                if char == 0: break
                if 32 <= char <= 126: s += chr(char)
                else: break
                j += 2
            if len(s) >= min_len:
                results.append(s)
        i += 1
    return results

def extract_ascii_strings(data, min_len=5):
    result, current = [], []
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result

def analyze_driver(path):
    r = {
        "path": str(path), "filename": path.name,
        "size_bytes": path.stat().st_size,
        "md5": "", "sha1": "", "sha256": "",
        "signed": False, "compile_timestamp": "",
        "architecture": "", "dangerous_imports": [],
        "device_names": [], "symlinks": [],
        "pdb_path": "", "company": "", "description": "",
        "original_filename": "", "error": "",
    }
    try:
        r["md5"], r["sha1"], r["sha256"] = hash_file(path)
        with open(path, "rb") as f:
            raw = f.read()
        pe = pefile.PE(data=raw, fast_load=False)
        r["signed"] = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            r["compile_timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
        except Exception:
            r["compile_timestamp"] = f"0x{ts:08X}"
        r["architecture"] = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}.get(
            pe.FILE_HEADER.Machine, "Unknown")
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for lib in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in lib.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        if any(d.lower() == name.lower() for d in DANGEROUS_IMPORTS):
                            r["dangerous_imports"].append(name)
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                if not isinstance(fi, list): fi = [fi]
                for entry in fi:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            for k, v in st.entries.items():
                                key = k.decode(errors="ignore").strip()
                                val = v.decode(errors="ignore").strip()
                                if key == "CompanyName": r["company"] = val
                                elif key == "FileDescription": r["description"] = val
                                elif key == "OriginalFilename": r["original_filename"] = val
        ascii_strs = extract_ascii_strings(raw)
        for s in ascii_strs:
            if ".pdb" in s.lower():
                r["pdb_path"] = s; break
        # Check ASCII strings for device names and symlinks (often stored as plain ASCII)
        seen_devs = set(r["device_names"])
        seen_syms = set(r["symlinks"])
        for s in ascii_strs:
            if "\\Device\\" in s and s not in seen_devs:
                r["device_names"].append(s); seen_devs.add(s)
            elif ("\\DosDevices\\" in s or "\\??\\" in s) and s not in seen_syms:
                r["symlinks"].append(s); seen_syms.add(s)
        # Check unicode strings for device names and symlinks
        for s in extract_unicode_strings(raw):
            if "\\Device\\" in s and s not in seen_devs:
                r["device_names"].append(s); seen_devs.add(s)
            elif ("\\DosDevices\\" in s or "\\??\\" in s) and s not in seen_syms:
                r["symlinks"].append(s); seen_syms.add(s)
        pe.close()
    except Exception as e:
        r["error"] = str(e)
    return r

# ── GUI ────────────────────────────────────────────────────────────────────────

class DriverScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Driver Scanner — LOLDrivers Research")
        self.root.configure(bg=BG)
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)

        self.all_results = []   # full scan output — never filtered
        self.scan_thread = None
        self.signed_only   = tk.BooleanVar(value=False)
        self.dangerous_only = tk.BooleanVar(value=False)

        # LOLDrivers cache: {hash_lower: driver_uuid}
        self._lold_cache    = None
        self._lold_cache_ts = 0.0

        self._build_ui()

        # Re-render table instantly when filters change
        self.signed_only.trace_add("write", self._apply_filters)
        self.dangerous_only.trace_add("write", self._apply_filters)

        if DND_AVAILABLE:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_drop)

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG, pady=14)
        header.pack(fill="x", padx=20)

        tk.Label(header, text="[ DRIVER SCANNER ]", font=("Courier New", 18, "bold"),
                 fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(header, text="LOLDrivers Research Tool", font=("Courier New", 10),
                 fg=TEXT_DIM, bg=BG).pack(side="left", padx=12, pady=4)

        # Thin accent line
        tk.Frame(self.root, bg=ACCENT, height=1).pack(fill="x", padx=20)

        # Main body
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=12)

        # Left panel
        left = tk.Frame(body, bg=BG, width=280)
        left.pack(side="left", fill="y", padx=(0, 14))
        left.pack_propagate(False)

        self._build_left(left)

        # Right panel
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_right(right)

        # Status bar
        self.status_var = tk.StringVar(value="Ready. Drop a folder or click Browse.")
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")
        status_bar = tk.Frame(self.root, bg=BG2, pady=6)
        status_bar.pack(fill="x")
        tk.Label(status_bar, textvariable=self.status_var, font=("Courier New", 9),
                 fg=TEXT_DIM, bg=BG2, anchor="w").pack(side="left", padx=14)
        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=120)
        self.progress.pack(side="right", padx=14)

    def _build_left(self, parent):
        # Drop zone
        drop_frame = tk.Frame(parent, bg=BG3, bd=0, highlightthickness=2,
                              highlightbackground=BORDER)
        drop_frame.pack(fill="x", pady=(0, 12))

        self.drop_zone = tk.Label(
            drop_frame,
            text="⬇  DROP FOLDER HERE",
            font=("Courier New", 11, "bold"),
            fg=ACCENT if DND_AVAILABLE else TEXT_DIM,
            bg=BG3, pady=28, cursor="hand2" if DND_AVAILABLE else "arrow",
        )
        self.drop_zone.pack(fill="x")

        if not DND_AVAILABLE:
            tk.Label(drop_frame, text="(install tkinterdnd2 to enable)", font=("Courier New", 8),
                     fg=TEXT_DIM, bg=BG3).pack(pady=(0, 8))

        # Browse button
        self._btn(parent, "📂  BROWSE FOLDER", self._browse, ACCENT).pack(fill="x", pady=(0, 8))

        # Filters
        filt = tk.LabelFrame(parent, text=" FILTERS ", font=("Courier New", 9, "bold"),
                             fg=TEXT_DIM, bg=BG, bd=1, highlightthickness=0,
                             relief="flat", highlightbackground=BORDER)
        filt.pack(fill="x", pady=(4, 12))

        self._check(filt, "Signed only  (recommended)", self.signed_only)
        self._check(filt, "Dangerous imports only", self.dangerous_only)

        # Export / actions
        self._btn(parent, "💾  EXPORT CSV",       self._export_csv,       GOLD   ).pack(fill="x", pady=(0, 8))
        self._btn(parent, "📋  EXPORT YAML",      self._export_yaml,      ACCENT ).pack(fill="x", pady=(0, 8))
        self._btn(parent, "🔍  CHECK LOLDRIVERS", self._check_loldrivers, GREEN  ).pack(fill="x", pady=(0, 8))
        self._btn(parent, "🗑  CLEAR RESULTS",    self._clear,            ACCENT2).pack(fill="x")

        # Summary box
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=12)
        tk.Label(parent, text="SUMMARY", font=("Courier New", 9, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(anchor="w")

        self.summary_text = tk.Text(parent, bg=BG2, fg=TEXT, font=("Courier New", 9),
                                    bd=0, relief="flat", height=10, state="disabled",
                                    highlightthickness=1, highlightbackground=BORDER)
        self.summary_text.pack(fill="both", expand=True, pady=(6, 0))

    def _build_right(self, parent):
        # Toolbar
        toolbar = tk.Frame(parent, bg=BG)
        toolbar.pack(fill="x", pady=(0, 8))
        tk.Label(toolbar, text="RESULTS", font=("Courier New", 10, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(side="left")

        self.count_label = tk.Label(toolbar, text="", font=("Courier New", 9),
                                    fg=ACCENT, bg=BG)
        self.count_label.pack(side="left", padx=10)

        # Table
        cols = ("priority", "filename", "arch", "signed", "danger", "company", "compiled", "sha256")
        col_labels = ("!", "Filename", "Arch", "Signed", "Dangerous Imports", "Company", "Compiled", "SHA256")
        col_widths = (28, 170, 55, 70, 200, 140, 90, 260)

        frame = tk.Frame(parent, bg=BG, highlightthickness=1, highlightbackground=BORDER)
        frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background=BG2, foreground=TEXT, fieldbackground=BG2,
            borderwidth=0, font=("Courier New", 9), rowheight=22)
        style.configure("Treeview.Heading",
            background=BG3, foreground=ACCENT, font=("Courier New", 9, "bold"),
            borderwidth=0, relief="flat")
        style.map("Treeview",
            background=[("selected", BG3)],
            foreground=[("selected", ACCENT)])
        style.configure("Vertical.TScrollbar", background=BG3, troughcolor=BG,
                        arrowcolor=TEXT_DIM, borderwidth=0)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                 selectmode="browse", style="Treeview")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview,
                            style="Vertical.TScrollbar")
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview,
                            style="Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        for col, label, width in zip(cols, col_labels, col_widths):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, minwidth=30, anchor="w")

        self.tree.tag_configure("high",    background="#1a1200", foreground=GOLD)
        self.tree.tag_configure("danger",  background="#180a0a", foreground=ACCENT2)
        self.tree.tag_configure("signed",  background="#091510", foreground=GREEN)
        self.tree.tag_configure("normal",  background=BG2,       foreground=TEXT)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Detail panel
        detail_frame = tk.Frame(parent, bg=BG2, highlightthickness=1,
                                highlightbackground=BORDER)
        detail_frame.pack(fill="x", pady=(10, 0))

        tk.Label(detail_frame, text="DETAILS", font=("Courier New", 9, "bold"),
                 fg=TEXT_DIM, bg=BG2, pady=4, padx=8).pack(anchor="w")

        self.detail_text = tk.Text(detail_frame, bg=BG2, fg=TEXT, font=("Courier New", 9),
                                   bd=0, relief="flat", height=7,
                                   highlightthickness=0, state="disabled", wrap="none")
        det_scroll = ttk.Scrollbar(detail_frame, orient="vertical",
                                   command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=det_scroll.set)
        self.detail_text.pack(side="left", fill="both", expand=True, padx=8, pady=(0, 8))
        det_scroll.pack(side="right", fill="y", pady=(0, 8))

        # Tag colours for detail panel
        self.detail_text.tag_configure("key",        foreground=ACCENT)
        self.detail_text.tag_configure("value",      foreground=TEXT)
        self.detail_text.tag_configure("danger",     foreground=ACCENT2, font=("Courier New", 9, "bold"))
        self.detail_text.tag_configure("signed",     foreground=GREEN)
        self.detail_text.tag_configure("hash",       foreground=TEXT_DIM)
        self.detail_text.tag_configure("gold",       foreground=GOLD, font=("Courier New", 9, "bold"))
        self.detail_text.tag_configure("lold_known", foreground=ACCENT2, font=("Courier New", 9, "bold"))
        self.detail_text.tag_configure("lold_clean", foreground=GREEN,   font=("Courier New", 9, "bold"))

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _btn(self, parent, text, cmd, color):
        b = tk.Button(parent, text=text, command=cmd,
                      bg=BG3, fg=color, activebackground=BG2, activeforeground=color,
                      font=("Courier New", 10, "bold"), bd=0, pady=8, cursor="hand2",
                      relief="flat", highlightthickness=1, highlightbackground=BORDER)
        b.bind("<Enter>", lambda e: b.configure(bg=BG2))
        b.bind("<Leave>", lambda e: b.configure(bg=BG3))
        return b

    def _check(self, parent, text, var):
        tk.Checkbutton(parent, text=text, variable=var,
                       bg=BG, fg=TEXT, activebackground=BG, activeforeground=ACCENT,
                       selectcolor=BG3, font=("Courier New", 9), bd=0).pack(anchor="w", padx=8, pady=3)

    def _selected_result(self):
        """Return (idx, result) for the currently selected tree row, or (None, None)."""
        sel = self.tree.selection()
        if not sel:
            return None, None
        idx = int(sel[0][1:])  # iid is "r<index>"
        if idx < len(self.all_results):
            return idx, self.all_results[idx]
        return None, None

    # ── Events ─────────────────────────────────────────────────────────────────

    def _browse(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self._start_scan(folder)

    def _on_drop(self, event):
        path = event.data.strip().strip("{}")
        if os.path.isdir(path):
            self._start_scan(path)
        else:
            messagebox.showwarning("Not a folder", f"Please drop a folder, not a file.\n\n{path}")

    def _on_select(self, _event):
        _, r = self._selected_result()
        if r:
            self._show_detail(r)

    # ── Filtering ──────────────────────────────────────────────────────────────

    def _passes_filter(self, r):
        if self.signed_only.get() and not r["signed"]:
            return False
        if self.dangerous_only.get() and not r["dangerous_imports"]:
            return False
        return True

    def _apply_filters(self, *_):
        """Rebuild the tree from all_results using the current filter state."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, r in enumerate(self.all_results):
            if self._passes_filter(r):
                self._add_row(r, idx)
        self.count_label.config(text=f"{len(self.tree.get_children())} result(s)")

    # ── Scanning ───────────────────────────────────────────────────────────────

    def _start_scan(self, folder):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self._clear()
        self.status_var.set(f"Scanning: {folder}")
        self.progress.start(12)
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(folder,), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, folder):
        root = Path(folder)
        sys_files = sorted(root.rglob("*.sys"))

        if not sys_files:
            self.root.after(0, lambda: self.status_var.set("No .sys files found."))
            self.root.after(0, self.progress.stop)
            return

        total = len(sys_files)
        self.root.after(0, lambda: self.status_var.set(f"Found {total} driver(s). Analysing..."))

        for i, path in enumerate(sys_files, 1):
            r = analyze_driver(path)
            idx = len(self.all_results)
            self.all_results.append(r)

            if self._passes_filter(r):
                self.root.after(0, lambda r=r, idx=idx: self._add_row(r, idx))

            self.root.after(0, lambda i=i, t=total, name=path.name: self.status_var.set(
                f"Analysing {i}/{t}: {name}"))

        self.root.after(0, lambda: self._finish_scan(total))

    def _finish_scan(self, total):
        self.progress.stop()
        results = self.all_results
        signed   = sum(1 for r in results if r["signed"])
        unsigned = sum(1 for r in results if not r["signed"])
        danger   = sum(1 for r in results if r["dangerous_imports"])
        high     = sum(1 for r in results if r["signed"] and r["dangerous_imports"])
        shown    = len(self.tree.get_children())

        self.status_var.set(
            f"Done — {shown} shown / {total} scanned  |  "
            f"Signed: {signed}  Unsigned: {unsigned}  "
            f"Dangerous: {danger}  🎯 High priority: {high}"
        )
        self.count_label.config(text=f"{shown} result(s)")

        summary = (
            f"Scanned      {total}\n"
            f"Shown        {shown}\n"
            f"─────────────────────\n"
            f"Signed       {signed}\n"
            f"Unsigned     {unsigned}\n"
            f"─────────────────────\n"
            f"Dangerous    {danger}\n"
            f"─────────────────────\n"
            f"🎯 Priority  {high}\n"
        )
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("end", summary)
        self.summary_text.configure(state="disabled")

    def _add_row(self, r, idx):
        signed_str  = "YES ✓" if r["signed"] else "no"
        danger_str  = ", ".join(r["dangerous_imports"]) if r["dangerous_imports"] else "—"
        priority    = "🎯" if (r["signed"] and r["dangerous_imports"]) else ""

        tag = "normal"
        if r["signed"] and r["dangerous_imports"]: tag = "high"
        elif r["dangerous_imports"]:               tag = "danger"
        elif r["signed"]:                          tag = "signed"

        self.tree.insert("", "end", iid=f"r{idx}", tags=(tag,), values=(
            priority,
            r["filename"],
            r["architecture"],
            signed_str,
            danger_str,
            r["company"] or "—",
            r["compile_timestamp"],
            r["sha256"],
        ))
        self.count_label.config(text=f"{len(self.tree.get_children())} result(s)")

    def _show_detail(self, r):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")

        def kv(key, val, tag="value"):
            self.detail_text.insert("end", f"  {key:<20}", "key")
            self.detail_text.insert("end", f"{val}\n", tag)

        priority = r["signed"] and bool(r["dangerous_imports"])
        if priority:
            self.detail_text.insert("end", "  🎯 HIGH PRIORITY — Signed + Dangerous Imports\n", "gold")

        kv("File",         r["filename"])
        kv("Path",         r["path"])
        kv("Size",         f"{r['size_bytes']:,} bytes")
        kv("Architecture", r["architecture"])
        kv("Compiled",     r["compile_timestamp"])
        kv("Company",      r["company"] or "—")
        kv("Description",  r["description"] or "—")
        kv("Original Name",r["original_filename"] or "—")
        kv("Signed",       "YES" if r["signed"] else "NO",
           "signed" if r["signed"] else "danger")

        if r["dangerous_imports"]:
            kv("Dangerous Imports", ", ".join(r["dangerous_imports"]), "danger")
        else:
            kv("Dangerous Imports", "None found")

        kv("Device Names", ", ".join(r["device_names"]) or "—")
        kv("Symlinks",     ", ".join(r["symlinks"]) or "—")

        if r["pdb_path"]:
            kv("PDB Path", r["pdb_path"])

        self.detail_text.insert("end", "\n")
        kv("MD5",    r["md5"],    "hash")
        kv("SHA1",   r["sha1"],   "hash")
        kv("SHA256", r["sha256"], "hash")

        if r["error"]:
            kv("ERROR", r["error"], "danger")

        self.detail_text.configure(state="disabled")

    # ── LOLDrivers check ───────────────────────────────────────────────────────

    def _check_loldrivers(self):
        _, r = self._selected_result()
        if r is None:
            messagebox.showinfo("No selection", "Select a driver row first.")
            return
        self.status_var.set("Fetching LOLDrivers database…")
        threading.Thread(target=self._lold_check_worker, args=(r,), daemon=True).start()

    def _lold_check_worker(self, r):
        try:
            lookup = self._fetch_loldrivers()
            sha256 = r["sha256"].lower()
            sha1   = r["sha1"].lower()
            md5    = r["md5"].lower()
            match_uuid = lookup.get(sha256) or lookup.get(sha1) or lookup.get(md5)
            self.root.after(0, lambda: self._show_lold_result(r, match_uuid))
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"LOLDrivers check failed: {e}"))

    def _fetch_loldrivers(self):
        now = time.time()
        if self._lold_cache and (now - self._lold_cache_ts) < 3600:
            return self._lold_cache
        req = urllib.request.Request(
            LOLDRIVERS_API_URL,
            headers={"User-Agent": "DriverScanner-LOLDriversResearch/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        lookup = {}
        for driver in data:
            uid = driver.get("Id", "")
            for sample in driver.get("KnownVulnerableSamples", []):
                for key in ("MD5", "SHA1", "SHA256"):
                    h = (sample.get(key) or "").lower().strip()
                    if h:
                        lookup[h] = uid
        self._lold_cache    = lookup
        self._lold_cache_ts = now
        return lookup

    def _show_lold_result(self, r, match_uuid):
        self.detail_text.configure(state="normal")
        # Prepend the result line before any existing content
        if match_uuid:
            line = f"  ⚠ KNOWN in LOLDrivers — UUID: {match_uuid}\n"
            tag  = "lold_known"
        else:
            line = "  ✓ NOT in LOLDrivers database (as of this fetch)\n"
            tag  = "lold_clean"
        self.detail_text.insert("1.0", line, tag)
        self.detail_text.configure(state="disabled")
        self.status_var.set("LOLDrivers check complete.")

    # ── YAML export ────────────────────────────────────────────────────────────

    def _export_yaml(self):
        _, r = self._selected_result()
        if r is None:
            messagebox.showinfo("No selection", "Select a driver row first.")
            return
        yaml_str = self._build_yaml(r)

        dlg = tk.Toplevel(self.root)
        dlg.title(f"LOLDrivers YAML — {r['filename']}")
        dlg.configure(bg=BG)
        dlg.geometry("720x560")
        dlg.grab_set()

        tk.Label(dlg, text="Copy this YAML and submit as a PR to the LOLDrivers repo.",
                 font=("Courier New", 9), fg=TEXT_DIM, bg=BG).pack(anchor="w", padx=12, pady=(10, 4))

        txt_frame = tk.Frame(dlg, bg=BG, highlightthickness=1, highlightbackground=BORDER)
        txt_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        txt = tk.Text(txt_frame, bg=BG2, fg=TEXT, font=("Courier New", 9),
                      bd=0, relief="flat", wrap="none",
                      highlightthickness=0, insertbackground=ACCENT)
        sb_y = ttk.Scrollbar(txt_frame, orient="vertical",   command=txt.yview)
        sb_x = ttk.Scrollbar(txt_frame, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        txt.grid(row=0, column=0, sticky="nsew")
        sb_y.grid(row=0, column=1, sticky="ns")
        sb_x.grid(row=1, column=0, sticky="ew")
        txt_frame.grid_rowconfigure(0, weight=1)
        txt_frame.grid_columnconfigure(0, weight=1)

        txt.insert("1.0", yaml_str)
        txt.configure(state="disabled")

        btn_row = tk.Frame(dlg, bg=BG)
        btn_row.pack(fill="x", padx=12, pady=(0, 12))

        def copy_yaml():
            dlg.clipboard_clear()
            dlg.clipboard_append(yaml_str)
            self.status_var.set("YAML copied to clipboard.")

        def save_yaml():
            dest = filedialog.asksaveasfilename(
                parent=dlg,
                defaultextension=".yaml",
                initialfile=r["filename"].replace(".sys", ".yaml"),
                filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
                title="Save LOLDrivers YAML",
            )
            if dest:
                Path(dest).write_text(yaml_str, encoding="utf-8")
                self.status_var.set(f"YAML saved to {dest}")

        self._btn(btn_row, "📋  COPY TO CLIPBOARD", copy_yaml, ACCENT).pack(side="left", padx=(0, 8))
        self._btn(btn_row, "💾  SAVE TO FILE",      save_yaml,  GOLD  ).pack(side="left")
        self._btn(btn_row, "✕  CLOSE",              dlg.destroy, ACCENT2).pack(side="right")

    def _build_yaml(self, r):
        arch_map = {"x86": "x86", "x64": "AMD64", "ARM64": "ARM64"}
        machine  = arch_map.get(r["architecture"], r["architecture"])
        tags_yaml = "\n".join(f"  - {imp}" for imp in r["dangerous_imports"]) \
                    if r["dangerous_imports"] else '  - ""'
        created  = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        return (
            f"Id: {uuid.uuid4()}\n"
            f"Author: \"\"\n"
            f"Created: {created}\n"
            f"MitreID: T1068\n"
            f"Category: vulnerable_driver\n"
            f"Verified: false\n"
            f"Commands:\n"
            f"  Command: \"\"\n"
            f"  Description: \"\"\n"
            f"  Usecase: Exploit vulnerable driver\n"
            f"  Privileges: kernel\n"
            f"  OperatingSystem: Windows\n"
            f"Resources:\n"
            f"  - \"\"\n"
            f"Acknowledgements:\n"
            f"  - Name: \"\"\n"
            f"    Handle: \"\"\n"
            f"KnownVulnerableSamples:\n"
            f"  - Filename: {r['filename']}\n"
            f"    MD5: {r['md5']}\n"
            f"    SHA1: {r['sha1']}\n"
            f"    SHA256: {r['sha256']}\n"
            f"    Signature: {r['company'] or ''}\n"
            f"    Date: {r['compile_timestamp']}\n"
            f"    Publisher: {r['company'] or ''}\n"
            f"    Description: {r['description'] or ''}\n"
            f"    FileVersion: \"\"\n"
            f"    MachineType: {machine}\n"
            f"    OriginalFilename: {r['original_filename'] or r['filename']}\n"
            f"    InternalName: \"\"\n"
            f"    Copyright: \"\"\n"
            f"    Authentihash:\n"
            f"      MD5: \"\"\n"
            f"      SHA1: \"\"\n"
            f"      SHA256: \"\"\n"
            f"Tags:\n"
            f"{tags_yaml}\n"
        )

    # ── Actions ────────────────────────────────────────────────────────────────

    def _export_csv(self):
        if not self.all_results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            title="Save results as CSV"
        )
        if not path:
            return
        # Export only rows currently visible in the tree (respects active filters)
        visible_idxs = [int(iid[1:]) for iid in self.tree.get_children()]
        fields = ["filename", "path", "size_bytes", "architecture", "signed",
                  "compile_timestamp", "dangerous_imports", "device_names",
                  "symlinks", "pdb_path", "company", "description",
                  "original_filename", "md5", "sha1", "sha256", "error"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for idx in visible_idxs:
                row = dict(self.all_results[idx])
                row["dangerous_imports"] = "; ".join(row["dangerous_imports"])
                row["device_names"]      = "; ".join(row["device_names"])
                row["symlinks"]          = "; ".join(row["symlinks"])
                w.writerow(row)
        messagebox.showinfo("Exported", f"Saved {len(visible_idxs)} result(s) to:\n{path}")

    def _clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.all_results = []
        self.count_label.config(text="")
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.configure(state="disabled")
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.configure(state="disabled")
        self.status_var.set("Ready. Drop a folder or click Browse.")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if DND_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    app = DriverScannerApp(root)
    root.mainloop()
