#!/usr/bin/env python3
"""
Driver Scanner GUI — LOLDrivers Research Tool
Drag a folder onto the window or click Browse to scan recursively for .sys files.
Also extracts and scans .zip, .cab, .exe, .msi, .7z, .rar archives.

Requirements:
    pip install pefile tkinterdnd2
Optional (for exe/msi/7z/rar extraction):
    7-Zip installed (https://7-zip.org) — auto-detected from PATH or default install locations.
"""

import os
import csv
import sys
import json
import time
import uuid
import shutil
import hashlib
import zipfile
import threading
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from datetime import datetime, timezone

try:
    import pefile
except ImportError:
    import subprocess as _sp
    _sp.check_call([sys.executable, "-m", "pip", "install", "pefile", "--break-system-packages"])
    import pefile

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

DANGEROUS_IMPORTS = [
    # Physical memory access
    "MmMapIoSpace", "MmMapIoSpaceEx",
    "MmGetPhysicalAddress", "MmCopyMemory",
    "MmAllocateContiguousMemory", "MmAllocateContiguousMemorySpecifyCache",
    # Section/view mapping
    "ZwMapViewOfSection", "ZwOpenSection",
    # Bus / hardware access
    "HalTranslateBusAddress", "HalGetBusDataByOffset", "HalSetBusDataByOffset",
    # Port I/O — 8, 16 and 32-bit variants
    "READ_PORT_UCHAR",  "WRITE_PORT_UCHAR",
    "READ_PORT_USHORT", "WRITE_PORT_USHORT",
    "READ_PORT_ULONG",  "WRITE_PORT_ULONG",
    # Kernel object / SSDT manipulation
    "ObReferenceObjectByName", "KeServiceDescriptorTable",
    # Driver loading and debug control (highest severity)
    "ZwLoadDriver", "ZwSystemDebugControl",
]

# Severity scores for dangerous imports (higher = more dangerous)
IMPORT_SEVERITY = {
    "ZwLoadDriver":                         10,
    "MmMapIoSpace":                         10,
    "MmMapIoSpaceEx":                       10,
    "ZwSystemDebugControl":                  9,
    "MmCopyMemory":                          9,
    "MmGetPhysicalAddress":                  9,
    "ZwMapViewOfSection":                    9,
    "KeServiceDescriptorTable":              8,
    "ObReferenceObjectByName":               7,
    "HalTranslateBusAddress":                6,
    "ZwOpenSection":                         6,
    "HalGetBusDataByOffset":                 5,
    "HalSetBusDataByOffset":                 5,
    "MmAllocateContiguousMemory":            4,
    "MmAllocateContiguousMemorySpecifyCache":4,
    "WRITE_PORT_UCHAR":                      3,
    "WRITE_PORT_USHORT":                     3,
    "WRITE_PORT_ULONG":                      3,
    "READ_PORT_UCHAR":                       2,
    "READ_PORT_USHORT":                      2,
    "READ_PORT_ULONG":                       2,
}

def _import_severity_score(imports):
    """Return the max severity score across a list of import names."""
    return max((IMPORT_SEVERITY.get(n, 1) for n in imports), default=0)

ARCHIVE_EXTENSIONS = {".zip", ".cab", ".exe", ".msi", ".7z", ".rar", ".iso"}

LOLDRIVERS_API_URL = "https://www.loldrivers.io/api/drivers.json"

# ── Archive helpers ────────────────────────────────────────────────────────────

def find_7zip():
    """Return path to 7z.exe or None."""
    found = shutil.which("7z") or shutil.which("7za")
    if found:
        return found
    for candidate in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]:
        if Path(candidate).exists():
            return candidate
    return None

def _7z_contains_sys(archive_path, seven_zip):
    """Return True if the archive listing contains at least one .sys entry."""
    try:
        result = subprocess.run(
            [seven_zip, "l", str(archive_path)],
            capture_output=True, timeout=30,
        )
        return b".sys" in result.stdout.lower()
    except Exception:
        return True  # assume yes on error — better to over-extract than skip

def extract_archive(archive_path, dest_dir, seven_zip=None):
    """
    Extract only .sys files from archive_path into dest_dir.
    Returns (list[Path], error_str).
    """
    suffix = archive_path.suffix.lower()
    error  = ""
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(archive_path) as zf:
                members = [m for m in zf.namelist()
                           if m.lower().endswith((".sys", ".cat"))]
                if not any(m.lower().endswith(".sys") for m in members):
                    return [], ""
                for member in members:
                    zf.extract(member, dest_dir)

        elif suffix == ".cab":
            for pattern in ("*.sys", "*.cat"):
                subprocess.run(
                    ["expand.exe", str(archive_path), f"-F:{pattern}", str(dest_dir)],
                    capture_output=True, timeout=60,
                )

        elif seven_zip:
            # Quick listing pass — skip archive entirely if no .sys present
            if not _7z_contains_sys(archive_path, seven_zip):
                return [], ""
            result = subprocess.run(
                [seven_zip, "x", str(archive_path), f"-o{dest_dir}",
                 "-y", "-r", "*.sys", "*.cat", "-mmt=on"],
                capture_output=True, timeout=300,
            )
            if result.returncode not in (0, 1):
                error = result.stderr.decode(errors="ignore").strip() or f"7z exit {result.returncode}"

        else:
            error = f"No extractor for {suffix} (install 7-Zip)"

    except Exception as e:
        error = str(e)

    sys_files = sorted(Path(dest_dir).rglob("*.sys")) if not error else []
    return sys_files, error

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

def analyze_driver(path, source_archive=""):
    r = {
        "path": str(path), "filename": path.name,
        "size_bytes": path.stat().st_size,
        "md5": "", "sha1": "", "sha256": "",
        "signed": False, "sign_type": "",   # "embedded", "catalog", or ""
        "compile_timestamp": "",
        "architecture": "", "dangerous_imports": [],
        "device_names": [], "symlinks": [],
        "pdb_path": "", "company": "", "description": "",
        "original_filename": "", "source_archive": source_archive,
        "error": "",
    }
    try:
        r["md5"], r["sha1"], r["sha256"] = hash_file(path)
        with open(path, "rb") as f:
            raw = f.read()
        pe = pefile.PE(data=raw, fast_load=False)
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            r["signed"]    = True
            r["sign_type"] = "embedded"
        elif any(path.parent.glob("*.cat")):
            r["signed"]    = True
            r["sign_type"] = "catalog"
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
                                if key == "CompanyName":      r["company"] = val
                                elif key == "FileDescription": r["description"] = val
                                elif key == "OriginalFilename": r["original_filename"] = val
        ascii_strs = extract_ascii_strings(raw)
        for s in ascii_strs:
            if ".pdb" in s.lower():
                r["pdb_path"] = s; break
        seen_devs = set()
        seen_syms = set()
        for s in ascii_strs:
            if "\\Device\\" in s and s not in seen_devs:
                r["device_names"].append(s); seen_devs.add(s)
            elif ("\\DosDevices\\" in s or "\\??\\" in s) and s not in seen_syms:
                r["symlinks"].append(s); seen_syms.add(s)
        for s in extract_unicode_strings(raw):
            if "\\Device\\" in s and s not in seen_devs:
                r["device_names"].append(s); seen_devs.add(s)
            elif ("\\DosDevices\\" in s or "\\??\\" in s) and s not in seen_syms:
                r["symlinks"].append(s); seen_syms.add(s)
        pe.close()
    except Exception as e:
        r["error"] = str(e)
    r["severity_score"] = _import_severity_score(r["dangerous_imports"])
    return r

# ── GUI ────────────────────────────────────────────────────────────────────────

class DriverScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Driver Scanner — LOLDrivers Research")
        self.root.configure(bg=BG)
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)

        self.all_results     = []
        self._temp_dirs      = []   # cleaned up on Clear or window close
        self._elapsed_running = False
        self._elapsed_start   = 0.0
        self.scan_thread     = None
        self.signed_only    = tk.BooleanVar(value=False)
        self.dangerous_only = tk.BooleanVar(value=False)

        self._lold_cache    = None
        self._lold_cache_ts = 0.0

        self._build_ui()

        self.signed_only.trace_add("write", self._apply_filters)
        self.dangerous_only.trace_add("write", self._apply_filters)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if DND_AVAILABLE:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_drop)

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG, pady=14)
        header.pack(fill="x", padx=20)
        tk.Label(header, text="[ DRIVER SCANNER ]", font=("Courier New", 18, "bold"),
                 fg=ACCENT, bg=BG).pack(side="left")
        tk.Label(header, text="LOLDrivers Research Tool", font=("Courier New", 10),
                 fg=TEXT_DIM, bg=BG).pack(side="left", padx=12, pady=4)
        tk.Frame(self.root, bg=ACCENT, height=1).pack(fill="x", padx=20)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=12)

        left = tk.Frame(body, bg=BG, width=280)
        left.pack(side="left", fill="y", padx=(0, 14))
        left.pack_propagate(False)
        self._build_left(left)

        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self._build_right(right)

        self.status_var = tk.StringVar(value="Ready. Drop a folder or click Browse.")
        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x")
        status_bar = tk.Frame(self.root, bg=BG2, pady=6)
        status_bar.pack(fill="x")
        tk.Label(status_bar, textvariable=self.status_var, font=("Courier New", 9),
                 fg=TEXT_DIM, bg=BG2, anchor="w").pack(side="left", padx=14)
        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=200)
        self.progress.pack(side="right", padx=14)
        self.elapsed_label = tk.Label(status_bar, text="", font=("Courier New", 9),
                                      fg=GOLD, bg=BG2, width=6, anchor="e")
        self.elapsed_label.pack(side="right")

    def _build_left(self, parent):
        drop_frame = tk.Frame(parent, bg=BG3, bd=0, highlightthickness=2,
                              highlightbackground=BORDER)
        drop_frame.pack(fill="x", pady=(0, 12))
        self.drop_zone = tk.Label(
            drop_frame, text="⬇  DROP FOLDER HERE",
            font=("Courier New", 11, "bold"),
            fg=ACCENT if DND_AVAILABLE else TEXT_DIM,
            bg=BG3, pady=28, cursor="hand2" if DND_AVAILABLE else "arrow",
        )
        self.drop_zone.pack(fill="x")
        if not DND_AVAILABLE:
            tk.Label(drop_frame, text="(install tkinterdnd2 to enable)", font=("Courier New", 8),
                     fg=TEXT_DIM, bg=BG3).pack(pady=(0, 8))

        self._btn(parent, "📂  BROWSE FOLDER", self._browse, ACCENT).pack(fill="x", pady=(0, 8))

        filt = tk.LabelFrame(parent, text=" FILTERS ", font=("Courier New", 9, "bold"),
                             fg=TEXT_DIM, bg=BG, bd=1, highlightthickness=0,
                             relief="flat", highlightbackground=BORDER)
        filt.pack(fill="x", pady=(4, 12))
        self._check(filt, "Signed only  (recommended)", self.signed_only)
        self._check(filt, "Dangerous imports only", self.dangerous_only)

        self._btn(parent, "💾  EXPORT CSV",       self._export_csv,       GOLD   ).pack(fill="x", pady=(0, 8))
        self._btn(parent, "📋  EXPORT YAML",      self._export_yaml,      ACCENT ).pack(fill="x", pady=(0, 8))
        self._btn(parent, "🔍  CHECK LOLDRIVERS", self._check_loldrivers, GREEN  ).pack(fill="x", pady=(0, 8))
        self._btn(parent, "🗑  CLEAR RESULTS",    self._clear,            ACCENT2).pack(fill="x")

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=12)
        tk.Label(parent, text="SUMMARY", font=("Courier New", 9, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(anchor="w")
        self.summary_text = tk.Text(parent, bg=BG2, fg=TEXT, font=("Courier New", 9),
                                    bd=0, relief="flat", height=12, state="disabled",
                                    highlightthickness=1, highlightbackground=BORDER)
        self.summary_text.pack(fill="both", expand=True, pady=(6, 0))

    def _build_right(self, parent):
        toolbar = tk.Frame(parent, bg=BG)
        toolbar.pack(fill="x", pady=(0, 8))
        tk.Label(toolbar, text="RESULTS", font=("Courier New", 10, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(side="left")
        self.count_label = tk.Label(toolbar, text="", font=("Courier New", 9),
                                    fg=ACCENT, bg=BG)
        self.count_label.pack(side="left", padx=10)

        cols       = ("priority", "filename", "arch", "signed", "danger", "company", "compiled", "sha256")
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

        self._sort_col      = None
        self._sort_reverse  = False

        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                 selectmode="browse", style="Treeview")
        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview, style="Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)

        for col, label, width in zip(cols, col_labels, col_widths):
            self.tree.heading(col, text=label,
                              command=lambda c=col: self._sort_by_col(c))
            self.tree.column(col, width=width, minwidth=30, anchor="w")

        self.tree.tag_configure("high",    background="#1a1200", foreground=GOLD)
        self.tree.tag_configure("danger",  background="#180a0a", foreground=ACCENT2)
        self.tree.tag_configure("signed",  background="#091510", foreground=GREEN)
        self.tree.tag_configure("normal",  background=BG2,       foreground=TEXT)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Button-3>", self._on_right_click)

        if DND_AVAILABLE:
            self.tree.drag_source_register(1, DND_FILES)
            self.tree.dnd_bind("<<DragInitCmd>>", self._on_drag_init)

        # Right-click context menu
        self.ctx_menu = tk.Menu(self.root, tearoff=0, bg=BG2, fg=TEXT,
                                activebackground=BG3, activeforeground=ACCENT,
                                font=("Courier New", 9), bd=0, relief="flat")
        self.ctx_menu.add_command(label="📋  Copy SHA256",             command=self._ctx_copy_sha256)
        self.ctx_menu.add_command(label="💾  Extract driver to…",      command=self._ctx_extract)
        self.ctx_menu.add_command(label="📂  Open containing folder",  command=self._ctx_open_folder)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="📋  Export YAML",             command=self._export_yaml)
        self.ctx_menu.add_command(label="🔍  Check LOLDrivers",        command=self._check_loldrivers)

        # Detail panel
        detail_frame = tk.Frame(parent, bg=BG2, highlightthickness=1, highlightbackground=BORDER)
        detail_frame.pack(fill="x", pady=(10, 0))
        tk.Label(detail_frame, text="DETAILS", font=("Courier New", 9, "bold"),
                 fg=TEXT_DIM, bg=BG2, pady=4, padx=8).pack(anchor="w")
        self.detail_text = tk.Text(detail_frame, bg=BG2, fg=TEXT, font=("Courier New", 9),
                                   bd=0, relief="flat", height=8,
                                   highlightthickness=0, state="disabled", wrap="none")
        det_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=det_scroll.set)
        self.detail_text.pack(side="left", fill="both", expand=True, padx=8, pady=(0, 8))
        det_scroll.pack(side="right", fill="y", pady=(0, 8))

        self.detail_text.tag_configure("key",        foreground=ACCENT)
        self.detail_text.tag_configure("value",      foreground=TEXT)
        self.detail_text.tag_configure("danger",     foreground=ACCENT2, font=("Courier New", 9, "bold"))
        self.detail_text.tag_configure("signed",     foreground=GREEN)
        self.detail_text.tag_configure("hash",       foreground=TEXT_DIM)
        self.detail_text.tag_configure("gold",       foreground=GOLD,    font=("Courier New", 9, "bold"))
        self.detail_text.tag_configure("archive",    foreground=GOLD)
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
        sel = self.tree.selection()
        if not sel:
            return None, None
        idx = int(sel[0][1:])
        if idx < len(self.all_results):
            return idx, self.all_results[idx]
        return None, None

    # ── Events ─────────────────────────────────────────────────────────────────

    # ── Elapsed time ticker ────────────────────────────────────────────────────

    def _start_elapsed_ticker(self):
        self._elapsed_running = True
        self._elapsed_start   = time.time()
        self._tick_elapsed()

    def _stop_elapsed_ticker(self):
        self._elapsed_running = False
        self.elapsed_label.config(text="")

    def _tick_elapsed(self):
        if not self._elapsed_running:
            return
        secs = int(time.time() - self._elapsed_start)
        if secs < 60:
            self.elapsed_label.config(text=f"{secs}s")
        else:
            self.elapsed_label.config(text=f"{secs // 60}m{secs % 60:02d}s")
        self.root.after(1000, self._tick_elapsed)

    # ── Events ─────────────────────────────────────────────────────────────────

    def _browse(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self._start_scan(folder)

    def _on_drag_init(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
        _, r = self._selected_result()
        if r is None:
            return ("refuse", DND_FILES, "")
        src = Path(r["path"])
        if not src.exists():
            self.status_var.set(f"Cannot drag: file not found — {src.name}")
            return ("refuse", DND_FILES, "")
        # Wrap path in braces if it contains spaces (Windows DND_FILES convention)
        path_str = f"{{{src}}}" if " " in str(src) else str(src)
        return ("copy", DND_FILES, path_str)

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

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.ctx_menu.post(event.x_root, event.y_root)

    # ── Right-click actions ────────────────────────────────────────────────────

    def _ctx_copy_sha256(self):
        _, r = self._selected_result()
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(r["sha256"])
            self.status_var.set(f"SHA256 copied: {r['sha256'][:20]}…")

    def _ctx_extract(self):
        _, r = self._selected_result()
        if r is None:
            return
        src = Path(r["path"])
        if not src.exists():
            messagebox.showerror("File not found",
                "The driver file is no longer accessible.\n"
                "It may have been in a temp folder that was cleared.\n\n"
                f"{src}")
            return
        dest = filedialog.asksaveasfilename(
            defaultextension=".sys",
            initialfile=r["filename"],
            filetypes=[("Driver files", "*.sys"), ("All files", "*.*")],
            title="Save driver to…",
        )
        if dest:
            shutil.copy2(str(src), dest)
            self.status_var.set(f"Driver saved to {dest}")

    def _ctx_open_folder(self):
        _, r = self._selected_result()
        if r is None:
            return
        folder = Path(r["path"]).parent
        if folder.exists():
            os.startfile(str(folder))
        else:
            messagebox.showwarning("Folder not found",
                "The containing folder no longer exists.\n"
                "Temp folders from archive extraction are cleared when you click Clear.\n\n"
                f"{folder}")

    # ── Filtering ──────────────────────────────────────────────────────────────

    def _passes_filter(self, r):
        if self.signed_only.get() and not r["signed"]:
            return False
        if self.dangerous_only.get() and not r["dangerous_imports"]:
            return False
        return True

    def _apply_filters(self, *_):
        for item in self.tree.get_children():
            self.tree.delete(item)
        rows = [(idx, r) for idx, r in enumerate(self.all_results) if self._passes_filter(r)]
        if self._sort_col:
            rows = self._sorted_rows(rows)
        for idx, r in rows:
            self._add_row(r, idx)
        self.count_label.config(text=f"{len(self.tree.get_children())} result(s)")

    def _sorted_rows(self, rows):
        col = self._sort_col
        rev = self._sort_reverse
        def key(pair):
            _, r = pair
            if col == "danger":
                return r.get("severity_score", 0)
            if col == "priority":
                return (1 if (r["signed"] and r["dangerous_imports"]) else 0)
            if col == "filename":
                return r["filename"].lower()
            if col == "arch":
                return r["architecture"]
            if col == "signed":
                return r["sign_type"]
            if col == "company":
                return (r["company"] or "").lower()
            if col == "compiled":
                return r["compile_timestamp"]
            if col == "sha256":
                return r["sha256"]
            return ""
        return sorted(rows, key=key, reverse=rev)

    def _sort_by_col(self, col):
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col     = col
            self._sort_reverse = col in ("danger", "priority")
        # Update heading arrows
        arrow_up   = " ▲"
        arrow_down = " ▼"
        for c in ("priority", "filename", "arch", "signed", "danger", "company", "compiled", "sha256"):
            label = dict(zip(
                ("priority", "filename", "arch", "signed", "danger", "company", "compiled", "sha256"),
                ("!", "Filename", "Arch", "Signed", "Dangerous Imports", "Company", "Compiled", "SHA256"),
            ))[c]
            if c == col:
                label += arrow_down if self._sort_reverse else arrow_up
            self.tree.heading(c, text=label)
        self._apply_filters()

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
        root         = Path(folder)
        extract_base = root / "_drvscan_extracted"

        # Exclude our own extraction folder from the direct .sys scan
        own_extract  = str(extract_base)
        sys_files    = sorted(
            p for p in root.rglob("*.sys")
            if not str(p).startswith(own_extract)
        )

        archives = sorted(set(
            p for ext in ARCHIVE_EXTENSIONS
            for p in root.rglob(f"*{ext}")
        ))

        if not sys_files and not archives:
            self.root.after(0, lambda: self.status_var.set("No .sys files or archives found."))
            self.root.after(0, self.progress.stop)
            return

        seven_zip = find_7zip()
        if archives and not seven_zip:
            self.root.after(0, lambda: self.status_var.set(
                "7-Zip not found — .exe/.msi/.7z/.rar skipped. .zip and .cab still work."))

        self.root.after(0, lambda: self.status_var.set(
            f"Found {len(sys_files)} driver(s), {len(archives)} archive(s)…"))

        # ── Phase 1: extract all archives in parallel (max 4 concurrent) ──────
        extracted_pairs = []   # (Path, source_archive_str)
        extract_errors  = []
        extract_lock    = threading.Lock()
        extract_done    = [0]

        if archives:
            extract_base.mkdir(exist_ok=True)
            if extract_base not in self._temp_dirs:
                self._temp_dirs.append(extract_base)

            n_arch = len(archives)
            self.root.after(0, lambda: [
                self.progress.stop(),
                self.progress.config(mode="determinate", maximum=n_arch, value=0),
                self._start_elapsed_ticker(),
            ])

            def _extract_one(archive):
                tmp = extract_base / archive.name
                tmp.mkdir(parents=True, exist_ok=True)
                try:
                    sys_found, err = extract_archive(archive, tmp, seven_zip)
                except Exception as e:
                    sys_found, err = [], str(e)
                with extract_lock:
                    extract_done[0] += 1
                    d = extract_done[0]
                self.root.after(0, lambda: self.progress.step(1))
                self.root.after(0, lambda d=d, t=n_arch, n=archive.name:
                    self.status_var.set(f"Extracting {d}/{t}: {n}"))
                return archive, sys_found, err

            with ThreadPoolExecutor(max_workers=min(4, n_arch)) as pool:
                for archive, sys_found, err in pool.map(_extract_one, archives):
                    if err:
                        extract_errors.append((archive, err))
                    else:
                        extracted_pairs.extend((p, str(archive)) for p in sys_found)

            self.root.after(0, self._stop_elapsed_ticker)

        # ── Phase 2: analyse all drivers in parallel (max 4 workers) ──────────
        # pefile is pure-Python CPU work; more than 4 threads increases GIL
        # contention and starves the tkinter main loop, causing visible freezes.
        all_jobs = [(p, "") for p in sys_files] + extracted_pairs
        total    = len(all_jobs)

        if total:
            self.root.after(0, lambda: [
                self.progress.stop(),
                self.progress.config(mode="determinate", maximum=total, value=0),
                self._start_elapsed_ticker(),
            ])

        results_lock  = threading.Lock()
        analyse_done  = [0]
        seen_sha256   = set()
        dedup_count   = [0]

        # Capture filter state once so background threads don't touch tkinter vars
        signed_only   = self.signed_only.get()
        dangerous_only = self.dangerous_only.get()

        def _passes(r):
            if signed_only   and not r["signed"]:           return False
            if dangerous_only and not r["dangerous_imports"]: return False
            return True

        update_every = max(1, total // 100)  # status text at most every 1% of total

        def _analyse_one(job):
            path, src = job
            r = analyze_driver(path, source_archive=src)
            with results_lock:
                analyse_done[0] += 1
                d = analyse_done[0]
                sha = r["sha256"]
                if sha and sha in seen_sha256:
                    dedup_count[0] += 1
                    self.root.after(0, lambda: self.progress.step(1))
                    return
                if sha:
                    seen_sha256.add(sha)
                idx = len(self.all_results)
                self.all_results.append(r)
            self.root.after(0, lambda: self.progress.step(1))
            if d % update_every == 0 or d == total:
                self.root.after(0, lambda d=d, t=total:
                    self.status_var.set(f"Analysing {d}/{t} drivers…"))
            if _passes(r):
                self.root.after(0, lambda r=r, idx=idx: self._add_row(r, idx))

        n_workers = min(os.cpu_count() or 4, 12)
        if total:
            with ThreadPoolExecutor(max_workers=n_workers) as pool:
                list(pool.map(_analyse_one, all_jobs))

        # Append extraction-error sentinels (not shown in tree, visible in summary)
        for archive, err in extract_errors:
            self.all_results.append({
                "path": str(archive), "filename": archive.name,
                "size_bytes": 0, "md5": "", "sha1": "", "sha256": "",
                "signed": False, "sign_type": "", "compile_timestamp": "", "architecture": "",
                "dangerous_imports": [], "device_names": [], "symlinks": [],
                "pdb_path": "", "company": "", "description": "",
                "original_filename": "", "source_archive": "",
                "severity_score": 0,
                "error": f"Extraction failed: {err}",
            })

        self.root.after(0, lambda: self._finish_scan(len(sys_files), len(archives), dedup_count[0]))

    def _finish_scan(self, direct_count, archive_count, dedup_count=0):
        self._stop_elapsed_ticker()
        self.progress.stop()
        results   = self.all_results
        embedded  = sum(1 for r in results if r.get("sign_type") == "embedded")
        catalog   = sum(1 for r in results if r.get("sign_type") == "catalog")
        signed    = embedded + catalog
        unsigned  = sum(1 for r in results if not r["signed"] and not r["error"])
        danger    = sum(1 for r in results if r["dangerous_imports"])
        high      = sum(1 for r in results if r["signed"] and r["dangerous_imports"])
        from_arch = sum(1 for r in results if r.get("source_archive"))
        errors    = sum(1 for r in results if r["error"])
        shown     = len(self.tree.get_children())

        dedup_str = f"  Dupes skipped: {dedup_count}" if dedup_count else ""
        self.status_var.set(
            f"Done — {shown} shown / {len(results)} unique  |  "
            f"Signed: {signed} ({embedded} emb / {catalog} cat)  "
            f"Dangerous: {danger}  🎯 Priority: {high}{dedup_str}"
        )
        self.count_label.config(text=f"{shown} result(s)")

        lines = [
            f"Direct .sys    {direct_count}",
            f"Archives       {archive_count}",
            f"From archives  {from_arch}",
            f"Dupes skipped  {dedup_count}",
            f"Unique results {len(results)}",
            f"Shown          {shown}",
            f"───────────────────────",
            f"Embedded ✓     {embedded}",
            f"Catalog  ✓     {catalog}",
            f"Unsigned       {unsigned}",
            f"───────────────────────",
            f"Dangerous      {danger}",
            f"───────────────────────",
            f"🎯 Priority    {high}",
        ]
        if errors:
            lines.append(f"⚠ Errors       {errors}")

        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        self.summary_text.insert("end", "\n".join(lines))
        self.summary_text.configure(state="disabled")

    def _add_row(self, r, idx):
        signed_str  = {"embedded": "YES ✓", "catalog": "CAT ✓"}.get(r["sign_type"], "no")
        sorted_imps = sorted(r["dangerous_imports"],
                             key=lambda n: IMPORT_SEVERITY.get(n, 1), reverse=True)
        danger_str  = ", ".join(sorted_imps) if sorted_imps else "—"
        priority    = "🎯" if (r["signed"] and r["dangerous_imports"]) else ""
        # Small marker for archive-extracted drivers
        filename   = f"[A] {r['filename']}" if r.get("source_archive") else r["filename"]

        tag = "normal"
        if r["signed"] and r["dangerous_imports"]: tag = "high"
        elif r["dangerous_imports"]:               tag = "danger"
        elif r["signed"]:                          tag = "signed"

        self.tree.insert("", "end", iid=f"r{idx}", tags=(tag,), values=(
            priority, filename, r["architecture"], signed_str,
            danger_str, r["company"] or "—", r["compile_timestamp"], r["sha256"],
        ))
        self.count_label.config(text=f"{len(self.tree.get_children())} result(s)")

    def _show_detail(self, r):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")

        def kv(key, val, tag="value"):
            self.detail_text.insert("end", f"  {key:<20}", "key")
            self.detail_text.insert("end", f"{val}\n", tag)

        if r["signed"] and r["dangerous_imports"]:
            self.detail_text.insert("end", "  🎯 HIGH PRIORITY — Signed + Dangerous Imports\n", "gold")

        if r.get("source_archive"):
            self.detail_text.insert("end", f"  📦 Extracted from: {r['source_archive']}\n", "archive")

        kv("File",          r["filename"])
        kv("Path",          r["path"])
        kv("Size",          f"{r['size_bytes']:,} bytes")
        kv("Architecture",  r["architecture"])
        kv("Compiled",      r["compile_timestamp"])
        kv("Company",       r["company"] or "—")
        kv("Description",   r["description"] or "—")
        kv("Original Name", r["original_filename"] or "—")
        sign_display = {"embedded": "YES — embedded Authenticode",
                        "catalog":  "YES — catalog signed (.cat)"}.get(r["sign_type"], "NO")
        kv("Signed", sign_display, "signed" if r["signed"] else "danger")

        if r["dangerous_imports"]:
            sorted_imps = sorted(r["dangerous_imports"],
                                 key=lambda n: IMPORT_SEVERITY.get(n, 1), reverse=True)
            kv("Dangerous Imports", ", ".join(sorted_imps), "danger")
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
            lookup    = self._fetch_loldrivers()
            match_uid = (lookup.get(r["sha256"].lower()) or
                         lookup.get(r["sha1"].lower()) or
                         lookup.get(r["md5"].lower()))
            self.root.after(0, lambda: self._show_lold_result(match_uid))
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

    def _show_lold_result(self, match_uuid):
        self.detail_text.configure(state="normal")
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
            dlg.clipboard_clear(); dlg.clipboard_append(yaml_str)
            self.status_var.set("YAML copied to clipboard.")

        def save_yaml():
            dest = filedialog.asksaveasfilename(
                parent=dlg, defaultextension=".yaml",
                initialfile=r["filename"].replace(".sys", ".yaml"),
                filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")],
                title="Save LOLDrivers YAML",
            )
            if dest:
                Path(dest).write_text(yaml_str, encoding="utf-8")
                self.status_var.set(f"YAML saved to {dest}")

        self._btn(btn_row, "📋  COPY TO CLIPBOARD", copy_yaml,   ACCENT ).pack(side="left", padx=(0, 8))
        self._btn(btn_row, "💾  SAVE TO FILE",      save_yaml,   GOLD   ).pack(side="left")
        self._btn(btn_row, "✕  CLOSE",              dlg.destroy, ACCENT2).pack(side="right")

    def _build_yaml(self, r):
        arch_map  = {"x86": "x86", "x64": "AMD64", "ARM64": "ARM64"}
        machine   = arch_map.get(r["architecture"], r["architecture"])
        tags_yaml = "\n".join(f"  - {imp}" for imp in r["dangerous_imports"]) \
                    if r["dangerous_imports"] else '  - ""'
        created   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
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

    # ── CSV export ─────────────────────────────────────────────────────────────

    def _export_csv(self):
        if not self.all_results:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")],
            title="Save results as CSV",
        )
        if not path:
            return
        visible_idxs = [int(iid[1:]) for iid in self.tree.get_children()]
        fields = ["filename", "source_archive", "path", "size_bytes", "architecture",
                  "signed", "compile_timestamp", "dangerous_imports", "device_names",
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

    # ── Clear ──────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._stop_elapsed_ticker()
        for tmp in self._temp_dirs:
            shutil.rmtree(tmp, ignore_errors=True)
        self._temp_dirs = []
        self.root.destroy()

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
        # Clean up temp dirs from archive extractions
        for tmp in self._temp_dirs:
            shutil.rmtree(tmp, ignore_errors=True)
        self._temp_dirs = []


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if DND_AVAILABLE:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()

    app = DriverScannerApp(root)
    root.mainloop()
