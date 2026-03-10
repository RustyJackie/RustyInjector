"""
utils/log.py — ANSI colours, output helpers, in-memory log, spinner.
"""

import sys
import time
import random
from typing import List, Optional

# ── Global flags ──────────────────────────────────────────────────────────────
_SILENT: bool = False
_log_entries: List[str] = []
_log_file: Optional[str] = None

# ── ANSI colour palette ───────────────────────────────────────────────────────
R = G = Y = B = C = W = DIM = BOLD = RST = ""


def setup_colors() -> None:
    global R, G, Y, B, C, W, DIM, BOLD, RST
    on = sys.stdout.isatty() and not _SILENT
    R    = "\033[91m" if on else ""
    G    = "\033[92m" if on else ""
    Y    = "\033[93m" if on else ""
    B    = "\033[94m" if on else ""
    C    = "\033[96m" if on else ""
    W    = "\033[97m" if on else ""
    DIM  = "\033[2m"  if on else ""
    BOLD = "\033[1m"  if on else ""
    RST  = "\033[0m"  if on else ""


setup_colors()


# ── Custom exception ──────────────────────────────────────────────────────────
class InjectionError(Exception):
    pass


# ── Internal log writer ───────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    entry = f"{time.strftime('%H:%M:%S')}  {level:<7}  {msg}"
    _log_entries.append(entry)
    if _log_file:
        try:
            with open(_log_file, "a") as fh:
                fh.write(entry + "\n")
        except OSError:
            pass


# ── Public output functions ───────────────────────────────────────────────────
def ok(msg: str) -> None:
    if not _SILENT:
        print(f"  {G}[✔]{RST} {msg}")
    _log("INFO", msg)


def info(msg: str) -> None:
    if not _SILENT:
        print(f"  {B}[·]{RST} {msg}")
    _log("DEBUG", msg)


def warn(msg: str) -> None:
    if not _SILENT:
        print(f"  {Y}[!]{RST} {msg}")
    _log("WARNING", msg)


def err(msg: str) -> None:
    if not _SILENT:
        print(f"  {R}[✘]{RST} {BOLD}{msg}{RST}")
    _log("ERROR", msg)


def die(msg: str, code: int = 1) -> None:
    err(msg)
    sys.exit(code)


# ── Spinner ───────────────────────────────────────────────────────────────────
def spinner(label: str, duration: float = 1.2) -> None:
    if _SILENT or not sys.stdout.isatty():
        return
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    deadline = time.monotonic() + duration
    i = 0
    try:
        while time.monotonic() < deadline:
            print(f"\r  {C}{frames[i % len(frames)]}{RST}  {label}", end="", flush=True)
            time.sleep(0.08)
            i += 1
    finally:
        print("\r" + " " * (len(label) + 8) + "\r", end="", flush=True)
