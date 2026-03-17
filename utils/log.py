"""
utils/log.py — ANSI colours, output helpers, in-memory log, spinner.
"""

import atexit
import sys
import time
import threading
from typing import IO, List, Optional

# ── Global state ──────────────────────────────────────────────────────────────
_SILENT: bool = False
_log_entries: List[str] = []
_log_file: Optional[str] = None
_log_fh: Optional[IO[str]] = None   # kept open for the lifetime of the run

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


def configure(silent: bool = False, log_file: Optional[str] = None) -> None:
    """
    Set global output preferences. Call once early in main() before any
    logging happens — colour codes, silent mode, and the log file handle
    are all initialised here.
    """
    global _SILENT, _log_file, _log_fh
    _SILENT  = silent
    _log_file = log_file

    if log_file:
        try:
            _log_fh = open(log_file, "a", buffering=1)   # line-buffered
            atexit.register(_close_log)
        except OSError:
            _log_fh = None

    # Recompute ANSI colour codes after updating silent/log settings.
    setup_colors()


def _close_log() -> None:
    global _log_fh
    if _log_fh is not None:
        try:
            _log_fh.close()
        except OSError:
            pass
        _log_fh = None


# ── Custom exception ──────────────────────────────────────────────────────────
class InjectionError(Exception):
    pass


# ── Internal log writer ───────────────────────────────────────────────────────
def _log(level: str, msg: str) -> None:
    entry = f"{time.strftime('%H:%M:%S')}  {level:<7}  {msg}"
    _log_entries.append(entry)
    if _log_fh is not None:
        try:
            _log_fh.write(entry + "\n")
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
class _Spinner:
    """
    Non-blocking spinner that runs in a background thread so it doesn't
    hold up the caller while waiting on ptrace/GDB.
    """
    _frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, label: str) -> None:
        self._label  = label
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self._frames[i % len(self._frames)]
            print(f"\r  {C}{frame}{RST}  {self._label}", end="", flush=True)
            i += 1
            self._stop.wait(0.08)
        # erase the spinner line
        print("\r" + " " * (len(self._label) + 8) + "\r", end="", flush=True)

    def start(self) -> "_Spinner":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join()


def spinner(label: str, duration: float = 1.2) -> None:
    """Show a spinner for *duration* seconds. Blocking, but fine for short pre-checks."""
    if _SILENT or not sys.stdout.isatty():
        return
    s = _Spinner(label).start()
    s._stop.wait(duration)
    s.stop()
