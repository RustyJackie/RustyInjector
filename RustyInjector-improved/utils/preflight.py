"""
utils/preflight.py — Preflight checks, PID resolution, library validation,
                     and post-injection verification.
"""

import os
import platform
import shutil
import sys
from pathlib import Path

from utils.log import ok, info, warn, err, die, DIM, W, RST
from core.stealth import check_monitors


def preflight(method: str, require_root: bool, abort_on_monitors: bool) -> None:
    info("Running preflight checks…")

    if require_root and os.geteuid() != 0:
        die(
            "Root privileges required.\n"
            f"      Run as:  {DIM}sudo python3 {sys.argv[0]} …{RST}"
        )

    if method == "ptrace" and platform.machine() != "x86_64":
        die(
            f"ptrace method requires x86_64, detected: {platform.machine()}\n"
            f"      Use --method gdb for other architectures."
        )

    if method == "gdb" and shutil.which("gdb") is None:
        die(
            "gdb not found — required for --method gdb.\n"
            f"      Install:  {DIM}sudo apt install gdb{RST}"
        )

    scope_file = Path("/proc/sys/kernel/yama/ptrace_scope")
    if scope_file.exists():
        scope = int(scope_file.read_text().strip())
        if scope >= 2:
            die(
                f"ptrace locked down (scope={scope}). Injection won't work.\n"
                f"      Fix:  {DIM}echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope{RST}"
            )
        elif scope == 1:
            warn(
                f"ptrace_scope=1 — may restrict attach to non-child processes.\n"
                f"      If it fails:  "
                f"{DIM}echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope{RST}"
            )

    monitors = check_monitors(abort_on_found=abort_on_monitors)
    if monitors:
        warn(f"Monitoring tool(s) detected: {', '.join(monitors)}")
        warn("Proceeding — your actions may be logged by these tools.")

    ok("Preflight passed.\n")


def _scan_proc_for_name(name: str) -> list:
    """
    Walk /proc and return all PIDs whose /proc/<pid>/comm matches *name*.
    Returns an empty list if nothing is found (no external tools needed).
    """
    matches = []
    try:
        # sort numerically so the lowest (oldest) PID comes first
        for entry in sorted(Path("/proc").iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else -1):
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text().strip()
                if comm == name:
                    matches.append(int(entry.name))
            except (OSError, ValueError):
                pass
    except PermissionError:
        pass
    return matches


def find_process_pid(process_name: str) -> int:
    info(f"Searching for process  {W}{process_name}{RST} …")

    pids = _scan_proc_for_name(process_name)

    if not pids:
        die(
            f"No running process named '{process_name}'.\n"
            f"      Check:  {DIM}pgrep -a {process_name}{RST}"
        )

    pid = pids[0]

    if len(pids) > 1:
        warn(
            f"Multiple instances: {', '.join(str(p) for p in pids)}\n"
            f"      Using PID {W}{pid}{RST} (oldest). Use --pid to override."
        )
    else:
        ok(f"Found PID  {W}{pid}{RST}")

    if not Path(f"/proc/{pid}").is_dir():
        die(f"PID {pid} vanished right after detection — race condition?")

    return pid


def resolve_pid(args) -> int:
    if args.pid:
        pid = args.pid
        if not Path(f"/proc/{pid}").is_dir():
            die(f"No process with PID {pid}.")
        ok(f"Using supplied PID  {W}{pid}{RST}")
        return pid
    return find_process_pid(args.process_name)


def validate_library(library_path: str) -> Path:
    p = Path(library_path).resolve()

    if not p.exists():
        die(f"Library not found: {p}")
    if not p.is_file():
        die(f"Not a regular file: {p}")
    if not os.access(p, os.R_OK):
        die(f"No read permission: {p}")

    with p.open("rb") as f:
        header = f.read(5)

    if header[:4] != b"\x7fELF":
        warn("File does not start with ELF magic — injection may fail.")
    else:
        bits = "64-bit" if header[4] == 2 else "32-bit"
        ok(f"Library validated  {DIM}({bits} ELF shared object){RST}")

    return p


def verify_injection(pid: int, library: Path, used_memfd: bool) -> None:
    """
    Check /proc/pid/maps for evidence that the library actually loaded.
    When memfd was used the real filename won't appear — we look for
    'memfd:' entries instead.
    """
    maps_file = Path(f"/proc/{pid}/maps")
    if not maps_file.exists():
        warn("Could not read /proc/<pid>/maps for verification.")
        return

    maps = maps_file.read_text()

    if used_memfd:
        if "memfd:" in maps:
            ok(f"memfd mapping confirmed in  {DIM}/proc/{pid}/maps{RST}  ✓")
        else:
            warn(
                "No 'memfd:' entry found in /proc/<pid>/maps.\n"
                "      dlopen() may have returned NULL silently.\n"
                "      Tip: check dmesg or run target with LD_DEBUG=libs."
            )
    else:
        if library.name in maps:
            ok(f"{W}{library.name}{RST} confirmed in  {DIM}/proc/{pid}/maps{RST}  ✓")
        else:
            warn(
                f"'{library.name}' not found in /proc/{pid}/maps.\n"
                "      dlopen() may have returned NULL or the library was unloaded immediately.\n"
                "      Common cause: missing symbol dependencies — check with ldd."
            )
