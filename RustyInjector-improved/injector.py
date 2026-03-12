#!/usr/bin/env python3
"""
d8888b. db    db .d8888. d888888b db    db      d888888b d8b   db    d88b d88888b  .o88b. d888888b  .d88b.  d8888b.
88  `8D 88    88 88'  YP `~~88~~' `8b  d8'        `88'   888o  88    `8P' 88'     d8P  Y8 `~~88~~' .8P  Y8. 88  `8D
88oobY' 88    88 `8bo.      88     `8bd8'          88    88V8o 88     88  88ooooo 8P         88    88    88 88oobY'
88`8b   88    88   `Y8b.    88       88            88    88 V8o88     88  88~~~~~ 8b         88    88    88 88`8b
88 `88. 88b  d88 db   8D    88       88           .88.   88  V888 db. 88  88.     Y8b  d8    88    `8b  d8' 88 `88.
88   YD ~Y8888P' `8888Y'    YP       YP         Y888888P VP   V8P Y8888P  Y88888P  `Y88P'    YP     `Y88P'  88   YD

    Rusty Injector  ·  Stealth Edition
    ─────────────────────────────────────────────────────────────────────────
    Primary  : direct ptrace(2) via ctypes — no GDB, no temp files,
               no child processes visible in ps.
    Fallback : --method gdb  (any architecture, less stealthy)
    ─────────────────────────────────────────────────────────────────────────
    Architecture : x86_64 Linux  (ptrace method)
    Requires     : root
    WARNING      : Authorized / educational use only.
"""

import os
import sys
import argparse
import textwrap
from pathlib import Path

import utils.log as _log_mod
from utils.log import ok, info, warn, err, die, setup_colors, spinner, InjectionError
from utils.log import BOLD, DIM, G, R, W, RST
import utils.signals as _signals
from utils.preflight import preflight, resolve_pid, validate_library, verify_injection
from core.stealth import (
    mask_process_comm,
    restore_process_comm,
    check_target_seccomp,
    check_selinux_apparmor,
    memfd_stage,
)
from core.ptrace import PtraceInjector
from core.gdb import inject_via_gdb


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="injector.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Inject a shared library (.so) into a running Linux process.

            Default method: direct ptrace(2) — no GDB, no temp files,
            no child processes visible in ps.  x86_64 only.

            Use --method gdb as a fallback for other architectures.
        """),
        epilog=textwrap.dedent("""\
            examples:
              sudo python3 injector.py nginx        /tmp/hook.so
              sudo python3 injector.py --pid 1337   /tmp/hook.so
              sudo python3 injector.py nginx        /tmp/hook.so --memfd --verify
              sudo python3 injector.py nginx        /tmp/hook.so --method gdb
              sudo python3 injector.py nginx        /tmp/hook.so --silent --log /tmp/run.log
              sudo python3 injector.py nginx        /tmp/hook.so --dry-run
        """),
    )

    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("process_name", nargs="?",
                        help="Target process name (e.g. nginx)")
    target.add_argument("--pid", type=int,
                        help="Target PID directly (overrides process_name)")

    p.add_argument("library",
                   help="Path to the .so file to inject")

    p.add_argument("--method", choices=["ptrace", "gdb"], default="ptrace",
                   help="Injection backend (default: ptrace)")
    p.add_argument("--memfd", action="store_true",
                   help="Stage library via memfd_create — "
                        "hides real path from target /proc/pid/maps")
    p.add_argument("--mask-comm", metavar="NAME", nargs="?",
                   const="kworker/0:0", default=None,
                   help="Disguise our process name in ps/top (default: kworker/0:0)")
    p.add_argument("--verify", action="store_true",
                   help="Check /proc/pid/maps after injection to confirm success")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen without actually injecting")
    p.add_argument("--silent", action="store_true",
                   help="Suppress all stdout/stderr output (log only)")
    p.add_argument("--abort-on-monitors", action="store_true",
                   help="Exit immediately if monitoring tools are detected")
    p.add_argument("--no-root-check", action="store_true",
                   help="Skip root privilege check (dangerous)")
    p.add_argument("--log", metavar="PATH", default=None,
                   help="Write log entries to file (default: in-memory only)")

    return p


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print()

    parser = build_parser()
    args   = parser.parse_args()

    # Wire up silent mode, log file, and colours before any output
    _log_mod.configure(silent=args.silent, log_file=args.log)
    setup_colors()

    # Register signal handlers for clean detach on interrupt
    _signals.register_handlers()

    # Optionally mask our process name in ps
    original_comm = Path("/proc/self/comm").read_text().strip()
    if args.mask_comm:
        mask_process_comm(args.mask_comm)
        info(f"Process comm masked as  {DIM}'{args.mask_comm[:15]}'{RST}")

    preflight(
        method            = args.method,
        require_root      = not args.no_root_check,
        abort_on_monitors = args.abort_on_monitors,
    )

    library = validate_library(args.library)
    pid     = resolve_pid(args)      # int from here on

    sec = check_target_seccomp(pid)
    if sec is not None and sec > 0:
        warn(f"Target has seccomp mode={sec} — mmap(PROT_EXEC) might be blocked.")

    mac = check_selinux_apparmor(pid)
    if mac:
        warn(f"Target has MAC profile: {mac}")

    # Optional memfd staging
    memfd_fd    = None
    inject_path = library
    used_memfd  = False

    if args.memfd and not args.dry_run:
        try:
            staged, memfd_fd = memfd_stage(library)
            inject_path = Path(staged)
            used_memfd  = True
            ok(f"Library staged via memfd  {DIM}→ {staged}{RST}")
        except OSError as exc:
            warn(f"memfd staging failed ({exc}), falling back to direct path.")

    # Injection
    success = False
    try:
        if args.dry_run:
            warn(f"[DRY RUN] Would inject  {W}{inject_path}{RST}  into PID {W}{pid}{RST}")
            warn(f"          Method: {args.method}" + ("  +memfd" if args.memfd else ""))
            success = True

        elif args.method == "ptrace":
            spinner(f"Injecting  {library.name}  into PID {pid}", duration=0.4)
            injector = PtraceInjector(pid)
            injector.inject(inject_path)
            success = True

        else:
            success = inject_via_gdb(pid, inject_path)

    except InjectionError as exc:
        err(str(exc))

    finally:
        if memfd_fd is not None:
            try:
                os.close(memfd_fd)
            except OSError:
                pass
        if args.mask_comm:
            restore_process_comm(original_comm)

    # Post-injection verification
    if success and args.verify and not args.dry_run:
        verify_injection(pid, library, used_memfd)

    # Result
    log_hint = f"  {DIM}Log: {_log_mod._log_file}{RST}" if _log_mod._log_file else ""
    if success:
        if not args.silent:
            print(f"\n  {BOLD}{G}Done.{RST}{log_hint}\n")
    else:
        if not args.silent:
            print(
                f"\n  {R}Injection failed.{RST}"
                + (f"  See {DIM}{_log_mod._log_file}{RST}" if _log_mod._log_file else "") + "\n"
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
