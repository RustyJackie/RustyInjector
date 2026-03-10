"""
utils/signals.py — SIGINT / SIGTERM handlers that guarantee clean detach.

We keep a module-level reference to the active injector so the signal
handler can call detach() even if the main thread is blocked in waitpid().
"""

import sys
import signal as _signal
from typing import TYPE_CHECKING, Optional

from utils.log import _log, warn

if TYPE_CHECKING:
    from core.ptrace import PtraceInjector

# Set by PtraceInjector.inject() before attaching, cleared after detach.
_active_injector: Optional["PtraceInjector"] = None


def _sigint_handler(sig, frame) -> None:
    print(f"\n\n  Interrupted — detaching cleanly.\n")
    _log("WARNING", "Caught SIGINT")
    if _active_injector and _active_injector._attached:
        _active_injector.detach()
    sys.exit(130)


def _sigterm_handler(sig, frame) -> None:
    """
    If we're killed after attaching but before detaching, the target
    would stay frozen indefinitely. This ensures we always leave it runnable.
    """
    _log("WARNING", "Caught SIGTERM — force-detaching")
    if _active_injector and _active_injector._attached:
        _active_injector.detach()
    sys.exit(143)


def register_handlers() -> None:
    _signal.signal(_signal.SIGINT,  _sigint_handler)
    _signal.signal(_signal.SIGTERM, _sigterm_handler)
