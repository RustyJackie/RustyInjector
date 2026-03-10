"""
core/shellcode.py — Position-independent x86_64 shellcode stubs.

All stubs end with INT3 (0xCC) so the injector can catch execution
completion via SIGTRAP without needing a separate breakpoint mechanism.
"""

import struct


# ── mmap stub ─────────────────────────────────────────────────────────────────
#
# Allocates a 4096-byte RWX scratch page via mmap(2).
# RAX holds the returned address when we hit INT3.
#
#   mov  rax, 9       ; SYS_mmap
#   xor  rdi, rdi     ; addr   = NULL
#   mov  rsi, 0x1000  ; len    = 4096
#   mov  rdx, 7       ; prot   = PROT_READ|PROT_WRITE|PROT_EXEC
#   mov  r10, 0x22    ; flags  = MAP_PRIVATE|MAP_ANONYMOUS
#   mov  r8,  -1      ; fd     = -1
#   xor  r9,  r9      ; offset = 0
#   syscall
#   int3

MMAP_STUB = bytes([
    0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,   # mov  rax, 9
    0x48, 0x31, 0xFF,                             # xor  rdi, rdi
    0x48, 0xC7, 0xC6, 0x00, 0x10, 0x00, 0x00,   # mov  rsi, 0x1000
    0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00,   # mov  rdx, 7
    0x49, 0xC7, 0xC2, 0x22, 0x00, 0x00, 0x00,   # mov  r10, 0x22
    0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF,   # mov  r8, -1
    0x4D, 0x31, 0xC9,                            # xor  r9, r9
    0x0F, 0x05,                                  # syscall
    0xCC,                                        # int3
])  # 44 bytes


def build_dlopen_stub(dlopen_addr: int, lib_path: bytes) -> bytes:
    """
    Build a stub that calls dlopen(lib_path, RTLD_NOW) then INT3.

    Layout:
      [0 ]  movabs rax, <dlopen_addr>   10 bytes
      [10]  lea    rdi, [rip + 8]        7 bytes  (points to path string below)
      [17]  mov    esi, 2                5 bytes  (RTLD_NOW)
      [22]  call   rax                   2 bytes
      [24]  int3                         1 byte
      [25]  <lib_path>\\x00              variable
    """
    sc  = b"\x48\xB8" + struct.pack("<Q", dlopen_addr)   # movabs rax
    sc += b"\x48\x8D\x3D" + struct.pack("<i", 8)         # lea rdi, [rip+8]
    sc += b"\xBE\x02\x00\x00\x00"                        # mov esi, 2
    sc += b"\xFF\xD0"                                     # call rax
    sc += b"\xCC"                                         # int3
    sc += lib_path + b"\x00"
    return sc


def build_munmap_stub(addr: int, size: int = 4096) -> bytes:
    """
    Build a stub that calls munmap(addr, size) then INT3.
    Used to clean up the RWX scratch page after injection.

      mov  rax, 11        ; SYS_munmap
      movabs rdi, <addr>
      mov  rsi, <size>
      syscall
      int3
    """
    return (
        b"\x48\xC7\xC0\x0B\x00\x00\x00"
        + b"\x48\xBF" + struct.pack("<Q", addr)
        + b"\x48\xC7\xC6" + struct.pack("<I", size)
        + b"\x0F\x05"
        + b"\xCC"
    )  # 26 bytes


def build_zero_stub(addr: int, size: int) -> bytes:
    """
    Build a stub that zeroes [addr, addr+size) with REP STOSQ, then INT3.
    Used to wipe shellcode residue from the target's memory before munmap.

      xor  rax, rax
      movabs rdi, <addr>
      mov  rcx, <size // 8>
      rep stosq
      int3
    """
    count = (size + 7) // 8
    return (
        b"\x48\x31\xC0"                                    # xor rax, rax
        + b"\x48\xBF" + struct.pack("<Q", addr)             # movabs rdi, addr
        + b"\x48\xB9" + struct.pack("<Q", count)            # movabs rcx, count
        + b"\xF3\x48\xAB"                                   # rep stosq
        + b"\xCC"                                           # int3
    )  # 27 bytes
