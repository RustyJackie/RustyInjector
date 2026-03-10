# Rusty Injector

A Python tool for injecting `.so` shared libraries into running Linux processes.

Primary method is direct **ptrace(2)** via ctypes — no GDB subprocess, no temp files, nothing extra visible in `ps`. GDB is available as a fallback for non-x86_64 targets.

---

## How it works

The injector attaches to the target process, allocates a small scratch page via `mmap`, writes a `dlopen()` shellcode stub into it, executes it, then cleans up — zeroes the scratch page, unmaps it, restores the original registers and detaches. The process keeps running as if nothing happened, with your library loaded into its memory space.

```
attach → mmap scratch page → write dlopen stub → execute → zero + munmap → restore → detach
```

---

## Requirements

- Linux x86_64 (ptrace method) / any arch (gdb method)
- Python 3
- `sudo` or root
- `gdb` — only if using `--method gdb`

> **Heads up:** Some distros block ptrace by default. If the script fails with a permissions error, try:
> ```bash
> echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
> ```

---

## Installation

```bash
git clone https://github.com/RustyJackie/RustyInjector.git
cd RustyInjector
chmod +x injector.py
```

---

## Usage

```bash
sudo python3 injector.py <process_name> <path_to_library.so>
sudo python3 injector.py --pid <pid>    <path_to_library.so>
```

### Examples

```bash
# Inject into a process by name
sudo python3 injector.py nginx /tmp/hook.so

# Inject into a specific PID
sudo python3 injector.py --pid 1337 /tmp/hook.so

# Hide library path from /proc/pid/maps via memfd
sudo python3 injector.py nginx /tmp/hook.so --memfd

# Verify injection succeeded by checking /proc/pid/maps
sudo python3 injector.py nginx /tmp/hook.so --verify

# Use GDB fallback (works on any architecture)
sudo python3 injector.py nginx /tmp/hook.so --method gdb

# Dry run — show what would happen without actually injecting
sudo python3 injector.py nginx /tmp/hook.so --dry-run

# Run silently and write log to file
sudo python3 injector.py nginx /tmp/hook.so --silent --log /tmp/inject.log
```

### All options

| Flag | Description |
|------|-------------|
| `--pid <n>` | Target by PID instead of process name |
| `--method ptrace\|gdb` | Injection backend (default: ptrace) |
| `--memfd` | Stage library in memfd — hides real path from target's `/proc/pid/maps` |
| `--mask-comm [NAME]` | Disguise injector process name in `ps`/`top` (default: `kworker/0:0`) |
| `--verify` | Check `/proc/pid/maps` after injection to confirm the library loaded |
| `--dry-run` | Show what would happen without injecting |
| `--silent` | Suppress all output |
| `--log PATH` | Write log entries to a file |
| `--abort-on-monitors` | Exit if monitoring tools (strace, auditd, etc.) are detected |
| `--no-root-check` | Skip root privilege check |

---

## Building a .so to inject

```c
// payload.c
#include <stdio.h>

__attribute__((constructor))
void on_load() {
    printf("[+] injected!\n");
}
```

```bash
gcc -shared -fPIC -o payload.so payload.c
```

The `constructor` attribute makes `on_load()` run automatically as soon as the library is loaded into the target process.

---

## Project structure

```
RustyInjector/
├── injector.py       # CLI entry point
├── core/
│   ├── ptrace.py     # Primary injection engine (ptrace + shellcode)
│   ├── shellcode.py  # mmap / dlopen / munmap / zero stubs (x86_64)
│   ├── gdb.py        # GDB fallback
│   └── stealth.py    # jitter, memfd staging, monitor detection, comm masking
└── utils/
    ├── log.py        # Output helpers, colours, spinner, in-memory log
    ├── signals.py    # SIGINT/SIGTERM handlers with guaranteed detach
    └── preflight.py  # Preflight checks, PID resolution, library validation
```

---

## Disclaimer

For educational purposes and authorized testing only. Don't use this on systems or processes you don't own.

---

## License

MIT — see [LICENSE](LICENSE).
