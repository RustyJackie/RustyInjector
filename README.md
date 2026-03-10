# Rusty Injector

A simple Python script that injects `.so` shared libraries into running Linux processes using `gdb`.

---

## What is this?

Sometimes you need to load a shared library into a process that's already running — whether for debugging, hooking, or just messing around. This script automates that via `gdb`: it attaches to the target process, calls `dlopen()` inside it, then detaches. The process keeps running as if nothing happened, except now your library is loaded.

No kernel modules, no custom drivers. Just Python and `gdb`.

---

## Requirements

- Linux
- Python 3
- `gdb` installed
- `sudo` (needed to attach to other processes)

If `gdb` isn't installed:
```bash
# Debian/Ubuntu
sudo apt install gdb

# Fedora/RHEL
sudo dnf install gdb
```

> **Heads up:** Some distros block ptrace by default. If the script fails with a permissions error, try:
> ```bash
> echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
> ```

---

## Installation

```bash
git clone https://github.com/rustyjackie/linux-injector.git
cd linux-injector
chmod +x injector.py
```

---

## Usage

```bash
sudo python3 injector.py <pid> <path_to_library.so>
```

Find the PID of your target process with `pgrep` or `ps`, then run:

```bash
sudo python3 injector.py 1337 /path/to/your/library.so
```

---

## Building a .so to inject

If you need a quick library to test with:

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

The `constructor` attribute makes `on_load()` run automatically as soon as the library is loaded.

---

## Disclaimer

For educational purposes and authorized testing only. Don't use this on systems or processes you don't own.

---

## License

MIT — see [LICENSE](LICENSE).
