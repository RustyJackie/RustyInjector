# Contributing

Thanks for taking the time.

## Before you open a PR

- Check open issues first — someone might already be working on it.
- For anything non-trivial, open an issue before writing code. No point spending
  hours on something that won't get merged.
- This project targets Linux x86_64 (ptrace) and any arch (GDB fallback). Keep
  that scope in mind.

## What's welcome

- Bug fixes
- Support for additional architectures in the ptrace path (ARM64 especially)
- Reliability improvements — better error handling, edge cases, etc.
- Documentation fixes

## What won't be merged

- Features that exist purely to make malicious use easier
- Obfuscation of any kind
- Anything that removes the `--dry-run`, `--verify`, or logging functionality

## Code style

Match what's already there. Concise, readable, commented where the *why* isn't
obvious. Type hints on everything. No external dependencies beyond the stdlib.

## Commit messages

Be specific. `fix: cancel blocking syscall before injection` is good.
`fixed stuff` is not.

## Testing

Test on an actual Linux box, not just a syntax check. If you're touching the
ptrace path, test on both a busy-loop process and a sleeping one
(e.g. `sleep 9999`). Mention what you tested in the PR description.
