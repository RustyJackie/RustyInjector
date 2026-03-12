# Security Policy

## Supported versions

Only the latest release gets security fixes. If you're running something older,
update first.

## Reporting a vulnerability

If you find a security issue in this project itself — not "this tool can be used
maliciously" (that's the point), but an actual vulnerability like privilege
escalation, arbitrary code execution in the injector itself, or similar — report
it privately before going public.

Open a [GitHub Security Advisory](../../security/advisories/new) or email the
maintainer directly if you can find the contact. Give a reasonable amount of time
to respond before disclosure, something like 14 days for a fix or at least an
acknowledgement.

Public issue tracker is fine for everything else.

## Intended use

This tool is intended for:

- Authorized penetration testing
- Security research on systems you own or have explicit permission to test
- Learning — understanding how ptrace-based injection works at the syscall level

Using it on systems without authorization is illegal in most jurisdictions and
not something this project supports in any way. The MIT license doesn't grant
you permission to break the law.
