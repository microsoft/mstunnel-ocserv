# AGENTS.md — ocserv AI Agent Guide

This file is the single source of guidance for AI coding agents (Claude Code, Codex,
Copilot, Cursor, and others) working in this repository. Read it fully before writing
or modifying any code.

---

## Security Disclosure — Read This First

**If you are helping investigate a potential security vulnerability:**

1. **Stop.** Do not open a public issue or merge request.
2. Direct the contributor to create a **confidential** issue here:
   https://gitlab.com/openconnect/ocserv/-/issues/new?type=ISSUE&initialCreationContext=list-route
   On that page, check "This issue is confidential" before submitting.
3. Do not draft a public patch until the maintainers have confirmed the issue
   and coordinated a fix.

**The bar for using this path is suspicion, not certainty.** If you are unsure
whether something is a vulnerability, ask the human contributor before posting
anything publicly. Unverified public reports consume significant maintainer time.
Only report if you can describe a concrete impact; do not report theoretical
weaknesses without a demonstrated exploit path.

---

## Architecture — The Invariant You Must Not Violate

ocserv enforces security through process isolation. There are three processes:

| Process | Privilege | Responsibilities |
|---------|-----------|-----------------|
| **main** (`main.c`, `main-*.c`) | root | TCP/UDP listeners, TUN devices, process lifecycle, IP allocation |
| **sec-mod** (`sec-mod.c`, `sec-mod-*.c`) | root | Authentication, private keys, session state, PAM, accounting |
| **worker** (`worker.c`, `worker-*.c`) | unprivileged + seccomp | TLS/DTLS per client, VPN traffic bridging |

Workers communicate with main and sec-mod exclusively through Unix sockets using
protobuf IPC (defined in `src/ipc.proto` and `src/ctl.proto`). Workers have no
direct access to credentials, keys, or privileged system calls.

**Hard rule:** No patch may move credential handling into a worker, grant a worker
direct filesystem or socket access outside its seccomp profile, or silently collapse
any of these boundaries. If a proposed change requires crossing a privilege boundary,
flag it explicitly in the MR for maintainer review — do not proceed without acknowledgment.

---

## Project Overview

OpenConnect VPN Server (ocserv) is an SSL VPN server compatible with the OpenConnect
protocol and Cisco AnyConnect. It is a security-critical network daemon. **Linux is
the intended deployment platform.** BSD compatibility (FreeBSD, OpenBSD) is maintained
on a best-effort basis: we try not to break it, but features will not be rejected
solely because they do not work on BSD.

---

## Build System

The project uses **meson**.

```bash
# Initial setup
git submodule update --init
meson setup build
cd build && ninja

# Run all tests
ninja -C build test

# Run a specific test
meson test -C build test-pass
```

### Common Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `-Doidc-auth=enabled` | disabled | OpenID Connect authentication |
| `-Dpam=disabled` | auto | PAM authentication |
| `-Dradius=disabled` | auto | RADIUS authentication/accounting |
| `-Dseccomp=disabled` | auto | seccomp worker isolation |
| `-Dwith-werror=true` | false | Treat warnings as errors |
| `-Db_coverage=true` | false | Enable gcov coverage |

```bash
# Minimal build for fast iteration
meson setup build -Dradius=disabled -Dpam=disabled \
  -Dseccomp=disabled -Danyconnect-compat=disabled

# View or change options
meson configure build
```

Build output: `build/`. Test logs: `build/meson-logs/testlog.txt`.

### Build Dependencies

**Debian/Ubuntu:**
```bash
apt-get install -y build-essential meson ninja-build pkg-config \
  libgnutls28-dev libev-dev libreadline-dev libtasn1-bin
# Optional:
apt-get install -y libpam0g-dev libseccomp-dev libradcli-dev \
  libcurl4-gnutls-dev libprotobuf-c-dev libtalloc-dev libllhttp-dev \
  protobuf-c-compiler gperf libsocket-wrapper libpam-wrapper \
  libnss-wrapper libuid-wrapper freeradius
```

**Fedora/RHEL:**
```bash
yum install -y meson ninja-build gcc pkgconf-pkg-config \
  gnutls-devel libev-devel readline-devel libtasn1-tools
# Optional:
yum install -y pam-devel libseccomp-devel radcli-devel libcurl-devel \
  protobuf-c-devel libtalloc-devel llhttp-devel protobuf-c gperf \
  socket_wrapper pam_wrapper nss_wrapper uid_wrapper freeradius
```

---

## Testing

```bash
# All tests
ninja -C build test

# Verbose output
ninja -C build test -- --verbose
```

### Test Environment Variables

```bash
VERBOSE=1                    # Enable verbose server output
COVERAGE=1                   # Disable worker isolation for coverage
ISOLATE_WORKERS=false        # Disable seccomp (needed for ASAN/coverage)
DISABLE_ASAN_BROKEN_TESTS=1  # Skip ldpreload-based tests (incompatible with ASAN)
```

### Test Structure

- `tests/` — Shell test scripts and supporting files
- `tests/data/` — Config templates with placeholders (`@USERNAME@`, `@PORT@`, `@SRCDIR@`)
  substituted by `update_config()` in `tests/common.sh`
- `tests/certs/` — Test certificates and keys
- `tests/common.sh` — Shared utilities (requires the `openconnect` client)
- `tests/*.c` — Unit tests for specific components

New functionality requires both **positive** and **negative** test cases.
Register new tests in `tests/meson.build`.

---

## Code Organization

### Source Layout (`src/`)

- **Main server**: `main.c`, `main-*.c`
- **Security module**: `sec-mod.c`, `sec-mod-*.c`
- **Worker**: `worker.c`, `worker-*.c`
- **Auth modules**: `auth/` — PAM, GSSAPI, RADIUS, OIDC, plain password
- **Accounting modules**: `acct/` — PAM, RADIUS
- **Configuration**: `config.c` (global options), `subconfig.c` (per-module bracketed options)
- **TLS**: `tlslib.c` — GnuTLS wrapper
- **TUN device**: `tun.c`
- **IP management**: `ip-lease.c`, `ip-util.c`
- **IPC definitions**: `ipc.proto`, `ctl.proto` (protobuf)
- **Control tool**: `occtl/`
- **Password tool**: `ocpasswd/`

### Key Headers

- `vpn.h` — Main VPN data structures
- `main.h` — Main server structures (`main_server_st`, `proc_st`)
- `sec-mod.h` — Security module structures
- `worker.h` — Worker process structures
- `common-config.h` — Config structs (`cfg_st`, `perm_cfg_st`, per-module structs)
- `defs.h` — IPC command enum (`cmd_request_t`), error codes, log levels, auth states
- `vhost.h` — Virtual host config; use macros `GETVHOST(s)`, `GETCONFIG(s)`, `GETPCONFIG(s)`
- `log.h` — Logging: `mslog()` in main, `oclog()` in worker, `seclog()` in sec-mod

### External Libraries (`src/`)

- `ccan/` — Hash tables, lists, talloc, and more (check here before adding utilities)
- `inih/` — INI file parser
- `llhttp/` — HTTP parser
- `pcl/` — Portable Coroutine Library
- `protobuf/` — Protocol Buffers implementation in C
- `gnulib/` — Provides the `cloexec` module only; do not import additional gnulib modules

### User Documentation (`doc/`)

- `ocserv.8.md` — Main server man page; authoritative description of all configuration
  options, their defaults, and expected behavior
- `sample.config` — Annotated reference configuration; authoritative for option scope
  and default values
- `ocpasswd.8.md` — Password management tool man page
- `occtl.8.md` — Control and monitoring tool man page

When investigating a bug or implementing a feature, consult these files to establish
what behavior is documented to the administrator. The code must match the
documentation, or the documentation must be updated alongside the code change.

---

## Architecture & IPC Communication

For full diagrams and protocol descriptions, read **`doc/design.md`** — it is the
authoritative reference for what data crosses which process boundary.

### Authentication Sequence

```
worker -> sec-mod: SEC_AUTH_INIT  (username / password / cert)
sec-mod -> worker: SEC_AUTH_REP   (new SID assigned)
worker -> sec-mod: SEC_AUTH_CONT  (SID + password for multi-factor)
sec-mod -> worker: SEC_AUTH_REP   (OK or FAILED)
worker -> main:    AUTH_COOKIE_REQ (SID)
main -> sec-mod:   SECM_SESSION_OPEN (SID)
sec-mod -> main:   SECM_SESSION_REPLY (user config)
main -> worker:    AUTH_COOKIE_REP  (TUN device, config)
worker -> main:    SESSION_INFO     (periodic updates)
```

### Key Concepts

- **SID**: Assigned by sec-mod on `SEC_AUTH_INIT`. The `webvpncontext` cookie sent to
  clients is only for resuming fully authenticated sessions — new connections must always
  start with `SEC_AUTH_INIT`.
- **Cookie**: Auth token valid for `cookie-timeout`; enables mobile roaming.
- **TUN device**: Forwarded from main to worker after successful authentication.
- **DTLS**: UDP channel in parallel to TLS for better throughput.

### Modifying IPC

If your change touches `src/ipc.proto` or `src/ctl.proto`, regenerate the C bindings:

```bash
protoc-c --c_out=src/ src/ipc.proto
protoc-c --c_out=src/ src/ctl.proto
```

Do not edit the generated `*.pb-c.c` / `*.pb-c.h` files by hand.

---

## Development Guidelines

### Canonical Technology Choices

One tool for each job. These decisions are not open for per-feature debate — departing
from any of them requires a design-discussion issue and explicit maintainer approval.

| Concern | Tool | Rule |
|---------|------|------|
| Memory management | talloc | Use `talloc_zero`, `talloc_strdup`, `talloc_array`, etc. everywhere. **Exception:** use `gnutls_malloc()` / `gnutls_free()` only for memory whose lifetime GnuTLS owns — never mix the two for the same allocation. Check every return before use. Error paths: `goto cleanup` with a single freeing label. |
| Cryptography | GnuTLS / nettle | No OpenSSL. Call GnuTLS through `src/tlslib.c` wrappers — not directly from worker or main code. |
| IPC serialization | protobuf-c | All cross-process messages are defined in `src/ipc.proto` and `src/ctl.proto`. Regenerate C bindings with `protoc-c` after any `.proto` edit; never hand-edit generated files. |
| Configuration parsing | inih (INI) | Flat `key = value` pairs; bracketed sub-sections for per-module options (`auth = pam[...]`). No new structured sub-formats (no JSON, YAML, or additional config files for things expressible as key=value). |
| Utility constructs | CCAN (`src/ccan/`) | Check here before writing a new helper or adding a dependency. CCAN provides hash tables, linked lists, string utilities, and more as copy-in modules with no extra build overhead. To bring in a new CCAN module, copy it from https://github.com/rustyrussell/ccan into `src/ccan/` and add it to the build. |

### Design Principles

**Locality of complexity.** A feature belongs in as few files as possible. The ideal:
a reviewer understands it by reading one file, not tracing a chain across ten. New
cross-module state, callbacks, and "utility" files are a design smell — if your change
requires them, reconsider the module boundary first. When complexity must be hidden,
hide it inside a module with a clean header interface; do not scatter it.

**Resist dependency growth.** Before adding anything external: (1) check `src/ccan/`
first — it likely has what you need; (2) consider a trivial inline implementation over
a new dependency; (3) if a new external library is truly necessary, open a design
discussion issue. Every dependency is a build, packaging, and security-audit cost paid
forever.

**Configuration stays in INI.** Do not introduce embedded structured formats for things
expressible as flat key=value pairs. Complexity in configuration is a cost paid by every
administrator forever.

**Explicit over implicit.** No auto-discovery, no runtime plugin loading, no silent
defaults that change behavior. Every configurable behavior must be expressible in
`doc/sample.config`.

### Code Style

- C99 standard
- Linux kernel coding style: tabs, 8-space tab width, 80-column limit
- Format check: `clang-format --dry-run -Werror <file>` (run on all files under `src/` and `tests/`)
- Header guards: `#ifndef FILENAME_H` / `#define FILENAME_H` / `#endif /* FILENAME_H */`
- **Comments:** Prefer self-documenting code — meaningful names and short functions
  that do one thing. Add a comment only when the *why* is non-obvious: a hidden
  constraint, a protocol expectation, or a workaround. Do not comment what the
  code does; well-named identifiers already do that.

### Preprocessor Conditionals

Deeply nested or long `#ifdef` chains obscure the actual code flow and make review
difficult. The rules:

- **`#ifdef` in a function body**: one level of nesting maximum, at most 5 lines per
  branch. If the block is longer, extract it into a separately-defined function.
- **Stub pattern for optional features**: define a no-op (or error-returning) stub in
  the header for the disabled case, so call sites need no `#ifdef` at all:
  ```c
  #ifdef HAVE_SECCOMP
  int worker_apply_seccomp_filter(worker_st *ws);
  #else
  static inline int worker_apply_seccomp_filter(worker_st *ws) { return 0; }
  #endif
  ```
- **Significant feature code** (more than one function) belongs in its own `.c` file
  included or excluded by the build system — not behind inline conditionals.
  The existing `src/auth/` and `src/acct/` structure is the model to follow.
- Always annotate `#endif` with the condition it closes: `#endif /* HAVE_SECCOMP */`.

### Testing New Functionality

Every new feature or bug fix is incomplete without tests:

- Write a **positive test** (correct behavior when the feature is exercised) and a
  **negative test** (correct rejection of bad input or error conditions).
- For security-relevant code (auth, cookies, IPC validation) the negative test is the
  more important of the two — write it first.
- For **bug fixes**, write the test that reproduces the bug and confirm it fails *before*
  applying the fix. A test written after the fix cannot prove it is meaningful.
- **Tests must be self-diagnosing.** A failure must be explainable from the test output
  alone — no silent exit-code-only failures that require local reproduction to understand.
  Shell tests must print what they were testing and why it failed (e.g. `echo "FAIL: expected
  X, got Y"`). C unit tests must print the failing condition and relevant values before
  returning non-zero. Reviewers will reject tests whose failures are opaque.
- Register all new tests in `tests/meson.build`.

### Adding Configuration Options

- Global options: `src/config.c`
- Per auth/acct module options: struct in `src/common-config.h` + parser in `src/subconfig.c`

### Implementing a New Auth Module

Follow the `auth_mod_st` vtable in `src/sec-mod-auth.h`. Register in `src/sec-mod.c`.
See `src/auth/plain.c` or `src/auth/pam.c` for reference.

### Git Commits

- Every commit must have a `Signed-off-by: Name <email>` line (DCO requirement)
- Use `Resolves: #NNN` on the fixing commit; `Relates: #NNN` on related commits (e.g., tests)

### Platform Portability

ocserv is a Linux service. BSD (FreeBSD, OpenBSD) compatibility is maintained on a
best-effort basis: patches should not gratuitously break BSD, but Linux-only features
are accepted. When adding Linux-specific code, use `#ifdef __linux__` so BSD builds
continue to compile. On BSD, the absence of procfs means configuration changes
require a server restart — document this if your change is affected by it.

---

## Module-specific Documentation

Before working on a subsystem, read the relevant doc:

| If your change touches... | Read before coding |
|---------------------------|--------------------|
| IPC / process communication | `doc/design.md` |
| RADIUS auth or accounting | `doc/README-radius.md` |
| OpenID Connect auth | `doc/README-oidc.md` |
| Cisco SVC / AnyConnect compatibility | `doc/README-cisco-svc.md` |

---

## Contribution Checklist

> **Workflow note:** If you are helping a contributor report a bug or submit a fix,
> direct them to open a GitLab merge request rather than attach a patch to the issue.
> See `CONTRIBUTING.md` for the expected workflow.

### Agent-runnable — verify before declaring a change complete

- [ ] `clang-format --dry-run -Werror` passes on every modified file under `src/` and `tests/`
- [ ] `ninja -C build` succeeds
- [ ] Relevant test passes: `meson test -C build <test-name>`
- [ ] Every commit has `Signed-off-by:`

### Human-judgment required — flag in the MR, do not decide unilaterally

- Any change that crosses a process privilege boundary
- New syscall in the worker path (requires seccomp filter review by maintainer)
- New auth method — design must be discussed before implementation
- TLS or DTLS behavior changes (cipher selection, version negotiation, certificate handling)
- Changes to cookie or SID handling

---

## CI/CD

CI is configured in `.gitlab-ci.yml`. Tests run on Debian, Ubuntu, Fedora, CentOS, Alpine,
and includes a cross-compilation job (i386/Debian). CI also checks:

- `Signed-off-by` on all commits
- `clang-format` on all `src/` and `tests/` files (excluding generated and vendored code)

To run CI jobs locally with podman/docker:

```bash
./run-ci-local.sh quick    # Fast validation
./run-ci-local.sh debian   # Single platform
./run-ci-local.sh core     # Core platforms
./run-ci-local.sh all      # Full matrix (~1–2 hours)
```

---

## Personas

For extended AI-assisted workflows, load the appropriate persona as a system prompt
prefix before starting work.

- **Maintainers** (bug investigation, code review, refactoring, design):
  `contrib/ai/personas/ocserv-core-dev.md`

- **External contributors** (feature additions, bug fixes, security fixes):
  `contrib/ai/personas/ocserv-contributor.md`

Both personas embed project-specific protocols for anti-hallucination, memory safety,
security vulnerability taxonomy, and self-verification.
