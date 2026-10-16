<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: requirements-from-implementation
type: reasoning
description: >
  Systematic reasoning protocol for deriving structured requirements
  from existing source code. Transforms code understanding into
  testable, atomic requirements with acceptance criteria.
applicable_to:
  - reverse-engineer-requirements
  - review-code
---

# Protocol: Requirements from Implementation

Apply this protocol when deriving requirements from an existing codebase.
The goal is to produce a structured requirements document that captures
what the implementation provides — not how it provides it. Execute all
phases in order.

## Phase 1: API Surface Enumeration

Systematically catalog every public-facing element of the codebase:

1. **Functions and entry points**: Signatures, parameters, return types,
   error conditions. For each, note whether it is public API, internal,
   or a convenience wrapper.
2. **Types and data structures**: Structs, enums, unions, typedefs.
   Identify which are opaque (implementation detail) vs. transparent
   (part of the API contract).
3. **Metaprogramming and indirection constructs** (if applicable):
   Preprocessor macros (C/C++), decorators (Python), annotations (Java),
   attribute macros (Rust), code generation. Expand representative
   invocations to understand the actual behavior. Document parameters,
   their types, and constraints.
4. **Constants and configuration surfaces**: Compile-time switches,
   feature flags, tuning parameters. Identify which are user-facing
   configuration vs. internal implementation constants.
5. **Error handling patterns**: How does the API report errors? Return
   codes, errno, out-parameters, callbacks, exceptions? Catalog the
   error space.

Produce a structured enumeration (table or list) before proceeding.
This becomes the completeness checklist for later phases.

## Phase 2: Behavioral Contract Extraction

For each API element identified in Phase 1:

1. **Preconditions**: What must be true before the caller invokes this?
   Look for parameter validation, assertions, documented constraints,
   and implicit assumptions (e.g., "pointer must not be NULL" even if
   unchecked).
2. **Postconditions**: What is guaranteed after successful execution?
   What state changes occur? What values are returned?
3. **Error behavior**: What happens on invalid input, resource exhaustion,
   or concurrent access? Is the API fail-safe, fail-fast, or undefined?
4. **Side effects**: Does the function modify global state, allocate
   memory the caller must free, register callbacks, or interact with
   external systems?
5. **Ordering constraints**: Must certain functions be called before
   others? Is there an initialization/teardown protocol?
6. **Thread safety**: Can this be called concurrently? From any thread?
   What synchronization does the caller need to provide?

For each contract, cite the specific code evidence (file, line,
function) that establishes it.

## Phase 3: Essential vs. Incidental Classification

For every behavioral observation from Phase 2, classify it:

1. **Essential behavior**: Behavior that callers depend on and that
   defines the API's value. This becomes a requirement.
   - Test: "If this behavior changed, would existing correct callers break?"
   - Test: "Is this behavior documented, tested, or part of the type
     signature?"

2. **Incidental behavior**: Behavior that happens to be true in this
   implementation but is not part of the contract.
   - Test: "Could a correct reimplementation reasonably behave differently?"
   - Test: "Is this an optimization, ordering artifact, or implementation
     convenience?"

3. **Ambiguous behavior**: Cannot be classified without domain knowledge
   or explicit confirmation from stakeholders. Flag with `[AMBIGUOUS]`.

For ambiguous items, state the two interpretations and their implications
for requirements.

## Phase 4: Requirement Synthesis

Transform essential behaviors into structured requirements:

1. **Group by functional area**: Organize related behaviors into
   requirement categories (e.g., initialization, data processing,
   error handling, resource management).
2. **Write atomic requirements**: Each requirement captures exactly one
   testable behavior using RFC 2119 keywords (MUST, SHOULD, MAY).
3. **Derive acceptance criteria**: For each requirement, define at least
   one concrete, measurable test derived from the code's actual behavior.
   Prefer criteria that can be validated against the existing
   implementation as a reference oracle.
4. **Preserve semantic fidelity**: Requirements must faithfully represent
   what the implementation does, even if the behavior seems suboptimal.
   If behavior appears buggy but is established, note it as a requirement
   and flag: `[REVIEW: may be a defect in the reference implementation]`.
5. **Capture non-functional characteristics**: Performance bounds,
   resource usage patterns, concurrency guarantees, and platform
   requirements observed in the implementation.

## Phase 5: Completeness and Gap Analysis

1. **Coverage check**: Cross-reference the requirements against the
   API surface enumeration from Phase 1. Every public API element
   MUST have at least one associated requirement. Flag any gaps.
2. **Undocumented behavior**: Identify behaviors observed in the code
   that have no documentation, no tests, and no obvious purpose.
   These may be bugs, deprecated features, or undocumented contracts.
   Flag with `[UNDOCUMENTED]`.
3. **Missing error cases**: For each API element, verify that error
   conditions are covered by requirements. Missing error handling
   is a common gap.
4. **Cross-cutting concerns**: Verify that thread safety, resource
   lifecycle, and error propagation requirements are captured as
   cross-cutting requirements, not just per-function notes.

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

The sections below extend the generic protocol with ocserv's three-process
architecture, vtable interfaces, IPC contracts, and documentation sources.

### Phase 1 — API Surface Enumeration (ocserv)

The primary API surfaces in ocserv are not library exports but internal module
contracts. Enumerate them in this order:

1. **Auth module vtable** (`src/sec-mod-auth.h`, `auth_mod_st`): Every field
   in the vtable is a required callback. Document which callbacks are mandatory
   vs. optional (NULL-safe) and what each is expected to do.

2. **IPC message types** (`src/ipc.proto`, `src/ctl.proto`): Each message is
   an entry point. For each, enumerate: direction (who sends, who receives),
   required fields, optional fields, and the expected response message type.

3. **Configuration struct fields** (`src/common-config.h`, `cfg_st`,
   `perm_cfg_st`, per-module config structs): Identify which fields are
   user-configurable (surfaced in `src/config.c` or `src/subconfig.c`) vs.
   internally derived. User-configurable fields have documentation in
   `doc/ocserv.8.md` and `doc/sample.config`.

4. **Log macros** (`src/log.h`): `mslog()` (main), `oclog()` (worker),
   `seclog()` (sec-mod). Note which severity levels are in use; this defines
   the diagnostic contract.

5. **Error codes** (`src/defs.h`, `cmd_request_t`, error code enums): Catalog
   every return code used in IPC and authentication flows.

### Phase 2 — Behavioral Contract Extraction (ocserv)

Adapt the generic questions for ocserv's process model:

- **"Thread safety"** → **"Process safety"**: ocserv's workers are isolated
  processes with no shared memory. State crossing a process boundary MUST go
  through IPC. If a function is called in multiple processes, its behavior in
  each must be specified separately.

- **Talloc ownership** is the primary precondition to establish for every
  allocation-returning function:
  - Who is the talloc parent context?
  - Is ownership transferred to the caller, or retained by the subsystem?
  - Can the allocation outlive the talloc context passed to the function?
  - Does the memory cross a process boundary? (If yes, it must be serialized
    via protobuf — a raw talloc pointer is meaningless in another process.)

- **GnuTLS memory**: For functions that interact with GnuTLS, identify whether
  returned memory must be freed with `gnutls_free()` rather than `talloc_free()`.
  This is a separate ownership domain.

- **IPC ordering constraints**: For multi-message exchanges (e.g.,
  `SEC_AUTH_INIT` → `SEC_AUTH_REP` → `SEC_AUTH_CONT` → `SEC_AUTH_REP`), the
  ordering is a precondition. Document the full exchange sequence for each
  operation, referencing `doc/design.md`.

- **Error behavior in the worker**: Workers run under seccomp. Any function
  that attempts a system call not in the worker's seccomp whitelist will cause
  the kernel to terminate the worker process (SIGKILL), not return an error.
  This is an error behavior that MUST be captured as a requirement if the
  function is called from worker context.

### Phase 3 — Essential vs. Incidental Classification (ocserv)

Use these additional tests before classifying behavior:

- **Documentation test**: If the behavior is described in `doc/ocserv.8.md`
  or `doc/sample.config`, it is **essential** — it is the documented contract
  with administrators. If the observed behavior contradicts the documentation,
  flag it as: `[REVIEW: contradicts doc/ocserv.8.md — code or doc must change]`.

- **AnyConnect compatibility test**: If the behavior is related to the
  CSTP/HTTSP protocol exchange, check `doc/README-cisco-svc.md`. Behaviors
  that preserve AnyConnect client compatibility are **essential** even if not
  documented in the man page.

- **Privilege boundary test**: Any behavior that enforces the three-process
  privilege model (worker cannot access credentials, main cannot do auth) is
  **essential** — it is a security invariant. Never classify these as incidental.

### Phase 4 — Requirement Synthesis (ocserv)

Group by these functional areas, annotating each requirement with its process:

| Category | Process(es) | Description |
|----------|-------------|-------------|
| `INIT` | main, sec-mod, worker | Startup, initialization, configuration loading |
| `AUTH` | sec-mod, worker (IPC) | Authentication flows, vtable callbacks |
| `ACCT` | sec-mod | Accounting start/stop, RADIUS, PAM acct |
| `SESSION` | sec-mod, main, worker | SID lifecycle, cookie issuance and validation |
| `IPC` | all | Message format, ordering, validation |
| `CFG` | main | Config parsing, reload behavior |
| `NET` | worker, main | TLS/DTLS handshake, IP allocation, routing |
| `SEC` | all | Seccomp, privilege drops, trust boundary enforcement |
| `ERR` | all | Error propagation, logging, client-visible error messages |
| `TEARDOWN` | all | Session cleanup, worker exit, talloc lifetime |

For `SEC` and `AUTH` categories, write the MUST NOT requirement before the
MUST requirement (negative contract precedes positive contract).

For `IPC` requirements, the acceptance criterion MUST reference specific
protobuf field names from `src/ipc.proto` or `src/ctl.proto`, not vague
descriptions.

### Phase 5 — Completeness and Gap Analysis (ocserv)

Additional gap checks specific to ocserv:

- **Vtable gap**: For every `auth_mod_st` vtable field, confirm a requirement
  covers the expected behavior and the NULL-safety contract. A NULL callback
  that the caller does not check is an undocumented crash path — flag it.

- **IPC field coverage**: For every field in each protobuf message, confirm
  a requirement covers how the receiver handles it when missing (proto3
  defaults to zero/empty) and what range of values is valid.

- **Config ↔ code gap**: For every field in the config struct visible in
  `src/common-config.h`, confirm it appears in `doc/ocserv.8.md`. Undocumented
  fields are either dead code or `[UNDOCUMENTED]` contracts.

- **Reload coverage**: For every configuration option, confirm whether a
  requirement covers its behavior on `SIGHUP`. Non-reloadable options must
  have a requirement stating that the value is fixed at startup.

- **Seccomp coverage**: For every syscall made from worker context, confirm
  it is in the seccomp whitelist. Functions that reach the worker path through
  indirect calls (callbacks, GnuTLS internals) are the most common gap.

<!-- END ocserv extensions -->
