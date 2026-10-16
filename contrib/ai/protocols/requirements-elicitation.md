<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: requirements-elicitation
type: reasoning
description: >
  Protocol for extracting, structuring, and validating requirements
  from natural language descriptions. Produces precise, testable,
  unambiguous requirements with stable identifiers.
applicable_to:
  - author-requirements-doc
  - interactive-design
  - hardware-design-workflow
---

# Protocol: Requirements Elicitation

Apply this protocol when converting a natural language description of a feature,
system, or project into structured requirements. The goal is to produce
requirements that are **precise, testable, unambiguous, and traceable**.

## Phase 1: Scope Extraction

From the provided description:

1. Identify the **core objective**: what problem does this solve? For whom?
2. Identify **explicit constraints**: performance targets, compatibility
   requirements, regulatory requirements, deadlines.
3. Identify **implicit constraints**: assumptions about the environment,
   platform, or existing system that are not stated but required.
   Flag each with `[IMPLICIT]`.
4. Define **what is in scope** and **what is out of scope**. When the
   boundary is unclear, enumerate the ambiguity and ask for clarification.

## Phase 2: Requirement Decomposition

For each capability described:

1. Break it into **atomic requirements** — each requirement describes
   exactly one testable behavior or constraint.
2. Use **RFC 2119 keywords** precisely:
   - MUST / MUST NOT — absolute requirement or prohibition
   - SHALL / SHALL NOT — equivalent to MUST (used in some standards)
   - SHOULD / SHOULD NOT — recommended but not absolute
   - MAY — truly optional
3. Assign a **stable identifier**: `REQ-<CATEGORY>-<NNN>`
   - Category is a short domain tag (e.g., AUTH, PERF, DATA, UI)
   - Number is sequential within the category
4. Write each requirement in the form:
   ```
   REQ-<CAT>-<NNN>: The system MUST/SHALL/SHOULD/MAY <behavior>
   when <condition> so that <rationale>.
   ```

## Phase 3: Ambiguity Detection

Review each requirement for language that introduces non-deterministic
interpretation. Apply the ambiguity pattern categories below
systematically; these categories are aligned with the
`prompt-determinism-analysis` protocol:

1. **Vague adjectives**: "fast," "responsive," "secure," "scalable,"
   "user-friendly" — replace with measurable criteria.
2. **Unquantified quantities**: "handle many users," "large files" —
   replace with specific numbers or ranges.
3. **Implicit behavior**: "the system handles errors" — what errors?
   What does "handle" mean? Retry? Log? Alert? Fail open? Fail closed?
4. **Undefined terms**: if a term could mean different things to different
   readers, add it to a glossary with a precise definition.
5. **Missing negative requirements**: for every "the system MUST do X,"
   consider "the system MUST NOT do Y" (e.g., "MUST NOT expose PII in logs").
6. **Open-ended enumerations**: "support formats like PDF, Word, etc." —
   enumerate the complete list or define the selection criterion
   (e.g., "all formats supported by the pandoc library").
7. **Hedge words in requirements**: "the system could support" or
   "consider adding" — these must be resolved to MUST, SHOULD, or MAY.
   If the user cannot decide, classify as MAY and flag for review.
8. **Missing conditional branches**: "if the user is authenticated,
   show the dashboard" — what happens if NOT authenticated? Add
   explicit else-branches for every conditional requirement.
9. **Unanchored comparatives**: "faster than the current system" —
   anchor to measurable baselines (e.g., "response time under 200ms
   at the 95th percentile, compared to the current 500ms").

## Phase 4: Dependency and Conflict Analysis

1. Identify **dependencies** between requirements: which requirements
   must be satisfied before others can be implemented or tested?
2. Check for **conflicts**: requirements that contradict each other
   or create impossible constraints.
3. Check for **completeness**: are there scenarios or edge cases
   that no requirement covers? If so, draft candidate requirements
   and flag them as `[CANDIDATE]` for review.

## Phase 5: Acceptance Criteria

For each requirement:

1. Define at least one **acceptance criterion** — a concrete test that
   determines whether the requirement is met.
2. Acceptance criteria should be:
   - **Specific**: describes exact inputs, actions, and expected outputs.
   - **Measurable**: pass/fail is objective, not subjective.
   - **Independent**: testable without requiring other requirements to be met
     (where possible).

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

The sections below extend the generic protocol with ocserv's privilege model,
configuration constraints, and project conventions. Apply these alongside the
base phases above.

### Phase 1 — Scope Extraction (ocserv)

In addition to the generic checklist, for every new feature or change:

- **Assign to a process.** Every requirement belongs to exactly one process:
  - `[PROC: main]` — TCP/UDP listener, TUN device, IP allocation, process lifecycle
  - `[PROC: sec-mod]` — authentication, private keys, session state, PAM, accounting
  - `[PROC: worker]` — per-client TLS/DTLS, VPN traffic, protocol handling
  - `[PROC: IPC]` — a behavior that requires a new or modified message between processes

  If a requirement touches more than one process, decompose it into per-process
  sub-requirements connected by an IPC requirement.

- **Flag Linux-only implicit constraints.** If the feature relies on Linux-specific
  interfaces (epoll, TUN, procfs, namespaces, cgroups), add:
  `[IMPLICIT: Linux-only; BSD builds will require a no-op stub]`.

- **Flag worker seccomp constraints.** Any requirement that causes the worker to
  invoke a system call not currently in the seccomp whitelist must be flagged:
  `[IMPLICIT: requires seccomp filter update; needs maintainer review]`.

- **Configuration format.** If the feature is user-configurable, the configuration
  MUST be expressible as INI `key = value` pairs or the existing bracketed
  sub-section syntax (`auth = module[key=value]`). Flag any requirement that
  assumes structured formats (JSON, YAML) as `[VIOLATION: configuration format]`.

### Phase 2 — Requirement Decomposition (ocserv)

Use these category tags for `REQ-<CAT>-<NNN>` identifiers:

| Tag | Domain |
|-----|--------|
| `AUTH` | Authentication logic (sec-mod, auth backends) |
| `ACCT` | Accounting (session start/stop, RADIUS, PAM acct) |
| `IPC` | Inter-process communication (ipc.proto, ctl.proto) |
| `CFG` | Configuration parsing and defaults |
| `SEC` | Security properties (trust boundaries, seccomp, privilege) |
| `NET` | TLS/DTLS, TCP/UDP, IP allocation, routing |
| `COMPAT` | AnyConnect / OpenConnect client compatibility |
| `LOG` | Logging, error messages, diagnostics |

**Negative requirements are mandatory for `SEC`, `AUTH`, and `IPC` categories.**
For every `REQ-SEC-*` or `REQ-AUTH-*` MUST requirement, write at least one
corresponding MUST NOT requirement. Examples:

- `REQ-SEC-001: The worker MUST NOT have direct access to private keys or
  session credentials. All credential operations MUST go through sec-mod via IPC.`
- `REQ-IPC-001: A worker MUST NOT accept IPC messages that contain a SID it
  did not receive via SEC_AUTH_REP.`

### Phase 3 — Ambiguity Detection (ocserv)

Additional ambiguity patterns to check in the ocserv context:

- **"Secure"**: Always replace with a concrete property — e.g., "authenticated
  via TLS client certificate," "protected from replay by SID validation,"
  "isolated by seccomp from filesystem access."
- **"Session"**: Disambiguate — is this a TLS session, a VPN session (identified
  by SID), a cookie-resumable session, or a PAM session?
- **"Reload"**: Disambiguate — config reload via `SIGHUP` (may not apply to all
  options), or full restart? Check `doc/sample.config` for the option's reload
  behavior annotation (`[reload]` vs. `[not-reloadable]`).
- **"All clients"**: Specify — does this apply during active sessions, or only
  to new connections? Does it apply to DTLS sessions as well as TLS?

### Phase 4 — Dependency and Conflict Analysis (ocserv)

Check for these ocserv-specific conflicts before finalizing requirements:

- **Process boundary conflicts**: A requirement `[PROC: worker]` that accesses
  state that belongs to `[PROC: sec-mod]` without an `[PROC: IPC]` requirement
  is a privilege model violation.
- **Config reload conflicts**: A requirement that changes behavior at runtime
  via a reload must be consistent with which options are marked reloadable in
  `doc/sample.config`. Non-reloadable options that appear to need live update
  are a conflict requiring explicit resolution.
- **AnyConnect compatibility conflicts**: If a requirement changes protocol
  behavior, check `doc/README-cisco-svc.md` for AnyConnect client expectations.
  A conflict with AnyConnect behavior must be flagged as `[COMPAT-RISK]`.

### Phase 5 — Acceptance Criteria (ocserv)

Map each acceptance criterion to the ocserv test infrastructure:

- **Positive test**: shell test in `tests/` that starts the full server stack
  and exercises the feature. Most such tests require root and will run in CI only.
- **Negative test**: shell test that verifies the server correctly rejects bad
  input or enforces the MUST NOT requirement. Write this first for `SEC`, `AUTH`,
  and `IPC` requirements.
- **Unit test**: a `tests/*.c` unit test for logic that does not require a full
  server (config parsing, data structure operations). These run locally without root.
- **Registration**: every new test must be registered in `tests/meson.build`.

Note in the acceptance criterion whether it is locally runnable or requires CI
(root / full server stack).

<!-- END ocserv extensions -->
