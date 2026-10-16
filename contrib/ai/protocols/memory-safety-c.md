<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) PromptKit Contributors -->

---
name: memory-safety-c
type: analysis
description: >
  Systematic protocol for analyzing memory safety issues in C codebases.
  Covers allocation/deallocation pairing, pointer lifecycle, buffer boundaries,
  and undefined behavior.
language: C
applicable_to:
  - investigate-bug
  - review-code
  - investigate-security
---

# Protocol: Memory Safety Analysis (C)

Apply this protocol when analyzing C code for memory safety defects. Execute
each phase in order. Do not skip phases — apparent simplicity often hides
subtle bugs.

## Phase 1: Allocation / Deallocation Pairing

For every allocation site (`malloc`, `calloc`, `realloc`, `strdup`, custom allocators):

1. Trace **all** code paths from allocation to deallocation.
2. Identify paths where deallocation is **missing** (leak) or **unreachable**
   (early return, exception-like longjmp, error branch).
3. Check for **double free**: paths where the same pointer is freed more than once.
4. Check for **mismatched APIs**: `malloc`/`free` vs `new`/`delete` vs custom
   allocator pairs.

## Phase 2: Pointer Lifecycle Analysis

For every pointer variable:

1. Determine its **ownership semantics**: who is responsible for freeing it?
   Is ownership transferred? Is it documented?
2. Check for **use-after-free**: any access to a pointer after its referent
   has been freed. Pay special attention to:
   - Pointers stored in structs or global state that outlive the allocation.
   - Pointers passed to callbacks or stored in event loops.
   - Conditional free followed by unconditional use.
3. Check for **dangling pointers**: pointers to stack variables that escape
   their scope (returned from function, stored in heap struct).
4. Verify **NULL checks** after allocation and after any operation that may
   invalidate a pointer (e.g., `realloc`).

## Phase 3: Buffer Boundary Analysis

For every buffer (stack arrays, heap allocations, string buffers):

1. Identify all **read and write accesses** to the buffer.
2. Verify that every access is **bounds-checked** or provably within bounds.
3. Check for **off-by-one errors** in loop conditions and index calculations.
4. Check `strncpy`, `snprintf`, `memcpy` calls for correct size arguments.
5. Identify any **user-controlled index or size** values that flow into
   buffer accesses without validation.

## Phase 4: Undefined Behavior Audit

Check for common sources of undefined behavior:

1. **Signed integer overflow** in size calculations.
2. **Null pointer dereference** on error paths.
3. **Uninitialized memory reads** — especially stack variables and struct
   fields after partial initialization.
4. **Type punning** violations (strict aliasing).
5. **Sequence point violations** in complex expressions.

## Output Format

For each finding, report:

```
[SEVERITY: Critical|High|Medium|Low]
Location: <file>:<line> or <function name>
Issue: <concise description>
Evidence: <code path or snippet demonstrating the issue>
Remediation: <specific fix recommendation>
Confidence: <High|Medium|Low — with justification if not High>
```

<!-- END PromptKit base -->

---

<!-- BEGIN ocserv extensions -->

## ocserv-Specific Extensions

The sections below extend the generic protocol with ocserv's allocator rules,
cross-process lifetime constraints, and error-path discipline.

### Allocator Rules (extends Phase 1)

ocserv uses **talloc** as its project-wide allocator. The generic phase 1
checks apply, but substitute these rules for allocator pairing:

- **talloc is the default.** Use `talloc_zero`, `talloc_strdup`,
  `talloc_memdup`, `talloc_array`, etc. for all allocations. Before
  introducing a new allocation, check how surrounding code allocates
  similar data.
- **`gnutls_malloc` / `gnutls_free` are the exception.** Use them only
  for memory whose lifetime GnuTLS owns — i.e., memory passed to a GnuTLS
  API that will call `gnutls_free()` on it internally (e.g., `gnutls_datum_t`
  fields consumed by GnuTLS internals). Never use `gnutls_free()` on a
  talloc allocation, and never pass a `gnutls_malloc` allocation to
  `talloc_free()`.
- **Mismatch check (ocserv-specific, not in the base protocol):** For every
  allocation, confirm the free call uses the matching API. A
  `talloc_strdup` freed with `gnutls_free()`, or vice versa, is a
  heap-corruption bug. Flag any site where the allocator is ambiguous.
- Check every allocation return value before use. A NULL return in a VPN
  server is a denial-of-service vulnerability.

### Cross-Process Pointer Lifetime (extends Phase 2)

ocserv's three processes (main, sec-mod, worker) have independent address
spaces. Extend the pointer lifecycle analysis with:

- **Allocations do not cross process boundaries.** A pointer allocated in
  worker memory is not accessible in main or sec-mod, and vice versa. Flag
  any struct field or IPC message that appears to transfer a raw pointer
  rather than serialized data.
- **Lifetime by process role:**
  - `sec-mod` and `main`: long-lived allocations that persist across client
    connections. These require explicit cleanup on session teardown.
  - `worker`: per-connection allocations freed when the worker exits. Do not
    store worker-process pointers in IPC messages intended for main or sec-mod.

### Error-Path Discipline (extends Phase 1 and Phase 2)

ocserv follows a `goto cleanup` pattern for resource management. When
reviewing allocation and free pairing:

- Every function that allocates resources must have a single `cleanup` label
  that frees all resources allocated so far.
- Multiple `return` paths that each partially free state are a defect —
  they produce leaks or double-frees on uncommon error paths.
- Verify that every early `goto cleanup` path leaves the cleanup label able
  to safely free whatever was allocated before the jump (i.e., pointers not
  yet allocated are NULL, and the cleanup code checks for NULL before
  freeing).

<!-- END ocserv extensions -->
