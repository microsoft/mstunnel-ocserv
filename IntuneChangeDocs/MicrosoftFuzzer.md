# Microsoft Fuzzer Support

This document catalogs every modification the Microsoft Intune Tunnel team has made to
the ocserv source **specifically to support fuzz testing**. The fuzz harnesses
themselves live in the Intune backend repo (`Intune-Svc-MobileAccess`) under
`src/linux/fuzzer/` and run in OneFuzz; the changes below are the minimal hooks in
ocserv that those harnesses depend on.

All of these are **test-only** hooks. None of them change production server behavior:
the added wrapper functions are never called on the server code path (only referenced
by the fuzz harnesses at link time), and the defensive guard below is a NULL check that
is a no-op in normal operation.

Wherever possible the harnesses avoid touching ocserv at all and instead use linker
`--wrap` stubs (e.g. `cstp_send`, `dtls_send`, `curl_easy_*`, `cjose_jws_verify`,
`_exit`) defined in the harness. The items here are the cases that could not be done
that way — mainly exposing `static` functions so a harness can call them directly.

## Changes

### 1. `parse_data_caller` — expose the AnyConnect data-packet parser
- **File:** `src/worker-vpn.c`
- **What:** Non-static wrapper around the `static` `parse_data`, so the
  `anyconnect-parser-fuzzer` harness can feed it AnyConnect CSTP/DTLS packets.
- **Why:** `parse_data` is the core VPN data-channel packet parser and the primary
  fuzz target, but it is `static` and otherwise only reachable through the live worker
  event loop.
- **Origin:** "Add Fuzzer testing fixes" — see `FuzzerTestFix.md`.

### 2. `dtls_send` NULL-session guard
- **File:** `src/tlslib.c`
- **What:** `dtls_send` returns `GNUTLS_E_INVALID_SESSION` when `dtls->dtls_session ==
  NULL` instead of dereferencing it.
- **Why:** The fuzz harness drives packet parsing without a negotiated DTLS session, so
  DPD/MTU code paths that call `dtls_send` would otherwise crash on a NULL session.
  This is a harmless guard in production (a live session is never NULL there).
- **Origin:** "Add Fuzzer testing fixes" — see `FuzzerTestFix.md`.

### 3. `parse_cstp_data_caller` / `parse_dtls_data_caller` — expose the framing validators
- **File:** `src/worker-vpn.c`
- **What:** Non-static wrappers around the `static` `parse_cstp_data` and
  `parse_dtls_data`, mirroring `parse_data_caller`.
- **Why:** These functions perform the CSTP `STF\x01` magic + length framing validation
  and the DTLS length guard that gate `parse_data`. They are `static`, so the
  `anyconnect-parser-fuzzer` harness could only reach `parse_data` directly and never
  exercised the framing checks. These wrappers let the harness cover them.
- **Origin:** [microsoft/mstunnel-ocserv PR #12](https://github.com/microsoft/mstunnel-ocserv/pull/12)
  (paired with Intune-Svc-MobileAccess PR
  [16351777](https://msazure.visualstudio.com/One/_git/Intune-Svc-MobileAccess/pullrequest/16351777)).

## Related harness-side work (no ocserv change required)

For context, the following fuzzer improvements live entirely in the harnesses
(`Intune-Svc-MobileAccess`, PR
[16351777](https://msazure.visualstudio.com/One/_git/Intune-Svc-MobileAccess/pullrequest/16351777))
and required no ocserv modification:

- **access-token-fuzzer:** structure-preserving JWS "envelope" modes so inputs pass
  `cjose_jws_import` and exercise the OIDC claim-validation pipeline and the JWKS
  refresh/curl path (via `--wrap` of `cjose_jws_verify`, `time`, and `curl_easy_*`).
- **anyconnect-parser-fuzzer:** `--wrap` stubs for `cstp_send` / `dtls_send`, a
  `/dev/null` tun fd, a passthrough decompressor, and richer `worker_st` setup to reach
  more of `parse_data`.
