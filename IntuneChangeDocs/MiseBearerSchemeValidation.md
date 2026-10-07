# MISE Bearer authentication scheme validation

## Summary

PAM token authentication now rejects HTTP `Authorization` headers that do not
use the Bearer scheme before forwarding the request to MISE.

This prevents unauthenticated probes and scanners that send schemes such as
`Basic` or `Negotiate` from generating noisy MISE
`UnsupportedAuthenticationScheme` errors. Valid Microsoft Tunnel device
authentication continues to pass the complete `Bearer <token>` header to MISE.

## Previous behavior

When `auth = "pam[use-token=yes]"` was configured, `worker-auth.c` copied the
complete HTTP `Authorization` header into the PAM username field without
validating its scheme. The MISE PAM module then supplied that value directly to
MISE as the authorization header.

As a result, any nonempty scheme reached MISE. MISE rejected non-Bearer values
with errors including:

- `MISE16003: Protocol validation failed`
- `UnsupportedAuthenticationScheme`
- `S2S18501: BearerProtocolHandler was unable to validate the authorizationHeader`

These failures did not indicate a problem with valid device authentication.
They could be produced by unrelated traffic reaching the public VPN endpoint.

## New behavior

For PAM token authentication, ocserv now:

1. Requires a case-insensitive `Bearer ` prefix.
2. Requires a nonempty value after the prefix.
3. Rejects missing, empty, `Basic`, `Negotiate`, and malformed headers before
   invoking PAM or MISE.
4. Returns `401 Unauthorized` with `WWW-Authenticate: Bearer` so the expected
   authentication scheme is advertised to the caller.
5. Logs only that the required scheme was absent; it does not log the
   authorization header or token.

## Code changes

- `src/http-auth.h`
  - Add the shared inline `http_auth_is_bearer()` validator. Keeping the
    validator header-only also supports standalone worker fuzzers without an
    additional link dependency.
- `src/worker-auth.c`
  - Validate the header in the PAM `use-token` path.
  - Reuse a Bearer challenge handler for PAM and OIDC responses.
- `src/Makefile.am`
  - Include the new validator in the ocserv build.
- `tests/bearer-auth.c`
  - Cover valid mixed-case Bearer schemes and rejected missing, empty, Basic,
    Negotiate, and malformed values.
- `tests/Makefile.am`
  - Register the validator test with `make check`.

## Compatibility

The token remains unchanged when passed to the MISE PAM module. Existing
clients that send `Authorization: Bearer <token>` are unaffected. The change is
limited to `pam[use-token=yes]`; username/password PAM and other authentication
methods retain their existing behavior.
