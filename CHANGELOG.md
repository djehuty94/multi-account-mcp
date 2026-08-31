# Changelog

Notable changes to Multi-Account MCP for Gmail & Drive will be recorded here.

## Unreleased

### Planned

- Record the first live two-account OAuth, Gmail, Drive, and macOS Keychain test with sacrificial accounts.
- Complete the public-repository security and release gates in `RELEASE_CHECKLIST.md`.

### Pre-release validation

- Exercised one sacrificial Drive account through partial-scope rejection, OAuth, macOS Keychain persistence, clean-process DPoP refresh, a zero-result search through the real MCP boundary, normal revocation, and local credential-file cleanup. This pre-commit smoke test does not replace the pending commit-bound two-account Gmail-and-Drive isolation gate.

## 0.1.0-alpha.1 - Pending

### Added

- Local standard-input/output MCP server for multiple explicitly selected Google accounts.
- Bring-your-own Google Desktop OAuth flow with read-only Gmail and Drive scope profiles.
- Per-authorization P-256 DPoP sender-constraining for refresh tokens, including bounded nonce challenge handling and no bearer-refresh fallback.
- Operating-system credential-vault storage for OAuth material, including DPoP private keys, and local non-secret account metadata.
- Gmail search, message read, and thread read with bounded text output.
- Drive search, metadata read, and bounded text export.
- Per-result account provenance, process-level account allowlists, signed continuation cursors, and untrusted-content markers.
- An immediate pre-consent data-use disclosure covering purpose/access, local credential handling, MCP host/model-provider processing, and the fact that the project operator receives nothing; continuing requires exact-alias acknowledgment before Google OAuth opens.
- Exact verified-email-to-alias confirmation in an interactive terminal before OAuth credentials or account metadata are persisted.
- Heartbeat-backed cross-process serialization for account connection/removal, including live-owner stale-lock checks and same-identity race protection.
- Fail-closed, typed recovery for uncertain lease cleanup and post-rename disconnect commits.
- Metadata-driven Google-client cache reconciliation that evicts removed or reconnected account clients and their captured credential material.
- Bounded process-local global, per-alias, and `list_accounts` invocation budgets before account or Google access.
- Runtime `drive`, `gmail`, and `both` service surfaces; unselected service tools are absent from MCP discovery and `both` remains the default.
- Security, privacy, architecture, OAuth setup, and project landscape documentation.
- Automated account-isolation, storage, parsing, policy, and MCP handshake tests.

### Fixed

- Verify lock ownership with each lock's unpredictable token, while retaining device/inode checks where reliable, so Windows lease cleanup remains fail-closed without depending on unstable Windows inode identity.
- Detect pre-existing or raced symlink lock paths before writing, and preserve dead-process stale locks for explicit recovery instead of risking deletion of a replacement live lock.
- Rebuild each OAuth token request body for every DPoP nonce attempt so Gaxios error redaction cannot mutate and corrupt the mandatory retry; token request bodies and DPoP proofs are also redacted from thrown request configurations.
- Reassert mutation-lease ownership immediately before remote revocation and again before local deletion, including cleanup revocation after a failed connection.
- Report incomplete post-revocation local cleanup as a typed `DISCONNECT_LOCAL_CLEANUP_INCOMPLETE` recovery state instead of implying that every local artifact was removed.
- Make first-use owner-marker initialization race-safe when concurrent processes create the state directory and marker.

### Security boundary

- No send, modify, upload, share, move, or delete tools.
- No attachment or arbitrary binary download.
- No hosted token broker, plaintext secret fallback, persistent content cache, or telemetry.

### Known limitations

- This alpha remains unreleased until the owner completes and records the blocking checks in `RELEASE_CHECKLIST.md`.
- The required commit-bound two-account Gmail-and-Drive isolation test is still pending; do not use valuable accounts based on the one-account Drive smoke test.
- Text extraction intentionally supports a limited set of Gmail and Drive content shapes.
- Google Workspace administrators and Google OAuth policy can block or revoke access independently of Multi-Account MCP.
