# Security policy

Multi-Account MCP handles access to email and cloud files. Treat every release as security-sensitive software.

## Supported versions

Only the latest release on the default branch receives security fixes during the alpha period.

## Reporting a vulnerability

Please use GitHub’s private vulnerability reporting / Security Advisory flow for this repository. Do not open a public issue containing a vulnerability, token, OAuth client JSON, email content, file content, or personally identifiable information.

Include:

- affected commit/version and operating system;
- a minimal reproduction using synthetic accounts/data;
- impact and preconditions;
- whether any credential or real account may have been exposed.

Never send real Google tokens. They should be revoked immediately instead.

## Intended guarantees in 0.1.0-alpha.1

- Local STDIO transport only; no listening MCP network service.
- System-browser Google OAuth with loopback on `127.0.0.1`, random port, PKCE `S256`, random one-time state, and a ten-minute timeout.
- Per-authorization P-256 DPoP keys sender-constrain refresh tokens. The authorization-code exchange uses a code-derived proof identifier; refreshes use fresh proof identifiers, support one bounded Google nonce challenge, and have no non-DPoP refresh fallback.
- Verified Google ID-token `sub` is the durable account identity.
- Immediately before Google consent, `auth add` discloses the requested read-only access, local credential handling, MCP host/model-provider processing, and that the project operator receives nothing. It requires exact-alias acknowledgment and opens no Google authorization if that disclosure is declined.
- After OAuth, `auth add` requires a second exact-alias confirmation after showing the verified email and requested alias on stderr. No OAuth client, refresh token, or account metadata is persisted before that binding confirmation; decline or prompt failure revokes the new grant. Duplicate existing identities fail without revocation to protect the existing grant.
- Account connection and removal share a cross-process mutation lease with periodic heartbeats, ownership assertions immediately before credential mutation or remote revocation, and conservative failure when lease cleanup is uncertain. Stale locks are detected but never deleted automatically, avoiding a race that could remove a newly acquired live lock.
- Per-account DPoP-bound refresh tokens, their DPoP private JWKs, and the desktop OAuth client are stored in the OS credential vault through native bindings.
- Access tokens exist only in process memory.
- The per-account Google-client cache is reconciled against current metadata, evicting clients and captured credential closures when an account is removed or reconnected.
- Account metadata is non-secret, atomically written, mode `0600` in a mode `0700` directory, and symlink targets are rejected.
- Gmail, Drive, and userinfo data requests are hard-coded `GET` requests allowlisted to `https://gmail.googleapis.com` and `https://www.googleapis.com`.
- OAuth authorization, bounded DPoP token requests, certificate retrieval, and revocation use fixed Google endpoints; they do not share the data-request origin allowlist.
- Read-only scopes and read-only MCP tools only.
- Bounded process-local token buckets run before account resolution or Google access: global, per-named-alias, and separately for `list_accounts`. Alias bucket keys are hashed and memory is bounded.
- Runtime `mcp --services drive|gmail|both` selection removes unselected service tools from registration and `tools/list`; it does not rely on rejecting already-advertised calls.
- No content cache, search index, telemetry, or raw-content logs.
- Bounded result counts, body characters, and downloaded text bytes.
- Bounded Google JSON responses, MIME depth/part counts, attachments, and thread message counts.
- Redirect following disabled on authenticated Google API requests.
- Attachment content and unsupported binaries are not downloaded.
- Every result includes account provenance and retrieved content is labelled untrusted.
- On normal success, disconnect revokes the Google token before deleting local credentials and metadata. `--local-only` deliberately skips revocation; uncertain or incomplete cleanup fails with typed reconciliation guidance instead of claiming deletion succeeded.

## Non-guarantees

- “As secure as the native connector” cannot be claimed without the native connector’s private design, infrastructure, audits, and incident controls.
- The OS credential vault protects secrets at rest; malware or another process running as the same unlocked user may still access them.
- DPoP materially limits use of a refresh token copied without its private key, but the software DPoP key is stored in the same OS-vault account item and is exportable to the local process. It is not Secure Enclave/hardware-backed and does not protect against compromise that can retrieve the complete vault item.
- Invocation rate limits are defense in depth inside one running MCP process. Restarting the process resets them; they are not a boundary against a hostile local user or a client that can launch unlimited processes.
- The process launcher and its environment are part of the local trust boundary. `MULTI_ACCOUNT_MCP_HOME`, `APPDATA`, and `XDG_CONFIG_HOME` select an absolute local configuration root; they are never accepted as MCP tool arguments. A custom root must be a private directory controlled by the same non-elevated user, especially on Windows where Node.js mode bits do not prove ACL ownership.
- State must remain on a local filesystem. Network shares and mapped network drives are unsupported because their exclusive-create and file-identity semantics may not match a local filesystem. Reopened lock handles must have matching nonzero device and full-precision file IDs. On Windows, a pathname checkpoint may omit its device ID, but must still match the authoritative handle's exact nonzero file ID. An unavailable handle identity fails closed.
- A compromised dependency or MCP host can read data returned to the process, and the chosen MCP host may send tool results to a remote model provider under that provider's policies. Use the committed lockfile, trusted releases, and a host/provider configuration compatible with Google Limited Use.
- Google Workspace administrators can block, restrict, or revoke access at any time.
- `0.1.0-alpha.1` is macOS-first. A pre-release smoke test has exercised one sacrificial Drive account through scope rejection, OAuth, macOS Keychain persistence, a clean-process DPoP refresh, the actual MCP boundary, revocation, and cleanup. The required commit-bound two-account Gmail-and-Drive isolation test is still pending. Do not use high-value accounts until that gate is closed.
- Windows and Linux runtime/keyring behavior has not been validated and is not a supported platform claim for this alpha.
- Configured CI and local automated tests provide logic, type, build, and STDIO coverage. The limited smoke test above is not proof of two-account isolation, Gmail behavior, cross-platform keyring behavior, or end-to-end production security.

## Prompt-injection boundary

Provider-controlled account email/display names and Gmail/Drive content can contain instructions crafted to manipulate an agent. Multi-Account MCP returns these values as data and adds an explicit `untrustedExternalContent` marker, including on `list_accounts`. MCP server instructions require the host to ignore instructions inside retrieved data and forbid that content from choosing accounts or triggering tool calls. Wildcards are rejected, and an optional process-level allowlist can limit the visible aliases. If the user has not named an account, the host is instructed to list aliases, present them, and stop for a choice.

This is defense in depth, not proof that the server can cryptographically distinguish user-authored tool arguments from model-generated ones. The strongest `0.1.0-alpha.1` controls are the out-of-band process allowlist and absence of write tools. For valuable accounts, run separate narrowly allowlisted MCP processes. Do not add arbitrary URL fetches, shell execution, mail send, Drive write/share/delete, or content-driven account routing to this server.

## Secret handling rules

- Never commit or paste OAuth client JSON, refresh/access tokens, ID tokens, authorization codes, cookies, or account exports.
- Never commit, paste, log, or separately export a DPoP private JWK or proof JWT.
- Never put secrets in command-line arguments, stdout, logs, crash reports, tests, fixtures, screenshots, GBrain, Drive, or issue trackers.
- MCP JSON-RPC owns stdout. Diagnostics go to stderr and exclude Google content and secrets; the deliberate interactive `auth add` confirmation is the exception that displays the verified account email and requested alias on stderr.
- Never add a plaintext token fallback. A missing/unavailable credential vault is a hard failure.
- Preserve the prior refresh token when a refresh response omits one.
- Treat `invalid_grant` as reauthorization-required, not a retry loop.

## Stale-lock recovery

Multi-Account MCP deliberately preserves a `.accounts.lock` or `.connect.lock` that is more than ten minutes old and names a process that is no longer running. Automatic stale-lock deletion is unsafe because another process could replace the file between validation and deletion.

Recover only on the same local computer and user account that runs Multi-Account MCP:

1. Stop every MCP host and `multi-account-mcp auth` command using this state directory, then confirm no such process remains active.
2. For `.connect.lock`, first run `multi-account-mcp auth list` and review Multi-Account MCP in Google Account security. Reconcile any grant that exists on only one side before changing the lock.
3. Locate the dedicated state directory: `${MULTI_ACCOUNT_MCP_HOME}/multi-account-mcp` when that override is set; otherwise `%APPDATA%\Multi-Account MCP` on Windows, `${XDG_CONFIG_HOME}/multi-account-mcp` when that variable is set, or `~/.config/multi-account-mcp` elsewhere.
4. Move only the exact stale lock named by the error out of that directory to a private quarantine location. Never remove the state directory, `accounts.json`, the ownership marker, another lock, or any Keychain/credential-vault item as part of lock recovery.
5. Retry once. If account state is unexpected, stop, move the quarantined lock back if its original path is free, and report the issue without attaching the lock contents.

## Public/hosted release gate

The local BYO-client architecture is not sufficient for a hosted multi-user service. A remote release additionally requires:

- separate MCP OAuth 2.1 and Google OAuth trust domains—no token passthrough;
- strict tenant/account ownership checks on every request;
- KMS/HSM-backed envelope encryption and key rotation;
- protected-resource metadata, PKCE, issuer/audience/resource validation, HTTPS, and no bearer confusion;
- privacy policy, deletion process, Limited Use disclosure, terms, verified domain, and incident response;
- Google sensitive/restricted-scope verification and recurring CASA/security assessment where required;
- independent penetration testing, dependency provenance, SBOM, signed builds, secret scanning, alerting, and audit logs that exclude content.

Primary requirements: [Google Workspace API User Data and Developer Policy](https://developers.google.com/workspace/workspace-api-user-data-developer-policy), [Google OAuth best practices](https://developers.google.com/identity/protocols/oauth2/resources/best-practices), [OpenAI plugin security guidance](https://developers.openai.com/plugins/guides/security-privacy), and [MCP authorization security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations).
