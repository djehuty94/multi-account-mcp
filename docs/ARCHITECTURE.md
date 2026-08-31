# Architecture and trust boundaries

## Local 0.1.0-alpha.1

```text
┌──────────────────────────────┐       selected prompts/tool results       ┌──────────────────────────────┐
│ Configured MCP host          │──────────────────────────────────────────►│ Chosen model provider        │
│ (runs the local MCP process) │                                           │ (may be remote)              │
└──────────────┬───────────────┘                                           └──────────────────────────────┘
               │ JSON-RPC over inherited stdio
┌──────────────▼───────────────┐
│ Multi-Account MCP process    │
│                              │
│ tool schemas + policy        │
│ account resolver             │
│ per-account OAuth clients    │
│ Gmail / Drive adapters       │
└──────┬──────────┬────────────┘
       │          │
       │          └──────────────► Google HTTPS APIs
       │
       ├─ non-secret metadata ──► accounts.json (0600)
       └─ refresh tokens + per-account DPoP keys
                              └─► OS credential vault
```

STDIO is the MCP process-to-host trust boundary. Credentials and DPoP private keys do not cross it, but bounded Gmail/Drive tool results do. The configured MCP host may send those results to its chosen model provider, which may be remote and has its own data policies. The Multi-Account MCP project operator is not in this data path and receives nothing. The local process has no HTTP listener except the one-time Google OAuth callback bound to `127.0.0.1` during `auth add`.

## Account identity

Each connection has:

- random local UUID (`id`), used in result provenance;
- user-chosen alias, used in tool arguments;
- verified Google OpenID Connect `sub`, used to prevent rebinding/cross-account mixups;
- email/name for display only;
- exact granted scopes;
- a keyring entry reference derived from the validated alias.

The account registry rejects:

- reusing an alias for a different Google `sub`;
- connecting the same Google `sub` under another alias;
- malformed aliases that could affect paths or key names;
- symlinked metadata paths.

Before serving Gmail or Drive, a newly created per-account client calls Google userinfo and compares the live `sub` with stored metadata. A mismatch stops before any mailbox or Drive request.

## OAuth sequence

```text
CLI       Loopback       System browser       Google
 │            │                │                 │
 ├─ show data-use disclosure   │                 │
 ├─ require exact alias acknowledgment           │
 ├─ bind 127.0.0.1:0           │                 │
 ├─ state + PKCE verifier      │                 │
 ├─ generate P-256 DPoP key    │                 │
 ├────────────────────────────►│─ authorization ─►│
 │            │◄──────────── callback(code,state)│
 │◄──────── code (single use)  │                 │
 ├──────── code + verifier + signed DPoP proof ─►│
 │◄──────── tokens + signed ID token ────────────│
 ├─ verify signature/aud/exp/sub/email           │
 ├─ show verified email + requested alias        │
 ├─ require exact alias in interactive terminal  │
 ├─ store refresh token + DPoP key in OS vault   │
 └─ store non-secret metadata                    │
```

Immediately before any Google authorization opens, the CLI discloses the requested read-only access, local credential handling, and that bounded results go to the configured MCP host and may be processed by its model provider; the user must type the exact requested alias to continue. The server then requests OpenID/email identity plus the per-account service profile selected at authorization: `gmail.readonly`, `drive.readonly`, or both. Each authorization generates a P-256 key. The code exchange carries an ES256 DPoP proof whose identifier is derived from the authorization code. Refreshes carry fresh proof identifiers and retry exactly once when Google returns a valid `use_dpop_nonce` challenge; there is no ordinary refresh-token fallback. Google access tokens remain bearer tokens and stay in memory.

No Google authorization opens if the pre-consent disclosure is declined. After OAuth, no OAuth client, refresh token, DPoP private key, or account metadata is persisted before the verified email-to-alias binding is explicitly confirmed with a second exact-alias entry. A declined or failed binding confirmation revokes the new grant; a duplicate existing Google identity is rejected without revocation to avoid invalidating its existing grant. The DPoP-bound refresh token and software private JWK are stored together in the OS vault only after confirmation; the access token and ID token are not. The private JWK is exportable software key material, not hardware-backed. Changing a profile requires remove/revoke followed by a fresh add, avoiding in-place refresh-token replacement.

Connection and removal run under one cross-process mutation lease. Its owner record is mode `0600`, heartbeat-renewed, and revalidated before Keychain or metadata mutation by both an unpredictable ownership token and the exact BigInt device/inode identity of the opened file and current pathname. The shorter atomic-metadata lock uses the same rule, and an unavailable or changed identity fails closed. A stale lock whose recorded process is gone is preserved and reported rather than automatically deleted: validation followed by deletion is not atomic and could otherwise remove a replacement live lock. If lease ownership or cleanup becomes uncertain after Google authorization, the operation does not automatically revoke a grant that another process may now own; it stops with explicit reconciliation and Google Account security guidance. State on network or mapped drives is unsupported because those filesystems may not provide local exclusive-create and identity semantics.

## Tool policy

Every external-data tool is read-only/non-destructive and returns:

- stable source account ID;
- account alias/email;
- bounded data;
- an untrusted-content security marker.

Search tools require exact account aliases and reject wildcards. Single-record reads require exactly one alias, so a Gmail message ID or Drive file ID can never silently fall through to another account. Optional process-level alias allowlists bound the accounts visible to one MCP launch. When no alias has been named, server instructions require the host to present `list_accounts` and stop for the user to choose.

Before metadata lookup, vault access, or Google access, a bounded in-process limiter charges one global token and one token for each distinct, syntactically valid alias. The defaults allow a 60-call global burst refilling at 60/minute and a 15-call per-alias burst refilling at 15/minute. `list_accounts` has a separate 12-call burst refilling at 12/minute. Alias bucket keys are SHA-256 hashes, the bucket map is capped, and only fully refilled buckets are evicted so alias churn cannot erase debt. This state is intentionally local to the process and resets on restart.

The runtime service surface is selected with `mcp --services drive|gmail|both` (default `both`). In Drive-only mode, `tools/list` contains `list_accounts` and the three Drive tools; Gmail-only mode contains `list_accounts` and the three Gmail tools. Unselected tools are never registered. Where [native ChatGPT connected-account support](https://help.openai.com/en/articles/20001494) provides multi-account Gmail for the relevant app/account/surface, the recommended setup is native Gmail plus this MCP in Drive-only mode for multiple Drives; optional Gmail support remains available for local BYO-OAuth workflows.

Multi-account search failures are isolated per account. Continuation cursors are signed with an ephemeral process key and bound to the provider, stable account ID, exact query, and one-hour expiry; continuing a result uses a single account. Restarting the process intentionally invalidates outstanding cursors.

## Egress

Gmail, Drive, and userinfo data requests are hard-coded `GET` requests and accept only these HTTPS origins:

- `https://gmail.googleapis.com`
- `https://www.googleapis.com`

OAuth authorization, bounded DPoP token requests, certificate retrieval, and revocation use fixed Google endpoints; they are not routed through the data-client origin allowlist above. No tool accepts a URL. File IDs and message/thread IDs are encoded as path segments. Drive query text is escaped before insertion into the provider query language.

## Future remote architecture

A remote MCP would add an independent resource-server identity and must never treat Google tokens as MCP bearer tokens:

```text
MCP client ── MCP OAuth token ──► hosted MCP resource server
                                           │
                                           └─ separate Google token ──► Google
```

This is a different product/security phase, not a transport toggle.
