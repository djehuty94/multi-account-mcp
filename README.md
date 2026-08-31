# Multi-Account MCP

Local-first, read-only MCP for multiple Gmail and Google Drive accounts.

Google, Gmail, and Google Drive are trademarks of Google LLC. This independent project is not affiliated with or endorsed by Google.

The current release is intentionally narrow:

- multiple Google accounts, each with an explicit local alias;
- Gmail search, message read, and thread read;
- Drive search, metadata read, and bounded text export;
- read-only Google scopes only;
- exact verified-email-to-alias confirmation in an interactive terminal before anything is persisted;
- DPoP-bound refresh tokens, per-account DPoP private keys, and OAuth client credentials in the operating-system credential vault;
- no mail/file content cache, telemetry, send, write, share, or delete tools.

> **Alpha/platform boundary:** `0.1.0-alpha.1` is macOS-first. One pre-release smoke test has exercised a sacrificial Drive account through OAuth, macOS Keychain, clean-process DPoP refresh, the MCP boundary, revocation, and cleanup. A commit-bound two-account Gmail-and-Drive isolation test with non-sensitive accounts is still required before using valuable data. Windows and Linux runtime/keyring support is not yet claimed.

## Why this exists

This project started because the setup motivating it lacked a reliable per-call Gmail/Drive account selector in Codex. Native availability is app-, account-, and surface-dependent and can change: OpenAI documents that [some apps support multiple connected accounts](https://help.openai.com/en/articles/20001494), while its [Google Drive connection guide](https://help.openai.com/en/articles/10929079) still tells users to choose the Google account they need. Check **Settings → Apps/Plugins → Connected accounts / Connect another account** before installing another connector.

Where native ChatGPT multi-account Gmail is available, prefer it for Gmail. Multi-Account MCP's stable value is explicit aliases on every call, local bring-your-own Google OAuth with native keyring storage, and a fixed read-only surface—especially a Drive-only surface for multiple Drives.

Other multi-account Google Workspace MCPs exist. [`adelaidasofia/google-workspace-mcp`](https://github.com/adelaidasofia/google-workspace-mcp) is a local, OS-keyring-backed full Workspace suite; [`taylorwilsdon/google_workspace_mcp`](https://github.com/taylorwilsdon/google_workspace_mcp) is a broad hosted/local implementation. Multi-Account MCP starts smaller because its first job is a clean personal trust boundary: read-only Gmail/Drive, DPoP, explicit aliases, and no telemetry—not dozens of write-capable tools. See [the landscape review](docs/LANDSCAPE.md).

## Security model

```text
Codex / local MCP client
          │ local stdio
          ▼
  Multi-Account MCP process
      ├─ account aliases + non-secret metadata → 0600 JSON
      ├─ refresh tokens + DPoP keys + client   → OS credential vault
      ├─ access tokens                          → process memory only
      └─ bounded HTTPS requests                 → Google APIs only
```

OAuth credentials and DPoP keys stay local. Bounded tool results cross STDIO to the MCP host you configure, and that host may send them to its chosen model provider under the provider's data policies; the Multi-Account MCP project operator is not in that path.

Important controls:

- OAuth Authorization Code flow with PKCE `S256`, cryptographic `state`, a single-use callback, and `127.0.0.1` on a random port.
- A separate P-256 DPoP key sender-constrains each refresh token. Code exchange and refresh use signed proofs; refresh handles Google's nonce challenge once and never falls back to an ordinary bearer refresh.
- Google ID tokens are verified and every alias is permanently bound to Google’s stable `sub` identifier. Email is display metadata, not authorization identity.
- Immediately before Google consent opens, `auth add` discloses the requested read-only access, local credential handling, and that bounded results go to the configured MCP host and may be processed by its model provider. Continuing requires typing the exact requested alias; declining stops before Google OAuth opens.
- After OAuth, `auth add` shows the verified email and requested alias on stderr and stores nothing until the user types the exact alias a second time to confirm that binding. A decline or prompt failure revokes the newly issued grant.
- Account connection and removal are serialized across processes with an owner-checked, heartbeat-renewed lease; final metadata and Keychain writes revalidate ownership before committing.
- Every Gmail/Drive tool requires exact account aliases. The all-account wildcard is rejected; searching every account means passing every alias explicitly.
- A process-level allowlist (`--accounts personal,work` or `MULTI_ACCOUNT_MCP_ALLOWED_ACCOUNTS`) can expose only a chosen subset of connected accounts to one MCP process.
- Every result carries its source account ID, alias, and email.
- Cross-account searches preserve successful results when another account is expired, blocked, or rate-limited.
- Pagination uses one-hour, process-local cursors signed and bound to the provider, account, and exact query.
- Provider-controlled account email/display names, retrieved subjects, snippets, bodies, filenames, and file contents are labelled untrusted. Server instructions forbid content-driven tool calls or account routing.
- The MCP exposes only read tools and every tool is annotated read-only/non-destructive.
- Errors and logs never include tokens, message bodies, file contents, queries, subjects, or filenames.
- Multi-Account MCP refuses to fall back to plaintext secrets if the OS credential vault is unavailable.
- Conservative process-local request budgets apply before account lookup or Google access: 60 calls/minute globally, 15 calls/minute per named alias, and 12 `list_accounts` calls/minute, each with the same-size initial burst.

This aims at the same *known categories* of control as a strong native connector, but nobody outside OpenAI can responsibly claim implementation parity with controls that are not public. See [SECURITY.md](SECURITY.md) and [the architecture](docs/ARCHITECTURE.md).

## Install for local development

Requirements: Node.js 22.12 or newer.

```bash
git clone https://github.com/djehuty94/multi-account-mcp
cd multi-account-mcp
npm ci
npm run check
npm link
```

`npm ci` uses the committed lockfile. `npm run check` type-checks, runs the tests, and builds `dist/`.

This alpha is distributed from GitHub only. The package is marked `private` to prevent accidental publication to the npm registry.

## Create the Google OAuth client

Google Auth Platform is the right Google-side setup even though Multi-Account MCP is not hosted. Configure an **installed/desktop public client**: the MCP runs locally, opens Google's consent page, and receives the one-time callback on loopback. It has no hosted backend, redirect service, or token broker. Follow [the exact OAuth setup guide](docs/GOOGLE_OAUTH_SETUP.md):

1. Create a Google Cloud project.
2. Enable the Gmail API and Google Drive API.
3. Configure the OAuth consent screen.
4. Create an OAuth client of type **Desktop app**.
5. Download its JSON temporarily outside this repository, other source checkouts, and synchronized folders; restrict it to mode `0600`.

Then connect the first account:

```bash
multi-account-mcp auth add personal --client /absolute/path/to/desktop-client.json
```

`auth add` must be run directly in an interactive terminal; piped input and a `--yes` bypass are intentionally unavailable. Immediately before opening Google consent, it explains the purpose and requested read-only access, local credential handling, and result sharing with your MCP host/model provider. You must type the exact requested alias to acknowledge that disclosure; declining stops before OAuth opens. After Google returns a verified identity, the terminal shows its email and the requested alias and requires the exact alias a second time to confirm the account binding. No OAuth client, refresh token, or account metadata is persisted before the binding confirmation. A mismatch, interruption, or prompt failure aborts the connection and revokes the new grant. A duplicate already-connected Google identity is rejected without revocation because revoking it could invalidate the existing account's grant.

The default is `--services both`. Use a narrower per-account profile whenever possible:

```bash
multi-account-mcp auth add mail-only --services gmail
multi-account-mcp auth add files-only --services drive
```

Only after successful confirmation does the flow store the OAuth client, DPoP-bound refresh token, and that account's DPoP private key in the OS credential vault. The P-256 key is vault-stored software key material, not a Secure Enclave or hardware-backed key. Add more accounts without passing the client file again:

```bash
multi-account-mcp auth add client-a
multi-account-mcp auth add client-b
multi-account-mcp auth list
multi-account-mcp doctor
```

After the first connection, run `multi-account-mcp doctor`. Once it passes and you have confirmed—without displaying or exporting values—that the OAuth client is in the OS credential vault, delete the downloaded client JSON and every stray copy.

Aliases use lowercase letters, numbers, and hyphens and start with a letter. An alias cannot be rebound while connected: changing its Google identity requires explicit removal, a fresh OAuth grant, and exact-alias confirmation.

Multi-Account MCP deliberately does not overwrite an existing alias or refresh token in place. To change an account's service profile, remove/revoke it and then add it again with the new `--services` value.

If Google reports `REAUTH_REQUIRED`, first run the normal revoke/remove command, then add the alias again with its prior service profile. If Google says the old token can no longer be revoked, confirm the grant's state in Google Account security before using `--local-only` for local cleanup.

To rotate the Desktop OAuth client or switch Google Cloud projects, remove every connected account first, then pass the new client JSON on the next `auth add`. Multi-Account MCP refuses client rotation while any account metadata remains.

Remove and revoke an account:

```bash
multi-account-mcp auth remove client-b --yes
```

`--local-only` skips Google revocation and should be used only when revocation is impossible or intentionally handled elsewhere.

## Connect the MCP

The repository is a Codex plugin (`.codex-plugin/plugin.json` + `.mcp.json`). Build it before loading it.

For the recommended multiple-Drive use case, expose only the Drive surface:

```bash
multi-account-mcp auth add personal --services drive --client /absolute/path/to/desktop-client.json
codex mcp add multi-account-mcp -- node /absolute/path/to/multi-account-mcp/dist/src/cli.js mcp --services drive
```

For a tighter trust boundary, expose only the accounts needed in that MCP process:

```bash
codex mcp add multi-account-mcp-work -- node /absolute/path/to/multi-account-mcp/dist/src/cli.js mcp --services drive --accounts client-a,client-b
```

Runtime `mcp --services drive|gmail|both` controls tool registration, not merely call-time rejection: unselected service tools are absent from `tools/list`. The default remains `both`; `gmail` and `both` preserve optional Gmail support. This runtime flag does not add OAuth scopes—each account must also have been connected with the corresponding `auth add --services` profile.

If native ChatGPT multi-account Gmail is available for your app/account/surface, use that for Gmail and run this MCP in `--services drive` mode for explicit access across multiple Drives. Optional Gmail mode remains useful when you specifically need local BYO OAuth, explicit per-call aliases, and this project's fixed read-only boundary.

If no process allowlist is supplied, all accounts that you deliberately connected are visible, but data tools still require exact aliases. When an account has not been named by the user, the MCP instructions require the host to list aliases, show them, and stop for selection.

The checked-in plugin manifest and `.mcp.json` support local Codex/plugin use; `cwd: "."` resolves the built server inside the local plugin checkout. Public ChatGPT/plugin-directory integration is not shipped in this alpha. That path needs a publicly hosted remote MCP plus its own authorization, tenant isolation, verification, and operations work, and remains future work.

### MCP, not a skill

The alpha needs only an MCP server: account access, tools, authorization, and read-only policy are capabilities enforced by the server. A skill would add optional workflow or prompting guidance; it would not strengthen authentication, authorization, or the security boundary. Such guidance can be added later without coupling it to account access.

## Tools

The default `both` surface exposes all tools below. `--services drive` or `--services gmail` removes the other service's tools from discovery entirely.

| Tool | Account selection | Behavior |
|---|---|---|
| `list_accounts` | none | Lists bounded, non-secret account metadata and aliases; output is marked untrusted |
| `search_gmail` | exact alias list | Searches messages; returns headers/snippets, partial failures, and per-account continuation cursors |
| `get_gmail_message` | exactly one alias | Returns bounded plain text + attachment metadata |
| `get_gmail_thread` | exactly one alias | Returns bounded plain text for up to 25 messages with a 250k-character thread budget |
| `search_drive` | exact alias list | Searches accessible Drives; returns metadata, partial failures, and per-account continuation cursors |
| `get_drive_file_metadata` | exactly one alias | Reads one file’s metadata |
| `read_drive_text` | exactly one alias | Reads bounded text from Docs/Slides/text files; native Sheets export is the first tab only |

There are deliberately no attachment download, send, draft, label, upload, share, move, or delete tools.

## Why Multi-Account MCP does not send email

Multi-Account MCP deliberately stops at search and read. This reflects my personal workflow: I use AI to find, read, and verify email, but I want full human control over everything that leaves my accounts.

This is a product choice, not a Gmail API limitation. The basic integration is relatively small: a fork can request Google's narrow `gmail.send` scope and call the Gmail send endpoint without rebuilding the read-only search layer. The security work matters more than the API call, though. A responsible extension should keep sending separately consented and disabled by default, show the exact account, recipients, subject, and body for real human approval, prevent retrieved content from choosing recipients, and never automatically retry an ambiguous send.

Multi-Account MCP itself will remain read-only. Contributors who add sending should treat it as a separate write-capable trust boundary rather than quietly widening the default connector.

## Google scope/compliance reality

Useful global Gmail and Drive search requires Google restricted scopes: `gmail.readonly` and `drive.readonly`. A public shared OAuth client—even for a local desktop app—or a hosted service therefore needs Google verification and can require recurring security assessment. The first open-source release uses **bring your own Google OAuth project and Desktop client**: OAuth credentials stay in your local OS credential vault and the project operates no backend or token broker. Tool results do not necessarily remain local; they are returned to the MCP host you configure and may be processed by its model provider under that provider's data policies. Desktop clients are public clients: their client ID and nominal client secret cannot be kept confidential in distributed software, so this repository never embeds a maintainer-owned client.

Google documents the relevant scope classifications in the [Gmail scope guide](https://developers.google.com/workspace/gmail/api/auth/scopes) and [Drive scope guide](https://developers.google.com/workspace/drive/api/guides/api-specific-auth). See [the setup guide](docs/GOOGLE_OAUTH_SETUP.md) before deciding between Testing and In production.

## Development

```bash
npm run typecheck
npm test
npm run build
npm run check
npm run release:check
```

The test suite covers DPoP proof/signature/nonce behavior and no-bearer fallback, account-selection requirements, local invocation budgets, stable-identity rebinding, same-identity OAuth races, cross-process mutation serialization and ambiguous-commit recovery, filesystem permissions and symlink refusal, Gmail/Drive account provenance, bounded content, query escaping, read-only MCP annotations, and a real STDIO handshake.

## Roadmap

- Commit-bound two-account Gmail-and-Drive OAuth/API isolation tests with non-sensitive accounts.
- Per-account health status and guided recovery.
- Quota-aware retry/backoff.
- Optional Drive picker mode using the narrower `drive.file` scope.
- Signed releases, SBOM, provenance, secret scanning, and independent security review.
- A remote MCP only after separate MCP OAuth, tenant isolation, KMS/HSM storage, Google verification, CASA, and incident response are in place.

Write tools are not on the Multi-Account MCP roadmap. The project intentionally preserves human control over outbound email; forks can add the comparatively small Gmail send integration under the separate-consent and confirmation boundary described above.

## License

[MIT](LICENSE)
