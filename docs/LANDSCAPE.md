# Multi-account Gmail/Drive MCP landscape

Research date: 2026-08-31. Primary project/official sources only.

## Existing options

| Project | Multi-account | Gmail + Drive | Trust model | Assessment |
|---|---:|---:|---|---|
| [`adelaidasofia/google-workspace-mcp`](https://github.com/adelaidasofia/google-workspace-mcp) | Yes, explicit account per call | Yes | Local; OS credential store | Closest current full-suite alternative: cross-platform, Keychain/Credential Manager/Secret Service backed, and much broader. Its 63-tool surface includes mail send, downloads, and many Drive/Docs/Sheets writes, and its plugin reports a first-run anonymous install signal unless opted out. Choose it when breadth matters more than this project's deliberately narrow no-telemetry/read-only boundary. |
| [`aaronsb/google-workspace-mcp`](https://github.com/aaronsb/google-workspace-mcp) | Yes, explicit email per call | Yes | Local STDIO; credentials in mode-0600 JSON | Small and useful behavioral reference, but current token storage is plaintext-at-rest and the inspected OAuth flow lacks PKCE. Harden before valuable accounts. |
| [`taylorwilsdon/google_workspace_mcp`](https://github.com/taylorwilsdon/google_workspace_mcp) | Yes | Yes | Local or remote OAuth 2.1; several storage backends | Broadest/mature feature set and better future hosted base, but much larger attack surface. Historical wrong-account issues make isolation tests release-critical. |
| [Composio connected accounts](https://docs.composio.dev/docs/authentication/managing-multiple-connected-accounts) | Yes | Yes | Hosted third party stores/refreshes tokens | Fast UX benchmark, but adds a cloud processor and is not the desired local/open-source trust boundary. |
| [Google Workspace remote MCP servers](https://developers.google.com/workspace/guides/configure-mcp-servers) | Not documented as one aggregated selector | Separate Gmail/Drive servers | Google-hosted, Developer Preview | Strong provider-native direction to watch, but not one multi-account Gmail+Drive surface today. |
| [`googleworkspace/cli`](https://github.com/googleworkspace/cli) | No (removed) | Yes | Native OS keychain | Useful security reference, but its current product does not provide the required multi-account MCP surface. |

## Build vs adopt decision

The feature already exists, so Multi-Account MCP should not pretend it invented multi-account Google MCP. The gap worth solving is a deliberately small and auditable trust boundary:

- PKCE and stable identity binding;
- DPoP-bound refresh tokens with no bearer-refresh fallback;
- OS-native secure secret storage with no plaintext fallback;
- Gmail/Drive read-only only;
- explicit source account on every call and result;
- no arbitrary API executor or write surface;
- no persistent content cache;
- no telemetry;
- content marked untrusted;
- cross-account isolation tests.

The local MVP is therefore an independent thin implementation informed by these projects. If hosted/team deployment becomes the near-term product, contributing hardening upstream to the Taylor Wilsdon project—or building on its remote architecture—deserves reevaluation before expanding Multi-Account MCP.
