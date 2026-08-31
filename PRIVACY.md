# Multi-Account MCP local privacy notice

Effective: 2026-08-31

Multi-Account MCP `0.1.0-alpha.1` runs locally on your computer. The project does not operate a backend, analytics service, token broker, telemetry collector, or content index.

## Data processed

When you invoke a tool, the local process requests the minimum bounded Gmail or Google Drive data needed for that invocation and returns it to your MCP host. It does not persist message bodies, subjects, snippets, filenames, file contents, searches, or attachments.

Non-secret account metadata—local ID, alias, Google stable account identifier, display email/name, granted scopes, and timestamps—is stored locally in `accounts.json`. OAuth client credentials, DPoP-bound refresh tokens, and per-account DPoP private keys are stored in your operating-system credential vault. Access tokens remain in process memory.

## Data sharing

Multi-Account MCP communicates directly with Google’s OAuth, Gmail, Drive, and userinfo endpoints. Tool results are provided to the MCP host you chose to run and may then be processed by that host's chosen model provider. The Multi-Account MCP project operator is not in this data path and receives no credentials, account metadata, queries, or tool results. No other sharing is built into the project.

Your MCP host and model provider have their own data policies. Do not use Multi-Account MCP with a host or provider you do not trust, and configure their retention and training controls appropriately for the connected data.

## Retention and deletion

Multi-Account MCP retains only account metadata and credentials required to reconnect. On normal success, `multi-account-mcp auth remove <alias> --yes` revokes the Google grant before deleting the local token and account metadata. `--local-only` deliberately skips Google revocation and removes only local state. A failed or interrupted removal can leave Google authorization or local state that requires reconciliation; do not assume deletion completed. Follow the typed error guidance, run `multi-account-mcp doctor`, and review the app under Google Account security before using one explicit `--local-only` cleanup when instructed. OS backups or credential-vault synchronization may have separate retention behavior controlled by your operating system.

## Google API Limited Use

Use of information received from Google APIs must comply with the [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy), including Limited Use requirements. The Multi-Account MCP software and project operator do not use Google Workspace data to train or improve a general-purpose AI model. Because tool results may be processed by the MCP host's chosen model provider, you must choose and configure a host/provider whose handling is compatible with Google Limited Use—including the applicable restriction on training or improving general-purpose AI models—and with your organization's policies. Do not connect Google data if you cannot establish that compatibility.
