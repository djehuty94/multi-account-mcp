# Contributing to Multi-Account MCP

Thank you for helping make Multi-Account MCP for Gmail & Drive safer and easier to audit.

## Alpha boundary

Version `0.1.0-alpha.1` is deliberately small:

- local MCP over standard input/output;
- bring-your-own Google OAuth project;
- explicit account selection;
- read-only Gmail and Google Drive access;
- bounded text results only;
- secrets in the operating-system credential vault;
- no hosted service, write tools, attachment downloads, content cache, or telemetry.

A proposal outside that boundary is welcome for discussion, but it requires an explicit threat model and must not be slipped into an otherwise unrelated pull request.

## Set up a development checkout

Use Node.js 22.12 or newer and npm with the committed lockfile:

```bash
npm ci
npm run check
```

Create a focused branch, keep the diff small, and match the existing TypeScript and Markdown style. Do not connect a real or valuable Google account just to develop or run the automated tests.

## Before opening a pull request

1. Add tests for new behavior and regressions.
2. Run `npm run check`.
3. Review the entire diff for secrets and private data.
4. Update documentation when commands, tool schemas, permissions, limits, or security behavior change.
5. Explain every added dependency, network destination, OAuth scope, or persistence mechanism.

Never commit or paste OAuth client files, tokens, authorization URLs or codes, email/file contents, account exports, screenshots containing private data, or raw production logs. Use synthetic fixtures and sacrificial accounts.

## Design expectations

- Keep account aliases explicit; never silently fan out across every connected account.
- Preserve source-account provenance on every result.
- Treat Gmail and Drive content as untrusted external data.
- Keep responses, downloads, parsing depth, and concurrency bounded.
- Fail closed when the credential vault or identity check is unavailable.
- Send MCP protocol output only to standard output; diagnostics belong on standard error and must exclude user content.
- Do not add a write capability or broader Google scope without a separate, reviewed capability design.

## Bugs, features, and security reports

Use the issue forms for bugs and feature requests. Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/djehuty94/multi-account-mcp/security/advisories/new), never through a public issue.

By contributing, you agree that your contribution is provided under the repository's MIT License.
