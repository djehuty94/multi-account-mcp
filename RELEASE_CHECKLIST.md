# v0.1.0-alpha.1 release checklist

> **STATUS: BLOCKED.** Publishing the clearly labelled source repository requires every **PRE-PUBLIC — OWNER** gate except the separately labelled live test. A tag, GitHub Release, npm publication, recommendation for valuable accounts, or “fully tested” claim additionally requires the **PRE-RELEASE — OWNER** live test, every **POST-PUBLIC — OWNER** gate, and green public CI.

The first release is local, bring-your-own OAuth, read-only, and text-only. A checked box is a factual release record, not an intention.

## Current local automated evidence

Recorded on 2026-08-31. These checks do not replace the fresh sanitized-repository, private/public CI, GitHub-settings, or live Google-account gates below.

- [x] `npm run check` passes: strict type-check, build, and 69/69 automated tests.
- [x] `npm run verify:package` passes: 65 allowlisted files, synchronized private alpha/package/plugin metadata, isolated tarball installation, and the exact four-tool Drive-only MCP surface.
- [x] The Codex plugin-creator validator accepts `.codex-plugin/plugin.json` and its `.mcp.json` reference.
- [x] `npm audit --omit=dev --audit-level=high` reports 0 vulnerabilities.
- [x] Direct production dependencies declare permissive MIT, BSD-2-Clause, or Apache-2.0 licenses.

## Pre-commit live smoke evidence (not the release gate)

Recorded on 2026-08-31 against the candidate tree before its sanitized root commit existed. This is useful implementation evidence, but it cannot satisfy the commit-bound two-account release gate below and must not be described as a full live pass.

- [x] A deliberately withheld Drive scope was rejected as `INVALID_GRANTED_SCOPES`; no account, OAuth client, or token reference was persisted.
- [x] One sacrificial Drive account completed the double alias-confirmation flow and persisted the Desktop OAuth client, DPoP-bound refresh token, and private DPoP key only in macOS Keychain.
- [x] A clean MCP process loaded the Keychain entries, completed DPoP refresh, and made an impossible-query Drive search through `search_drive` with zero files returned.
- [x] `doctor` reported one healthy connected account before cleanup.
- [x] Normal removal revoked the grant, removed alias metadata, and deleted the per-account Keychain token; the reusable OAuth client remained in Keychain.
- [x] The protected Desktop-client working copy and its uniquely content-matched downloaded JSON were permanently deleted after Keychain verification.
- [ ] Gmail, two simultaneous aliases, cross-account provenance/isolation, allowlists, partial failure, content bounding, and removal-while-the-other-account-remains still require the commit-bound two-account test below.

## PRE-PUBLIC — OWNER: name and repository identity

- [x] Record the naming-clearance method and date for **Multi-Account MCP**, with the descriptor **for Gmail & Drive**, before changing repository identity or visibility.
- [x] Confirm the repository target is exactly `djehuty94/multi-account-mcp` and that the name does not imply endorsement by Google, OpenAI, Gmail, or Google Drive.
- [x] Search the complete candidate tree for abandoned candidate names and stale repository URLs; resolve every match.
- [x] Confirm `0.1.0-alpha.1` is synchronized anywhere a version is declared.

Identity record:

- Reviewer: Codex-assisted exact-match review; owner selected the name
- Review date: 2026-08-31
- Clearance method or reference: Exact-phrase web search, exact GitHub target lookup, exact npm package lookup, and candidate-tree identity scan
- Result: PASS for source publication (not a legal trademark opinion)
- Sanitized notes: The phrase is descriptive and has been used generically, but no exact target repository or npm package existed at review time. The README carries an explicit Google/Gmail/Drive non-affiliation notice.

## PRE-RELEASE — OWNER: live two-account safety test

This may run before or after the source repository becomes public. Until it passes, the README, security policy, changelog, and repository description must distinguish the limited pre-commit one-account Drive smoke evidence from the still-pending commit-bound two-account Gmail-and-Drive isolation gate. No release tag or recommendation for valuable accounts is allowed.

Use two sacrificial Google accounts containing only synthetic mail and files. Never paste credentials, tokens, authorization URLs or codes, message/file contents, or real email addresses into this checklist, issues, commits, screenshots, or logs.

- [ ] Record the exact candidate commit SHA below before testing.
- [x] Create a dedicated bring-your-own Google Cloud project, enable only the Gmail and Drive APIs, and leave it inert until the hardened candidate is ready.
- [ ] Configure Google Auth Platform for External/Testing with an owner-selected support email and monitored developer contact; add only the two sacrificial identities as test users; provide Privacy Policy/Terms URLs where Google requires them; then create a **Desktop app** public OAuth client—not a Web application client.
- [ ] Download the Desktop client JSON outside the repository, every source checkout, and cloud-synchronized folders; set owner-only mode `0600`; never copy its values into logs, evidence, issues, commits, or chat.
- [ ] Enable only the Gmail and Drive APIs and confirm the consent screen requests only the documented identity and read-only service scopes.
- [ ] Run `auth add` without an interactive TTY and confirm it fails before opening OAuth or touching the vault/metadata store; confirm there is no `--yes` bypass.
- [ ] For each `auth add`, confirm the terminal immediately discloses the requested read-only purpose/access, local credential handling, MCP host/model-provider sharing, and that the project operator receives nothing; confirm declining or entering the wrong alias stops before Google consent opens and leaves the vault/metadata unchanged.
- [ ] Connect sacrificial account A under one alias and sacrificial account B under a different alias. For each, first type the exact alias to acknowledge the pre-consent disclosure; after OAuth, confirm the terminal shows the verified email and requested alias and persists nothing until the tester types the exact alias a second time to bind the account.
- [ ] Authorize a fresh sacrificial identity for a new alias, then type the wrong alias or interrupt confirmation; confirm no local client/token/metadata change remains and only the newly issued grant is revoked.
- [ ] Attempt to reconnect account A's Google identity under a second alias; confirm it fails without overwriting the existing account and without revoking account A's working grant.
- [ ] Without displaying or exporting secret values, confirm both DPoP-bound refresh tokens, their per-account DPoP private keys, and the OAuth client are in macOS Keychain; confirm access tokens remain process-local and no plaintext secret file appears in the repository or Multi-Account MCP state directory.
- [ ] Run `doctor` successfully after the OAuth client has been imported into Keychain, then delete the downloaded client JSON and all stray copies; confirm later account authorization works from the vault-stored client.
- [ ] Stop all MCP/auth processes, start a clean process, and make one harmless read with each alias. Because access tokens are never persisted, success must exercise the vault-loaded DPoP refresh path, including Google's nonce challenge when issued, with no bearer-refresh fallback.
- [ ] Confirm `auth list` and `doctor` expose only safe metadata and report a healthy state.
- [ ] Start the MCP from a clean build and confirm it advertises only the documented read-only tools.
- [ ] Start separate `mcp --services drive` and `mcp --services gmail` processes; confirm `tools/list` contains `list_accounts` plus exactly the three selected-service tools and no tools for the unselected service.
- [ ] Search Gmail separately in account A and account B; confirm every result has the correct account provenance and no result crosses aliases.
- [ ] Read one synthetic message and thread from each account; confirm text and attachment metadata are bounded and attachments are not downloaded.
- [ ] Search Drive separately in account A and account B; confirm every result has the correct account provenance and no result crosses aliases.
- [ ] Read one synthetic text file or native Google document from each account; confirm bounded text output and binary rejection.
- [ ] Run one explicitly named two-account search and confirm partial failures remain isolated to the affected account.
- [ ] Start an MCP process with a one-account allowlist and confirm the other alias is neither listed nor usable.
- [ ] Exercise the `list_accounts`, per-alias, and global local invocation budgets with synthetic/no-content calls; confirm they fail as `MCP_RATE_LIMITED` before account lookup/Google access, expose only an integer retry interval, and reset only when the process restarts.
- [ ] Place a harmless instruction-like string in synthetic mail/file content and confirm it is marked untrusted and cannot select accounts or trigger a write action.
- [ ] Revoke/remove account A and confirm its local credential and metadata disappear while account B continues to work.
- [ ] Review terminal output, local state, and generated files; confirm no query, subject, filename, body, file content, token, or authorization code was persisted or logged.

Evidence record (non-sensitive only):

- Candidate commit SHA:
- Test date and tester:
- macOS and Node.js versions:
- Synthetic aliases used:
- Result: BLOCKED / PASS
- Sanitized notes or follow-up issue links:

## PRE-PUBLIC — OWNER: manual source and package review

- [ ] Review `git status --short`; every intended file is accounted for and no local credential or generated content is staged.
- [ ] Review the complete staged diff, including source, tests, package manifest, lockfile, plugin manifest, MCP configuration, legal files, and GitHub workflow files.
- [ ] Inspect all commit author/committer identities and confirm no private email address or unintended personal metadata will enter public history.
- [ ] Run `git diff --cached --check` with no whitespace errors.
- [ ] Run a credential scan across both the staged tree and Git history; investigate every match rather than relying only on filenames.
- [ ] Confirm the cleared product identity and repository target match the identity record above.
- [ ] Confirm the package contents contain only intended runtime, plugin, documentation, privacy, terms, security, and license files.
- [ ] Confirm `package.json` remains `"private": true`, no npm publication script/configuration is present, and the source alpha is documented as GitHub-only.
- [ ] Confirm `0.1.0-alpha.1` matches exactly in `package.json`, `package-lock.json`, `.codex-plugin/plugin.json`, the changelog, and every release artifact or description.
- [ ] Validate `.codex-plugin/plugin.json` against the supported Codex plugin manifest schema/tool; confirm its MCP entrypoint, privacy/terms URLs, identity, version, and read-only capability match `.mcp.json`, `package.json`, and the documented surface.
- [ ] Check the package file list against an automated allowlist, install the packed tarball into an empty temporary directory, and complete an MCP handshake/tool-list smoke test from that installation.
- [ ] Confirm direct dependency licenses are compatible with MIT distribution.
- [ ] Confirm no shared Google OAuth client, real account identifier, private URL, local absolute path, or personal data is present.

Review record:

- Candidate commit SHA:
- Reviewer:
- Review date:
- Result: BLOCKED / PASS
- Sanitized notes or follow-up issue links:

## PRE-PUBLIC — OWNER: create the sanitized repository

- [ ] Create a **brand-new private** repository whose exact target is `djehuty94/multi-account-mcp`.
- [ ] Populate it from the reviewed candidate tree as a new sanitized root history. Do not change the visibility of the predecessor working repository, repoint its `origin`, push its Git history/tags, or push any of its local or remote-tracking refs to the public target.
- [ ] From a fresh clone of the new private repository, confirm its complete commit graph and every ref contain only the intended sanitized Multi-Account MCP history and the approved public author identity—no predecessor commits, private emails, secrets, local paths, or unrelated files.
- [ ] Compare the fresh clone's candidate tree with the reviewed source/package allowlist and record the exact commit SHA used by private CI and all later release checks.

## PRE-PUBLIC: private CI and reproducible verification

- [ ] `npm ci` succeeds from a clean checkout using the committed lockfile.
- [ ] `npm run check` succeeds locally on Node.js 22.
- [ ] Automated DPoP tests validate ES256 proof signatures/claims, authorization-code-derived proof IDs, random refresh proof IDs, exactly one valid nonce retry, malformed-key rejection, refresh single-flight behavior, and absence of a bearer-refresh fallback.
- [ ] GitHub CI succeeds in the private repository on Ubuntu, macOS, and Windows with the exact minimum supported Node.js 22.12.0.
- [ ] The packaging job validates the actual tarball against the file allowlist, installs it in an empty directory, and completes a Drive-only MCP handshake with the exact documented tool set.
- [ ] `npm audit` reports no unresolved production vulnerability accepted without a documented decision.
- [ ] A clean Codex MCP installation starts, completes the standard-input/output handshake, lists only the intended tools, and shuts down cleanly.
- [ ] All README install commands and internal documentation links work from the candidate commit.
- [ ] The naming and manual-review evidence records both say PASS for the same candidate commit.
- [ ] If the live test is still pending, every public-facing alpha warning accurately says so and no release tag is present.
- [ ] The owner explicitly approves the controlled change to public visibility.
- [ ] Review all private GitHub Actions logs for secrets or private data before changing visibility.

## Controlled visibility transition

- [ ] Make only the new sanitized `djehuty94/multi-account-mcp` repository public. Do not change the visibility of the predecessor working repository, and do not tag, release, publish, or announce the new repository yet.

## POST-PUBLIC — OWNER: GitHub security settings and green checks

Immediately after visibility changes, configure and verify the controls that are available to the public repository. If a listed control is unavailable, record the exact reason and compensating control rather than silently skipping it.

- [ ] Enable private vulnerability reporting so the link in `SECURITY.md` and the issue-template security link work.
- [ ] Enable Dependabot alerts and Dependabot security updates.
- [ ] Enable secret scanning and push protection.
- [ ] Enable CodeQL default setup for JavaScript/TypeScript, or record why an equivalent checked-in analysis workflow is used.
- [ ] Set the default GitHub Actions token permission to read repository contents only and disable workflow approval bypass where practical.
- [ ] Treat `.github/rulesets/main.json` and `.github/rulesets/release-tags.json` as configuration templates only: import or recreate them in GitHub, configure any repository-specific actor/check identifiers, enable them, and inspect the effective settings. Merely committing these JSON files does not activate protection.
- [ ] Verify the effective `main` ruleset requires the CI workflow, blocks force pushes and deletion, and requires branches to be up to date before merge; verify the effective release-tag ruleset prevents unauthorized tag updates/deletion.
- [ ] Confirm only trusted maintainers can change repository visibility, security settings, rulesets, Actions settings, and releases.
- [ ] Confirm repository description, topics, license detection, security policy, and default branch are correct.
- [ ] Trigger or observe CI on the public default branch and wait until Ubuntu, macOS, Windows, and packaging checks are green.
- [ ] Wait for secret-scanning backfill and CodeQL analysis to finish; confirm there are no unresolved secret-scanning, CodeQL, or high/critical dependency alerts.
- [ ] From a logged-out browser, verify the public clone, license, security-reporting link, workflow status, issue forms, and repository metadata.

Settings record:

- Owner who verified settings:
- Verification date:
- Result: BLOCKED / PASS
- Sanitized notes:

## POST-PUBLIC — OWNER: release decision

- [ ] The live two-account safety-test record says PASS for this candidate commit.
- [ ] The post-public settings record says PASS.
- [ ] Public CI is green for the reviewed candidate commit.
- [ ] The alpha warnings and known limitations accurately match the candidate.
- [ ] No npm publication is planned unless the owner separately verifies package-name ownership, provenance, and prerelease tagging.
- [ ] The owner explicitly approves tagging, creating the prerelease, and announcing it.

Only after every item above is complete:

- [ ] Create a signed annotated tag `v0.1.0-alpha.1` from the reviewed candidate commit.
- [ ] Create a GitHub **prerelease** from that tag with the known limitations and safety warning.
- [ ] Verify the published tag, release notes, and any release assets from a logged-out browser.
- [ ] Announce the release without promising native-connector security parity or production readiness.
- [ ] Monitor private vulnerability reports, dependency alerts, CI, and public issues during the alpha.
