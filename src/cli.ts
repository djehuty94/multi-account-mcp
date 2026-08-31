#!/usr/bin/env node

import { createInterface } from "node:readline/promises";
import {
  AccountService,
  type AccountBindingRequest,
  type DataUseDisclosureRequest,
} from "./auth/account-service.js";
import { SERVICE_SCOPES } from "./constants.js";
import { MultiAccountMcpError, safeErrorMessage } from "./errors.js";
import { runMcpServer } from "./mcp/server.js";
import { assertValidAlias } from "./policy/input.js";
import { AccountMetadataStore } from "./storage/metadata-store.js";
import { SystemKeyringVault } from "./storage/keyring-vault.js";
import type { GoogleService } from "./types.js";

const HELP = `Multi-Account MCP — local-first, read-only access to multiple Gmail and Google Drive accounts

Usage:
  multi-account-mcp auth add <alias> [--services gmail|drive|both] [--client /path/to/desktop-client.json] [--no-open]
  multi-account-mcp auth list
  multi-account-mcp auth remove <alias> --yes [--local-only]
  multi-account-mcp doctor
  multi-account-mcp mcp [--services drive|gmail|both] [--accounts personal,work]

Security defaults:
  - Gmail and Drive are read-only.
  - Prefer native ChatGPT multi-account Gmail where available; use MCP --services drive for multiple Drives.
  - Native connected-account availability: https://help.openai.com/en/articles/20001494
  - Refresh tokens and the OAuth client stay in the OS credential vault.
  - Email/file content is never cached on disk.
  - Adding an account requires interactive confirmation of the verified email and exact alias.
  - MCP --services removes unselected service tools from the advertised tool surface.
  - Removing an account revokes its Google token unless --local-only is explicit.
`;

function requireInteractiveTerminal(): void {
  if (process.stdin.isTTY !== true || process.stderr.isTTY !== true) {
    throw new MultiAccountMcpError(
      "auth add requires an interactive terminal. Re-run it directly and confirm the verified account-to-alias binding there.",
      "INTERACTIVE_TTY_REQUIRED",
    );
  }
}

function terminalLiteral(value: string): string {
  return JSON.stringify(value).replace(
    /[\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

async function confirmExactAlias(alias: string, prompt: string): Promise<boolean> {
  requireInteractiveTerminal();
  const readline = createInterface({
    input: process.stdin,
    output: process.stderr,
    terminal: true,
  });
  const abortController = new AbortController();
  const handleInterrupt = (): void => abortController.abort();
  readline.once("SIGINT", handleInterrupt);
  try {
    const answer = await readline.question(
      prompt,
      { signal: abortController.signal },
    );
    return answer === alias;
  } catch (error) {
    if (abortController.signal.aborted) return false;
    throw error;
  } finally {
    readline.off("SIGINT", handleInterrupt);
    readline.close();
  }
}

async function confirmDataUseDisclosure(
  request: Readonly<DataUseDisclosureRequest>,
): Promise<boolean> {
  console.error("Data-use disclosure — shown immediately before Google consent:");
  console.error(
    `- Purpose and access: read-only ${request.services.join(" + ")} data is fetched only for tool requests you make through your chosen MCP host.`,
  );
  console.error(
    "- Local handling: OAuth credentials and per-account DPoP keys stay in the OS credential vault; Multi-Account MCP has no backend, telemetry, or persistent mail/file-content cache.",
  );
  console.error(
    "- Sharing: bounded tool results are returned to your configured MCP host and may be processed by its model provider under their data policies. The Multi-Account MCP project operator receives nothing.",
  );
  return confirmExactAlias(
    request.alias,
    `Type the exact alias ${terminalLiteral(request.alias)} to acknowledge this disclosure and continue to Google consent: `,
  );
}

async function confirmAccountBinding(request: Readonly<AccountBindingRequest>): Promise<boolean> {
  console.error(`Google verified account: ${terminalLiteral(request.email)}`);
  console.error(`Requested local alias: ${terminalLiteral(request.alias)}`);
  return confirmExactAlias(
    request.alias,
    `Type the exact alias ${terminalLiteral(request.alias)} to confirm this binding: `,
  );
}

function takeOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith("--")) {
    throw new MultiAccountMcpError(`${name} requires a value.`, "INVALID_ARGUMENT");
  }
  args.splice(index, 2);
  return value;
}

function takeFlag(args: string[], name: string): boolean {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function assertNoExtraArgs(args: string[]): void {
  if (args.length > 0) {
    throw new MultiAccountMcpError(`Unexpected argument: ${args[0]}`, "INVALID_ARGUMENT");
  }
}

function parseServices(value: string | undefined): GoogleService[] {
  if (!value || value === "both") return ["gmail", "drive"];
  if (value === "gmail" || value === "drive") return [value];
  throw new MultiAccountMcpError("--services must be drive, gmail, or both.", "INVALID_ARGUMENT");
}

async function runAuth(args: string[]): Promise<void> {
  const action = args.shift();
  const store = new AccountMetadataStore();
  const vault = new SystemKeyringVault();
  const accounts = new AccountService(store, vault);

  if (action === "list") {
    assertNoExtraArgs(args);
    const connected = await accounts.list();
    if (connected.length === 0) {
      console.log("No Google accounts are connected.");
      return;
    }
    for (const account of connected) {
      const services = (Object.entries(SERVICE_SCOPES) as Array<[GoogleService, string]>)
        .filter(([, scope]) => account.scopes.includes(scope))
        .map(([service]) => service)
        .join("+");
      console.log(`${account.alias}\t${account.email}\tread-only ${services || "identity only"}`);
    }
    return;
  }

  if (action === "add") {
    const alias = args.shift();
    if (!alias) throw new MultiAccountMcpError("auth add requires an alias.", "INVALID_ARGUMENT");
    const clientFile = takeOption(args, "--client");
    const services = parseServices(takeOption(args, "--services"));
    const noOpen = takeFlag(args, "--no-open");
    assertNoExtraArgs(args);
    requireInteractiveTerminal();
    console.error(
      `Multi-Account MCP will request read-only ${services.join(" + ")} access. Google classifies global Gmail/Drive scopes as restricted.`,
    );
    const account = await accounts.connect({
      alias,
      confirmAccountBinding,
      confirmDataUseDisclosure,
      openBrowser: !noOpen,
      services,
      ...(clientFile ? { clientFile } : {}),
    });
    console.log(`Connected ${account.email} as "${account.alias}".`);
    return;
  }

  if (action === "remove") {
    const alias = args.shift();
    if (!alias) throw new MultiAccountMcpError("auth remove requires an alias.", "INVALID_ARGUMENT");
    const yes = takeFlag(args, "--yes");
    const localOnly = takeFlag(args, "--local-only");
    assertNoExtraArgs(args);
    if (!yes) {
      throw new MultiAccountMcpError(
        "Refusing to remove credentials without --yes. By default this also revokes the token at Google.",
        "CONFIRMATION_REQUIRED",
      );
    }
    const removed = await accounts.disconnect(alias, !localOnly);
    console.log(removed ? `Removed "${alias}".` : `No account named "${alias}" was connected.`);
    return;
  }

  throw new MultiAccountMcpError("Unknown auth command. Use `multi-account-mcp --help`.", "INVALID_ARGUMENT");
}

async function doctor(): Promise<void> {
  const store = new AccountMetadataStore();
  const vault = new SystemKeyringVault();
  const accounts = await store.list();
  const clientConfigured = (await vault.getOAuthClient()) !== null;
  const missingTokens: string[] = [];
  for (const account of accounts) {
    if (!(await vault.getTokens(account.alias))) missingTokens.push(account.alias);
  }

  console.log(`OAuth client in OS vault: ${clientConfigured ? "yes" : "no"}`);
  console.log(`Connected accounts: ${accounts.length}`);
  console.log(`Accounts missing vault tokens: ${missingTokens.length ? missingTokens.join(", ") : "none"}`);
  if (!clientConfigured || missingTokens.length > 0) process.exitCode = 1;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args.shift();

  if (command === "mcp") {
    const allowed = takeOption(args, "--accounts");
    const services = parseServices(takeOption(args, "--services"));
    assertNoExtraArgs(args);
    const allowedAliases = allowed
      ? allowed.split(",").map((alias) => assertValidAlias(alias.trim()))
      : undefined;
    if (allowedAliases?.length === 0) {
      throw new MultiAccountMcpError("--accounts requires at least one alias.", "INVALID_ARGUMENT");
    }
    await runMcpServer({
      services,
      ...(allowedAliases ? { allowedAliases } : {}),
    });
    return;
  }
  if (command === "auth") {
    await runAuth(args);
    return;
  }
  if (command === "doctor") {
    assertNoExtraArgs(args);
    await doctor();
    return;
  }
  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.log(HELP);
    return;
  }
  throw new MultiAccountMcpError(`Unknown command: ${command}`, "INVALID_ARGUMENT");
}

main().catch((error: unknown) => {
  const code = error instanceof MultiAccountMcpError ? error.code : "UNEXPECTED_ERROR";
  const message = error instanceof MultiAccountMcpError
    ? safeErrorMessage(error)
    : "Unexpected Multi-Account MCP error. No secret or Google content was logged.";
  console.error(`${code}: ${message}`);
  process.exitCode = 1;
});
