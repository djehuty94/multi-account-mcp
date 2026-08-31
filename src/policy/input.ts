import { MultiAccountMcpError } from "../errors.js";
import { LIMITS } from "../constants.js";
import type { AccountMetadata } from "../types.js";

const ALIAS_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

export function assertValidAlias(alias: string): string {
  if (!ALIAS_PATTERN.test(alias)) {
    throw new MultiAccountMcpError(
      "Account aliases must start with a lowercase letter and contain only lowercase letters, numbers, or hyphens (maximum 32 characters).",
      "INVALID_ALIAS",
    );
  }
  return alias;
}

export function resolveAccountSelection(
  selectors: string[],
  accounts: AccountMetadata[],
): AccountMetadata[] {
  if (selectors.length === 0) {
    throw new MultiAccountMcpError(
      "Select one or more account aliases explicitly.",
      "ACCOUNT_SELECTION_REQUIRED",
    );
  }

  if (selectors.includes("*")) {
    throw new MultiAccountMcpError(
      "The all-account wildcard is disabled. Pass the exact account aliases the user named.",
      "INVALID_ACCOUNT_SELECTION",
    );
  }

  const selected = selectors.map((alias) => {
    assertValidAlias(alias);
    const account = accounts.find((candidate) => candidate.alias === alias);
    if (!account) {
      throw new MultiAccountMcpError(`No connected account has alias "${alias}".`, "ACCOUNT_NOT_FOUND");
    }
    return account;
  });

  const unique = [...new Map(selected.map((account) => [account.alias, account])).values()];
  if (unique.length > LIMITS.maxAccountsPerCall) {
    throw new MultiAccountMcpError(
      `A single call may access at most ${LIMITS.maxAccountsPerCall} accounts.`,
      "TOO_MANY_ACCOUNTS",
    );
  }
  return unique;
}

export function clampInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value)) {
    throw new MultiAccountMcpError("Numeric limits must be whole numbers.", "INVALID_LIMIT");
  }
  return Math.min(Math.max(value, minimum), maximum);
}

export function escapeGoogleQueryLiteral(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}
