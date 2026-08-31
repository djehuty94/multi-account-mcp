import { APP_ID } from "../constants.js";
import { normalizeDpopPrivateJwk } from "../auth/google-oauth-client.js";
import { MultiAccountMcpError } from "../errors.js";
import type {
  GoogleOAuthClientCredentials,
  SecretVault,
  StoredGoogleTokens,
} from "../types.js";
import { assertValidAlias } from "../policy/input.js";

interface KeyringEntry {
  getPassword(): string | null;
  setPassword(password: string): void;
  deletePassword(): boolean;
}

type KeyringEntryConstructor = new (service: string, account: string) => KeyringEntry;

function isMissingEntry(error: unknown): boolean {
  return error instanceof Error && /not found|no entry|no matching/i.test(error.message);
}

function parseJsonSecret(raw: string, label: string): unknown {
  if (Buffer.byteLength(raw, "utf8") > 16_384) {
    throw new MultiAccountMcpError(
      `${label} in the operating-system credential vault is malformed. Remove and reconnect it.`,
      "INVALID_KEYRING_SECRET",
    );
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new MultiAccountMcpError(
      `${label} in the operating-system credential vault is malformed. Remove and reconnect it.`,
      "INVALID_KEYRING_SECRET",
    );
  }
}

function validBoundedSecret(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum &&
    !/[\u0000-\u001f\u007f]/.test(value);
}

function parseOAuthClient(raw: string): GoogleOAuthClientCredentials {
  const parsed = parseJsonSecret(raw, "OAuth client") as Partial<GoogleOAuthClientCredentials> | null;
  if (
    !parsed ||
    !validBoundedSecret(parsed.clientId, 512) ||
    !/^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$/.test(parsed.clientId) ||
    !validBoundedSecret(parsed.clientSecret, 512)
  ) {
    throw new MultiAccountMcpError(
      "OAuth client in the operating-system credential vault is malformed. Remove and reconnect it.",
      "INVALID_KEYRING_SECRET",
    );
  }
  return { clientId: parsed.clientId, clientSecret: parsed.clientSecret };
}

function parseTokens(raw: string, alias: string): StoredGoogleTokens {
  const parsed = parseJsonSecret(raw, `Tokens for ${alias}`) as Partial<StoredGoogleTokens> | null;
  if (
    !parsed ||
    parsed.version !== 1 ||
    !validBoundedSecret(parsed.refreshToken, 8_192) ||
    (parsed.tokenType !== undefined && !validBoundedSecret(parsed.tokenType, 64)) ||
    (parsed.scope !== undefined && !validBoundedSecret(parsed.scope, 4_096))
  ) {
    throw new MultiAccountMcpError(
      `Tokens for ${alias} in the operating-system credential vault are malformed. Remove and reconnect it.`,
      "INVALID_KEYRING_SECRET",
    );
  }
  let dpopPrivateJwk;
  try {
    dpopPrivateJwk = normalizeDpopPrivateJwk(parsed.dpopPrivateJwk);
  } catch {
    throw new MultiAccountMcpError(
      `Tokens for ${alias} in the operating-system credential vault do not contain a valid DPoP private key. Remove and reconnect it; bearer refresh is disabled.`,
      "INVALID_KEYRING_SECRET",
    );
  }
  return {
    version: 1,
    refreshToken: parsed.refreshToken,
    dpopPrivateJwk,
    ...(parsed.tokenType ? { tokenType: parsed.tokenType } : {}),
    ...(parsed.scope ? { scope: parsed.scope } : {}),
  };
}

export class SystemKeyringVault implements SecretVault {
  private async entry(account: string): Promise<KeyringEntry> {
    try {
      const module = await import("@napi-rs/keyring");
      const Entry = module.Entry as KeyringEntryConstructor;
      return new Entry(APP_ID, account);
    } catch (error) {
      throw new MultiAccountMcpError(
        "The operating-system credential vault is unavailable. Multi-Account MCP refuses to fall back to plaintext token storage.",
        "KEYRING_UNAVAILABLE",
        { cause: error instanceof Error ? error.name : "unknown" },
      );
    }
  }

  private async read(account: string): Promise<string | null> {
    try {
      return (await this.entry(account)).getPassword();
    } catch (error) {
      if (isMissingEntry(error)) return null;
      if (error instanceof MultiAccountMcpError) throw error;
      throw new MultiAccountMcpError(
        "Could not read the operating-system credential vault.",
        "KEYRING_READ_FAILED",
      );
    }
  }

  private async write(account: string, value: string): Promise<void> {
    try {
      (await this.entry(account)).setPassword(value);
    } catch (error) {
      if (error instanceof MultiAccountMcpError) throw error;
      throw new MultiAccountMcpError(
        "Could not write the operating-system credential vault.",
        "KEYRING_WRITE_FAILED",
      );
    }
  }

  async getOAuthClient(): Promise<GoogleOAuthClientCredentials | null> {
    const raw = await this.read("oauth-client");
    return raw ? parseOAuthClient(raw) : null;
  }

  async setOAuthClient(credentials: GoogleOAuthClientCredentials): Promise<void> {
    const validated = parseOAuthClient(JSON.stringify(credentials));
    await this.write("oauth-client", JSON.stringify(validated));
  }

  async getTokens(alias: string): Promise<StoredGoogleTokens | null> {
    assertValidAlias(alias);
    const raw = await this.read(`account:${alias}`);
    return raw ? parseTokens(raw, alias) : null;
  }

  async setTokens(alias: string, tokens: StoredGoogleTokens): Promise<void> {
    assertValidAlias(alias);
    const validated = parseTokens(JSON.stringify(tokens), alias);
    await this.write(`account:${alias}`, JSON.stringify(validated));
  }

  async deleteTokens(alias: string): Promise<boolean> {
    assertValidAlias(alias);
    const account = `account:${alias}`;
    if ((await this.read(account)) === null) return false;
    try {
      return (await this.entry(account)).deletePassword();
    } catch (error) {
      if (isMissingEntry(error)) return false;
      if (error instanceof MultiAccountMcpError) throw error;
      throw new MultiAccountMcpError(
        "Could not remove credentials from the operating-system credential vault.",
        "KEYRING_DELETE_FAILED",
      );
    }
  }
}
