import type { OAuth2Client } from "google-auth-library";
import { StringDecoder } from "node:string_decoder";
import { IDENTITY_SCOPES, LIMITS, SERVICE_SCOPES } from "../constants.js";
import { MultiAccountMcpError } from "../errors.js";
import type { AccountMetadata, GoogleService, SecretVault } from "../types.js";
import {
  createGoogleOAuthClient,
  normalizeDpopPrivateJwk,
  refreshGoogleAccessTokenWithDpop,
} from "../auth/google-oauth-client.js";

const ALLOWED_ORIGINS = new Set([
  "https://gmail.googleapis.com",
  "https://www.googleapis.com",
]);

function assertAllowedGoogleUrl(url: string): void {
  const parsed = new URL(url);
  if (!ALLOWED_ORIGINS.has(parsed.origin)) {
    throw new MultiAccountMcpError("Blocked an unexpected outbound URL.", "OUTBOUND_URL_BLOCKED");
  }
}

function classifyGoogleError(error: unknown): MultiAccountMcpError {
  const candidate = error as {
    response?: { status?: number; data?: unknown };
    code?: string | number;
    message?: string;
  };
  const status = candidate.response?.status ?? candidate.code;
  const serialized = JSON.stringify(candidate.response?.data ?? "");
  if (status === 401 || /invalid_grant/i.test(serialized)) {
    return new MultiAccountMcpError(
      "Google authorization is no longer valid. Remove/revoke the alias, then add it again with its prior --services profile. If Google confirms the grant is already invalid, use --local-only only after checking Google Account security.",
      "REAUTH_REQUIRED",
    );
  }
  if (status === 403) {
    return new MultiAccountMcpError(
      "Google refused this read request. Check that the API is enabled, the scope is granted, and Workspace policy allows it.",
      "GOOGLE_FORBIDDEN",
    );
  }
  if (status === 429) {
    return new MultiAccountMcpError("Google rate-limited this account. Retry later.", "GOOGLE_RATE_LIMITED");
  }
  return new MultiAccountMcpError("A Google API request failed.", "GOOGLE_API_FAILED", {
    status: typeof status === "number" ? status : undefined,
  });
}

function decodeTextBuffer(buffer: Buffer, contentType: string | null): {
  text: string;
  charsetFallback: boolean;
} {
  const match = /charset\s*=\s*["']?([^;\s"']+)/i.exec(contentType ?? "");
  const raw = (match?.[1] ?? "utf-8").toLowerCase();
  const charset = raw === "utf8" ? "utf-8" : raw === "latin1" ? "iso-8859-1" : raw;
  const supported = new Set(["utf-8", "us-ascii", "iso-8859-1", "windows-1252"]);
  if (!supported.has(charset)) {
    return { text: new StringDecoder("utf8").write(buffer), charsetFallback: true };
  }
  return {
    text: charset === "utf-8"
      ? new StringDecoder("utf8").write(buffer)
      : new TextDecoder(charset).decode(buffer),
    charsetFallback: false,
  };
}

export class GoogleAccountClient {
  constructor(
    readonly account: AccountMetadata,
    private readonly client: OAuth2Client,
  ) {}

  async json<T>(options: {
    url: string;
    params?: Record<string, unknown>;
  }): Promise<T> {
    assertAllowedGoogleUrl(options.url);
    try {
      const response = await this.client.request<T>({
        url: options.url,
        method: "GET",
        params: options.params,
        timeout: LIMITS.requestTimeoutMs,
        retry: false,
        maxRedirects: 0,
        maxContentLength: LIMITS.maxGoogleJsonBytes,
        follow: 0,
        size: LIMITS.maxGoogleJsonBytes,
        headers: { "Accept-Encoding": "identity" },
      });
      return response.data;
    } catch (error) {
      if (error instanceof MultiAccountMcpError) throw error;
      throw classifyGoogleError(error);
    }
  }

  async text(options: {
    url: string;
    params?: Record<string, unknown>;
    maxBytes?: number;
  }): Promise<{
    text: string;
    truncated: boolean;
    contentType?: string;
    charsetFallback: boolean;
  }> {
    assertAllowedGoogleUrl(options.url);
    const maxBytes = options.maxBytes ?? LIMITS.maxDownloadedBytes;
    try {
      const response = await this.client.request<NodeJS.ReadableStream>({
        url: options.url,
        method: "GET",
        params: options.params,
        timeout: LIMITS.requestTimeoutMs,
        responseType: "stream",
        retry: false,
        validateStatus: () => true,
        maxRedirects: 0,
        follow: 0,
        size: maxBytes + 1,
        headers: { "Accept-Encoding": "identity" },
      });

      if (response.status < 200 || response.status >= 300) {
        const rejectedStream = response.data as NodeJS.ReadableStream;
        if ("destroy" in rejectedStream && typeof rejectedStream.destroy === "function") {
          rejectedStream.destroy();
        }
        throw classifyGoogleError({ response: { status: response.status } });
      }

      const chunks: Buffer[] = [];
      let total = 0;
      let truncated = false;
      const stream = response.data as NodeJS.ReadableStream & AsyncIterable<Buffer | Uint8Array | string>;
      for await (const chunk of stream) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (total + buffer.length > maxBytes) {
          const remaining = Math.max(0, maxBytes - total);
          if (remaining > 0) chunks.push(buffer.subarray(0, remaining));
          truncated = true;
          if ("destroy" in stream && typeof stream.destroy === "function") stream.destroy();
          break;
        }
        chunks.push(buffer);
        total += buffer.length;
      }

      const header = response.headers.get("content-type");
      const decoded = decodeTextBuffer(Buffer.concat(chunks), header);
      return {
        text: decoded.text,
        truncated,
        charsetFallback: decoded.charsetFallback,
        ...(typeof header === "string" ? { contentType: header } : {}),
      };
    } catch (error) {
      if (error instanceof MultiAccountMcpError) throw error;
      throw classifyGoogleError(error);
    }
  }
}

export class GoogleClientFactory {
  private readonly clients = new Map<string, Promise<GoogleAccountClient>>();

  constructor(
    private readonly vault: SecretVault,
    private readonly makeOAuthClient: typeof createGoogleOAuthClient = createGoogleOAuthClient,
  ) {}

  reconcileAccounts(accounts: readonly AccountMetadata[]): number {
    const activeKeys = new Set(
      accounts.map((account) => `${account.id}:${account.googleSub}:${account.updatedAt}`),
    );
    let removed = 0;
    for (const key of this.clients.keys()) {
      if (!activeKeys.has(key)) {
        this.clients.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  forAccount(account: AccountMetadata, service: GoogleService): Promise<GoogleAccountClient> {
    const requiredScopes = [...IDENTITY_SCOPES, SERVICE_SCOPES[service]];
    const missingScope = requiredScopes.find((scope) => !account.scopes.includes(scope));
    if (missingScope) {
      throw new MultiAccountMcpError(
        `Account "${account.alias}" has not authorized ${service}. Reconnect it with the required service profile.`,
        "MISSING_REQUIRED_SCOPE",
      );
    }
    const cacheKey = `${account.id}:${account.googleSub}:${account.updatedAt}`;
    const cached = this.clients.get(cacheKey);
    if (cached) return cached;
    for (const key of this.clients.keys()) {
      if (key.startsWith(`${account.id}:`)) this.clients.delete(key);
    }
    const created = this.create(account).catch((error) => {
      this.clients.delete(cacheKey);
      throw error;
    });
    this.clients.set(cacheKey, created);
    return created;
  }

  private async create(account: AccountMetadata): Promise<GoogleAccountClient> {
    const [credentials, tokens] = await Promise.all([
      this.vault.getOAuthClient(),
      this.vault.getTokens(account.alias),
    ]);
    if (!credentials || !tokens) {
      throw new MultiAccountMcpError(
        `Credentials are missing for account "${account.alias}". Reconnect it.`,
        "ACCOUNT_CREDENTIALS_MISSING",
      );
    }

    const dpopPrivateJwk = normalizeDpopPrivateJwk(tokens.dpopPrivateJwk);
    const client = this.makeOAuthClient(credentials);
    client.setCredentials({});
    let storedTokens = { ...tokens, dpopPrivateJwk };
    let currentNonce: string | undefined;
    let refreshInFlight: Promise<{ access_token: string; expiry_date: number }> | null = null;
    client.refreshHandler = () => {
      if (refreshInFlight) return refreshInFlight;
      refreshInFlight = (async () => {
        const refreshed = await refreshGoogleAccessTokenWithDpop(
          client,
          credentials,
          storedTokens,
          currentNonce,
        );
        currentNonce = refreshed.nonce;
        const nextStoredTokens = {
          version: 1 as const,
          refreshToken: refreshed.refreshToken,
          dpopPrivateJwk,
          ...(refreshed.tokenType ? { tokenType: refreshed.tokenType } : {}),
          ...(refreshed.scope ? { scope: refreshed.scope } : {}),
        };
        if (
          nextStoredTokens.refreshToken !== storedTokens.refreshToken ||
          nextStoredTokens.tokenType !== storedTokens.tokenType ||
          nextStoredTokens.scope !== storedTokens.scope
        ) {
          await this.vault.setTokens(account.alias, nextStoredTokens);
          storedTokens = nextStoredTokens;
        }
        return {
          access_token: refreshed.accessToken,
          expiry_date: refreshed.expiryDate,
        };
      })().finally(() => {
        refreshInFlight = null;
      });
      return refreshInFlight;
    };

    let identity: { sub?: string; email?: string };
    try {
      const response = await client.request<{ sub?: string; email?: string }>({
        url: "https://www.googleapis.com/oauth2/v3/userinfo",
        method: "GET",
        timeout: LIMITS.requestTimeoutMs,
        retry: false,
        maxRedirects: 0,
        maxContentLength: 100_000,
        follow: 0,
        size: 100_000,
        headers: { "Accept-Encoding": "identity" },
      });
      identity = response.data;
    } catch (error) {
      throw classifyGoogleError(error);
    }

    if (!identity.sub || identity.sub !== account.googleSub) {
      throw new MultiAccountMcpError(
        `Credential identity mismatch for account "${account.alias}". No Gmail or Drive request was made.`,
        "ACCOUNT_IDENTITY_MISMATCH",
      );
    }
    return new GoogleAccountClient(account, client);
  }
}
