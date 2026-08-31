import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type JsonWebKey,
} from "node:crypto";
import { OAuth2Client } from "google-auth-library";
import { LIMITS } from "../constants.js";
import { MultiAccountMcpError } from "../errors.js";
import type {
  DpopPrivateJwk,
  GoogleOAuthClientCredentials,
  StoredGoogleTokens,
} from "../types.js";

export const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const MAX_DPOP_NONCE_LENGTH = 1_024;
const REDACTED_TOKEN_REQUEST = "<<REDACTED TOKEN REQUEST>>";

interface GoogleTokenResponse {
  access_token?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
  token_type?: string;
}

export interface DpopTokenExchangeResult {
  tokens: GoogleTokenResponse;
  nonce?: string;
}

export interface DpopRefreshResult {
  accessToken: string;
  expiryDate: number;
  refreshToken: string;
  tokenType?: string;
  scope?: string;
  nonce?: string;
}

function canonicalP256Value(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.length === 32 && decoded.toString("base64url") === value;
  } catch {
    return false;
  }
}

function nodePrivateJwk(value: DpopPrivateJwk): JsonWebKey {
  return {
    kty: value.kty,
    crv: value.crv,
    x: value.x,
    y: value.y,
    d: value.d,
  };
}

export function normalizeDpopPrivateJwk(value: unknown): DpopPrivateJwk {
  const candidate = value as Partial<DpopPrivateJwk> | null;
  if (
    !candidate ||
    candidate.kty !== "EC" ||
    candidate.crv !== "P-256" ||
    !canonicalP256Value(candidate.x) ||
    !canonicalP256Value(candidate.y) ||
    !canonicalP256Value(candidate.d)
  ) {
    throw new MultiAccountMcpError(
      "The stored DPoP private key is missing or malformed. Remove and reconnect the account; bearer refresh is disabled.",
      "INVALID_DPOP_PRIVATE_KEY",
    );
  }
  const normalized: DpopPrivateJwk = {
    kty: "EC",
    crv: "P-256",
    x: candidate.x,
    y: candidate.y,
    d: candidate.d,
  };
  try {
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(Buffer.from(normalized.d, "base64url"));
    const derivedPoint = ecdh.getPublicKey(undefined, "uncompressed");
    if (
      derivedPoint.length !== 65 ||
      derivedPoint[0] !== 0x04 ||
      derivedPoint.subarray(1, 33).toString("base64url") !== normalized.x ||
      derivedPoint.subarray(33, 65).toString("base64url") !== normalized.y
    ) {
      throw new Error("public coordinates do not match private scalar");
    }
    const privateKey = createPrivateKey({ key: nodePrivateJwk(normalized), format: "jwk" });
    const derived = createPublicKey(privateKey).export({ format: "jwk" });
    if (
      derived.kty !== "EC" ||
      derived.crv !== "P-256" ||
      derived.x !== normalized.x ||
      derived.y !== normalized.y
    ) {
      throw new Error("public coordinates do not match private key");
    }
  } catch {
    throw new MultiAccountMcpError(
      "The stored DPoP private key is missing or malformed. Remove and reconnect the account; bearer refresh is disabled.",
      "INVALID_DPOP_PRIVATE_KEY",
    );
  }
  return normalized;
}

export function normalizeDpopNonce(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_DPOP_NONCE_LENGTH ||
    !/^[A-Za-z0-9._~+/=-]+$/.test(value)
  ) {
    throw new MultiAccountMcpError(
      "Google returned an invalid DPoP nonce. No token request was retried.",
      "INVALID_DPOP_NONCE",
    );
  }
  return value;
}

export function generateDpopPrivateJwk(): DpopPrivateJwk {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return normalizeDpopPrivateJwk(privateKey.export({ format: "jwk" }));
}

export function authorizationCodeDpopJti(code: string): string {
  return createHash("sha256").update(code, "utf8").digest("base64url");
}

export function createDpopProof(
  privateJwk: DpopPrivateJwk,
  options: { jti: string; nonce?: string; issuedAt?: number },
): string {
  const normalized = normalizeDpopPrivateJwk(privateJwk);
  if (!options.jti || options.jti.length > 512 || /[\u0000-\u001f\u007f]/.test(options.jti)) {
    throw new MultiAccountMcpError("The DPoP JWT ID is invalid.", "INVALID_DPOP_JTI");
  }
  const issuedAt = options.issuedAt ?? Math.floor(Date.now() / 1_000);
  if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) {
    throw new MultiAccountMcpError("The DPoP issued-at timestamp is invalid.", "INVALID_DPOP_IAT");
  }
  const nonce = options.nonce === undefined ? undefined : normalizeDpopNonce(options.nonce);
  const header = {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: normalized.x,
      y: normalized.y,
    },
  };
  const payload = {
    jti: options.jti,
    htm: "POST",
    htu: GOOGLE_TOKEN_ENDPOINT,
    ...(nonce ? { nonce } : {}),
    iat: issuedAt,
  };
  const encodedHeader = Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign("sha256", Buffer.from(signingInput, "ascii"), {
    key: createPrivateKey({ key: nodePrivateJwk(normalized), format: "jwk" }),
    dsaEncoding: "ieee-p1363",
  });
  if (signature.length !== 64) {
    throw new MultiAccountMcpError("Could not create a valid ES256 DPoP proof.", "DPOP_SIGNING_FAILED");
  }
  return `${signingInput}.${signature.toString("base64url")}`;
}

function responseNonce(headers: unknown, required = false): string | undefined {
  const candidate = headers && typeof headers === "object" && "get" in headers &&
      typeof (headers as { get?: unknown }).get === "function"
    ? (headers as { get(name: string): string | null }).get("dpop-nonce")
    : undefined;
  if (candidate === null || candidate === undefined || candidate === "") {
    if (required) {
      throw new MultiAccountMcpError(
        "Google requested a DPoP nonce retry without a valid DPoP-Nonce header.",
        "INVALID_DPOP_NONCE",
      );
    }
    return undefined;
  }
  return normalizeDpopNonce(candidate);
}

function redactTokenRequestError<T extends { config?: unknown; response?: unknown }>(data: T): T {
  const redactConfig = (value: unknown): void => {
    if (!value || typeof value !== "object") return;
    const config = value as { data?: unknown; body?: unknown; headers?: unknown };
    config.data = REDACTED_TOKEN_REQUEST;
    config.body = REDACTED_TOKEN_REQUEST;
    config.headers = new Headers({
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: REDACTED_TOKEN_REQUEST,
    });
  };

  redactConfig(data.config);
  if (data.response && typeof data.response === "object") {
    const response = data.response as { config?: unknown; data?: unknown; headers?: unknown };
    redactConfig(response.config);
    const responseError = response.data && typeof response.data === "object"
      ? (response.data as { error?: unknown }).error
      : undefined;
    response.data = typeof responseError === "string" ? { error: responseError } : {};

    if (
      response.headers &&
      typeof response.headers === "object" &&
      "get" in response.headers &&
      "forEach" in response.headers &&
      "delete" in response.headers &&
      typeof (response.headers as { get?: unknown }).get === "function" &&
      typeof (response.headers as { forEach?: unknown }).forEach === "function" &&
      typeof (response.headers as { delete?: unknown }).delete === "function"
    ) {
      const headers = response.headers as {
        get(name: string): string | null;
        forEach(callback: (value: string, key: string) => void): void;
        delete(name: string): void;
      };
      const nonce = headers.get("dpop-nonce");
      const names: string[] = [];
      headers.forEach((_value, name) => names.push(name));
      for (const name of names) {
        if (name.toLowerCase() !== "dpop-nonce") headers.delete(name);
      }
      if (!nonce) headers.delete("dpop-nonce");
    }
  }
  return data;
}

async function requestToken(
  client: OAuth2Client,
  parameters: URLSearchParams,
  proof: string,
): Promise<DpopTokenExchangeResult> {
  const response = await client.transporter.request<GoogleTokenResponse>({
    url: GOOGLE_TOKEN_ENDPOINT,
    method: "POST",
    data: parameters,
    timeout: LIMITS.requestTimeoutMs,
    retry: false,
    maxRedirects: 0,
    maxContentLength: 1_000_000,
    follow: 0,
    size: 1_000_000,
    errorRedactor: redactTokenRequestError,
    headers: {
      "Accept-Encoding": "identity",
      "Content-Type": "application/x-www-form-urlencoded",
      DPoP: proof,
    },
  });
  const nonce = responseNonce(response.headers);
  return { tokens: response.data, ...(nonce ? { nonce } : {}) };
}

export async function exchangeAuthorizationCodeWithDpop(
  client: OAuth2Client,
  credentials: GoogleOAuthClientCredentials,
  options: { code: string; codeVerifier: string; redirectUri: string },
  privateJwk: DpopPrivateJwk,
): Promise<DpopTokenExchangeResult> {
  const proof = createDpopProof(privateJwk, {
    jti: authorizationCodeDpopJti(options.code),
  });
  return requestToken(client, new URLSearchParams({
    grant_type: "authorization_code",
    code: options.code,
    redirect_uri: options.redirectUri,
    client_id: credentials.clientId,
    client_secret: credentials.clientSecret,
    code_verifier: options.codeVerifier,
  }), proof);
}

function isDpopNonceChallenge(error: unknown): boolean {
  const candidate = error as {
    message?: unknown;
    status?: unknown;
    response?: { status?: unknown; data?: unknown };
  };
  const responseError = candidate.response?.data &&
      typeof candidate.response.data === "object"
    ? (candidate.response.data as { error?: unknown }).error
    : undefined;
  // Gaxios v7 consumes a WHATWG Response adapter body into its error message and
  // may leave response.data undefined. Accept only Google's exact error code,
  // paired with the exact 400 status; challengeNonce separately requires and
  // validates the bounded DPoP-Nonce header before a single retry is possible.
  const errorCode = responseError ?? candidate.message;
  const status = candidate.response?.status ?? candidate.status;
  return status === 400 && errorCode === "use_dpop_nonce";
}

function challengeNonce(error: unknown): string {
  return responseNonce(
    (error as { response?: { headers?: unknown } }).response?.headers,
    true,
  ) as string;
}

function assertBoundedToken(value: unknown, label: string, maximum = 8_192): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new MultiAccountMcpError(`Google returned an invalid ${label}.`, "INVALID_DPOP_TOKEN_RESPONSE");
  }
  return value;
}

export async function refreshGoogleAccessTokenWithDpop(
  client: OAuth2Client,
  credentials: GoogleOAuthClientCredentials,
  stored: StoredGoogleTokens,
  nonce?: string,
): Promise<DpopRefreshResult> {
  const privateJwk = normalizeDpopPrivateJwk(stored.dpopPrivateJwk);
  const refreshToken = assertBoundedToken(stored.refreshToken, "refresh token");
  const attempt = (nonce: string | undefined) => requestToken(
    client,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
    }),
    createDpopProof(privateJwk, {
      jti: randomBytes(24).toString("base64url"),
      ...(nonce ? { nonce } : {}),
    }),
  );

  let result: DpopTokenExchangeResult;
  try {
    result = await attempt(nonce === undefined ? undefined : normalizeDpopNonce(nonce));
  } catch (error) {
    if (!isDpopNonceChallenge(error)) throw error;
    const nonce = challengeNonce(error);
    try {
      result = await attempt(nonce);
    } catch (retryError) {
      if (isDpopNonceChallenge(retryError)) {
        throw new MultiAccountMcpError(
          "Google rejected the DPoP nonce retry. No further token request was attempted.",
          "DPOP_NONCE_RETRY_REJECTED",
        );
      }
      throw retryError;
    }
  }

  const accessToken = assertBoundedToken(result.tokens.access_token, "access token", 16_384);
  const expiresIn = result.tokens.expires_in;
  if (!Number.isSafeInteger(expiresIn) || (expiresIn ?? 0) < 1 || (expiresIn ?? 0) > 86_400) {
    throw new MultiAccountMcpError(
      "Google returned an invalid access-token lifetime.",
      "INVALID_DPOP_TOKEN_RESPONSE",
    );
  }
  if (result.tokens.token_type !== undefined && result.tokens.token_type.toLowerCase() !== "bearer") {
    throw new MultiAccountMcpError(
      "Google returned an unexpected DPoP access-token type.",
      "INVALID_DPOP_TOKEN_RESPONSE",
    );
  }
  const nextRefreshToken = result.tokens.refresh_token === undefined
    ? refreshToken
    : assertBoundedToken(result.tokens.refresh_token, "refresh token");
  const scope = result.tokens.scope === undefined
    ? stored.scope
    : assertBoundedToken(result.tokens.scope, "scope", 4_096);
  const tokenType = result.tokens.token_type ?? stored.tokenType;
  return {
    accessToken,
    expiryDate: Date.now() + (expiresIn as number) * 1_000,
    refreshToken: nextRefreshToken,
    ...(tokenType ? { tokenType } : {}),
    ...(scope ? { scope } : {}),
    ...(result.nonce ? { nonce: result.nonce } : {}),
  };
}

export function createGoogleOAuthClient(
  credentials?: GoogleOAuthClientCredentials,
  redirectUri?: string,
): OAuth2Client {
  return new OAuth2Client({
    ...(credentials
      ? { clientId: credentials.clientId, clientSecret: credentials.clientSecret }
      : {}),
    ...(redirectUri ? { redirectUri } : {}),
    transporterOptions: {
      timeout: LIMITS.requestTimeoutMs,
      maxRedirects: 0,
      maxContentLength: 1_000_000,
      follow: 0,
      size: 1_000_000,
      retry: false,
      headers: { "Accept-Encoding": "identity" },
    },
  });
}
