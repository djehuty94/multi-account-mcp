import { randomBytes, timingSafeEqual } from "node:crypto";
import { constants as fsConstants, open } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { spawn } from "node:child_process";
import { CodeChallengeMethod, OAuth2Client } from "google-auth-library";
import { IDENTITY_SCOPES, LIMITS, SERVICE_SCOPES } from "../constants.js";
import { MultiAccountMcpError } from "../errors.js";
import type { GoogleOAuthClientCredentials, GoogleService, StoredGoogleTokens } from "../types.js";
import {
  createGoogleOAuthClient,
  exchangeAuthorizationCodeWithDpop,
  generateDpopPrivateJwk,
} from "./google-oauth-client.js";

interface GoogleClientFile {
  installed?: {
    client_id?: string;
    client_secret?: string;
  };
}

export interface OAuthIdentity {
  googleSub: string;
  email: string;
  displayName?: string;
}

export interface OAuthResult {
  identity: OAuthIdentity;
  tokens: StoredGoogleTokens;
  grantedScopes: string[];
}

export async function revokeGoogleToken(
  token: string,
  client: OAuth2Client = createGoogleOAuthClient(),
): Promise<void> {
  await client.transporter.request({
    url: client.getRevokeTokenURL(token).toString(),
    method: "POST",
    timeout: LIMITS.requestTimeoutMs,
    retry: false,
    maxRedirects: 0,
    maxContentLength: 100_000,
    follow: 0,
    size: 100_000,
    headers: { "Accept-Encoding": "identity" },
  });
}

interface LoopbackListener {
  redirectUri: string;
  waitForCode: Promise<string>;
  close(): Promise<void>;
}

function stateMatches(expected: string, actual: string): boolean {
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(actual);
  return expectedBytes.length === actualBytes.length && timingSafeEqual(expectedBytes, actualBytes);
}

function browserCommand(url: string): { command: string; args: string[] } {
  if (process.platform === "darwin") return { command: "open", args: [url] };
  if (process.platform === "win32") {
    return { command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", url] };
  }
  return { command: "xdg-open", args: [url] };
}

function openSystemBrowser(url: string): void {
  const { command, args } = browserCommand(url);
  const child = spawn(command, args, { detached: true, stdio: "ignore", shell: false });
  child.on("error", () => {
    console.error(`Could not open the browser automatically. Open this URL:\n${url}`);
  });
  child.unref();
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function startLoopbackListener(expectedState: string): Promise<LoopbackListener> {
  let resolveCode!: (code: string) => void;
  let rejectCode!: (error: Error) => void;
  let settled = false;

  const waitForCode = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });

  const server = createServer((request, response) => {
    if (settled) {
      response.writeHead(409, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("This authorization request has already been used.");
      return;
    }

    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method !== "GET" || url.pathname !== "/oauth2/callback") {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found.");
      return;
    }

    const state = url.searchParams.get("state") ?? "";
    if (!stateMatches(expectedState, state)) {
      response.writeHead(400, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      response.end("<h2>Multi-Account MCP rejected this callback.</h2><p>You may close this tab.</p>");
      return;
    }

    const error = url.searchParams.get("error");
    const code = url.searchParams.get("code") ?? "";

    if (error) {
      settled = true;
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      response.end("<h2>Multi-Account MCP authorization was cancelled.</h2><p>You may close this tab.</p>");
      rejectCode(new MultiAccountMcpError("Google authorization was cancelled.", "OAUTH_CANCELLED"));
      return;
    }

    if (!code) {
      response.writeHead(400, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      });
      response.end("<h2>Multi-Account MCP rejected this callback.</h2><p>You may close this tab.</p>");
      return;
    }

    settled = true;
    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    response.end("<h2>Authorization received.</h2><p>Return to the terminal to verify and explicitly confirm the account-to-alias binding before anything is stored.</p>");
    resolveCode(code);
  });

  server.on("clientError", (_error, socket) => socket.destroy());
  server.listen({ host: "127.0.0.1", port: 0, exclusive: true });
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    await closeServer(server);
    throw new MultiAccountMcpError("Could not start the local OAuth callback.", "OAUTH_CALLBACK_FAILED");
  }

  const timer = setTimeout(() => {
    if (settled) return;
    settled = true;
    rejectCode(new MultiAccountMcpError(
      "Google authorization timed out after 10 minutes. Close the old browser tab and run auth add again; its callback listener is no longer active.",
      "OAUTH_TIMEOUT",
    ));
    void closeServer(server);
  }, LIMITS.oauthTimeoutMs);
  timer.unref();

  return {
    redirectUri: `http://127.0.0.1:${address.port}/oauth2/callback`,
    waitForCode: waitForCode.finally(() => clearTimeout(timer)),
    close: () => closeServer(server),
  };
}

export async function loadOAuthClientFile(path: string): Promise<GoogleOAuthClientCredentials> {
  let parsed: GoogleClientFile;
  try {
    const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
    const nonBlocking = "O_NONBLOCK" in fsConstants ? fsConstants.O_NONBLOCK : 0;
    const handle = await open(path, fsConstants.O_RDONLY | noFollow | nonBlocking);
    try {
      const stats = await handle.stat();
      if (!stats.isFile() || stats.size > 1_000_000) throw new Error("unsafe file");
      if (
        process.platform !== "win32" &&
        ((stats.mode & 0o077) !== 0 || (typeof process.getuid === "function" && stats.uid !== process.getuid()))
      ) {
        throw new MultiAccountMcpError(
          "The OAuth client JSON must be owned by the current user and readable only by that user. Run `chmod 600 /path/to/client.json` and retry.",
          "UNSAFE_OAUTH_CLIENT_PERMISSIONS",
        );
      }
      const buffer = Buffer.alloc(1_000_001);
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      if (offset > 1_000_000) throw new Error("oversized file");
      parsed = JSON.parse(buffer.subarray(0, offset).toString("utf8")) as GoogleClientFile;
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error instanceof MultiAccountMcpError) throw error;
    throw new MultiAccountMcpError(
      "Could not read the Google Desktop OAuth client JSON file.",
      "INVALID_OAUTH_CLIENT_FILE",
    );
  }

  const clientId = parsed.installed?.client_id;
  const clientSecret = parsed.installed?.client_secret;
  if (
    typeof clientId !== "string" ||
    !/^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$/.test(clientId) ||
    clientId.length > 512 ||
    typeof clientSecret !== "string" ||
    clientSecret.length < 1 ||
    clientSecret.length > 512 ||
    /[\u0000-\u001f\u007f]/.test(clientSecret)
  ) {
    throw new MultiAccountMcpError(
      "Multi-Account MCP requires a Google OAuth client of type Desktop app (the JSON must contain an installed client).",
      "INVALID_OAUTH_CLIENT_FILE",
    );
  }
  return { clientId, clientSecret };
}

export async function runGoogleOAuth(
  credentials: GoogleOAuthClientCredentials,
  options: {
    openBrowser: boolean;
    services: GoogleService[];
    loginHint?: string;
    knownGoogleSubs?: string[];
    beforeRevoke?: () => Promise<void>;
  },
): Promise<OAuthResult> {
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const dpopPrivateJwk = generateDpopPrivateJwk();
  const listener = await startLoopbackListener(state);
  try {
    const client = createGoogleOAuthClient(credentials, listener.redirectUri);
    const { codeVerifier, codeChallenge } = await client.generateCodeVerifierAsync();
    if (!codeVerifier || !codeChallenge) {
      throw new MultiAccountMcpError("Could not generate OAuth PKCE material.", "PKCE_GENERATION_FAILED");
    }
    const requiredScopes = [
      ...IDENTITY_SCOPES,
      ...options.services.map((service) => SERVICE_SCOPES[service]),
    ];
    const authorizationUrl = client.generateAuthUrl({
      access_type: "offline",
      scope: requiredScopes,
      state,
      nonce,
      prompt: options.loginHint ? "consent" : "consent select_account",
      include_granted_scopes: false,
      code_challenge_method: CodeChallengeMethod.S256,
      code_challenge: codeChallenge,
      ...(options.loginHint ? { login_hint: options.loginHint } : {}),
    });

    console.error("Opening Google authorization in your system browser...");
    if (options.openBrowser) openSystemBrowser(authorizationUrl);
    else console.error(authorizationUrl);

    const code = await listener.waitForCode;
    let tokens;
    try {
      ({ tokens } = await exchangeAuthorizationCodeWithDpop(
        client,
        credentials,
        { code, codeVerifier, redirectUri: listener.redirectUri },
        dpopPrivateJwk,
      ));
    } catch {
      throw new MultiAccountMcpError(
        "Google authorization-code exchange failed. Confirm the Desktop OAuth client and try again.",
        "OAUTH_TOKEN_EXCHANGE_FAILED",
      );
    }
    let verifiedSub: string | undefined;
    try {
      if (!tokens.refresh_token) {
        throw new MultiAccountMcpError(
          "Google did not return a refresh token. Revoke the app in your Google Account and connect again.",
          "MISSING_REFRESH_TOKEN",
        );
      }
      if (!tokens.id_token) {
        throw new MultiAccountMcpError("Google did not return an identity token.", "MISSING_ID_TOKEN");
      }

      let ticket;
      try {
        ticket = await client.verifyIdToken({
          idToken: tokens.id_token,
          audience: credentials.clientId,
        });
      } catch {
        throw new MultiAccountMcpError(
          "Google identity-token verification failed. No account was connected.",
          "INVALID_GOOGLE_IDENTITY",
        );
      }
      const payload = ticket.getPayload();
      verifiedSub = payload?.sub;
      if (
        !payload?.sub ||
        !payload.email ||
        payload.email_verified !== true ||
        !payload.nonce ||
        !stateMatches(nonce, payload.nonce)
      ) {
        throw new MultiAccountMcpError(
          "Google returned an incomplete or unverified identity.",
          "INVALID_GOOGLE_IDENTITY",
        );
      }

      const grantedScopes = (tokens.scope ?? "").split(/\s+/).filter(Boolean);
      const required = new Set<string>(requiredScopes);
      const missingScopes = requiredScopes.filter((scope) => !grantedScopes.includes(scope));
      const unexpectedScopes = grantedScopes.filter((scope) => !required.has(scope));
      if (missingScopes.length > 0 || unexpectedScopes.length > 0) {
        throw new MultiAccountMcpError(
          "Google did not return exactly Multi-Account MCP's required read-only scopes.",
          "INVALID_GRANTED_SCOPES",
        );
      }

      return {
        identity: {
          googleSub: payload.sub,
          email: payload.email,
          ...(payload.name ? { displayName: payload.name } : {}),
        },
        grantedScopes,
        tokens: {
          version: 1,
          refreshToken: tokens.refresh_token,
          dpopPrivateJwk,
          ...(tokens.scope ? { scope: tokens.scope } : {}),
          ...(tokens.token_type ? { tokenType: tokens.token_type } : {}),
        },
      };
    } catch (error) {
      const knownIdentity = verifiedSub && options.knownGoogleSubs?.includes(verifiedSub);
      const cleanupToken = tokens.refresh_token ?? tokens.access_token;
      if (!verifiedSub && (options.knownGoogleSubs?.length ?? 0) > 0) {
        throw new MultiAccountMcpError(
          "Authorization validation failed, but Multi-Account MCP could not safely revoke the grant without risking another connected account. Review Multi-Account MCP in Google Account security.",
          "CONNECT_ROLLBACK_INCOMPLETE",
        );
      }
      if (!knownIdentity && cleanupToken) {
        try {
          await options.beforeRevoke?.();
          await revokeGoogleToken(cleanupToken);
        } catch {
          throw new MultiAccountMcpError(
            "Authorization validation failed and Google token cleanup could not be verified. Revoke Multi-Account MCP in Google Account security.",
            "CONNECT_ROLLBACK_INCOMPLETE",
          );
        }
      }
      throw error;
    }
  } finally {
    await listener.close();
  }
}
