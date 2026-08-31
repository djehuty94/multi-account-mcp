import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import {
  createGoogleOAuthClient,
  generateDpopPrivateJwk,
} from "../src/auth/google-oauth-client.js";
import { IDENTITY_SCOPES, SERVICE_SCOPES } from "../src/constants.js";
import { GoogleAccountClient, GoogleClientFactory } from "../src/google/client.js";
import type { AccountMetadata, SecretVault, StoredGoogleTokens } from "../src/types.js";

const account: AccountMetadata = {
  id: "11111111-1111-4111-8111-111111111111",
  alias: "work",
  googleSub: "stable-google-sub",
  email: "person@company.example",
  scopes: ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/drive.readonly"],
  createdAt: "2026-08-31T00:00:00.000Z",
  updatedAt: "2026-08-31T00:00:00.000Z",
};

test("the only requested service scopes are the exact Gmail and Drive read-only scopes", () => {
  assert.deepEqual([...IDENTITY_SCOPES], [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
  ]);
  assert.deepEqual(SERVICE_SCOPES, {
    gmail: "https://www.googleapis.com/auth/gmail.readonly",
    drive: "https://www.googleapis.com/auth/drive.readonly",
  });
});

test("Google data transport blocks other origins and hard-codes GET", async () => {
  const oauth = createGoogleOAuthClient();
  oauth.setCredentials({ access_token: "synthetic-test-access-token" });
  const preparedRequests: Array<{ method?: string; maxRedirects?: number; retry?: boolean }> = [];
  oauth.transporter.defaults.adapter = async (options) => {
    preparedRequests.push(options);
    return Object.assign(new Response("{}", { status: 200 }), {
      config: options,
      data: {},
    }) as never;
  };
  const client = new GoogleAccountClient(account, oauth);

  await assert.rejects(
    client.json({ url: "https://example.invalid/drive/v3/files" }),
    /Blocked an unexpected outbound URL/,
  );
  assert.equal(preparedRequests.length, 0);

  await client.json({ url: "https://www.googleapis.com/drive/v3/files" });
  const prepared = preparedRequests[0];
  assert.equal(prepared?.method, "GET");
  assert.equal(prepared?.maxRedirects, 0);
  assert.equal(prepared?.retry, false);
});

test("account identity verification hard-codes GET for Google userinfo", async () => {
  const oauth = createGoogleOAuthClient();
  const preparedRequests: Array<{ url?: string | URL; method?: string }> = [];
  oauth.transporter.defaults.adapter = async (options) => {
    preparedRequests.push(options);
    const url = new URL(String(options.url));
    const data = url.pathname === "/token"
      ? { access_token: "synthetic-test-access-token", expires_in: 3_600, token_type: "Bearer" }
      : { sub: account.googleSub, email: account.email };
    return Object.assign(new Response(JSON.stringify(data), { status: 200 }), {
      config: options,
      data,
    }) as never;
  };
  const vault: SecretVault = {
    getOAuthClient: async () => ({
      clientId: "test.apps.googleusercontent.com",
      clientSecret: "synthetic-secret",
    }),
    setOAuthClient: async () => undefined,
    getTokens: async () => ({
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: generateDpopPrivateJwk(),
    }),
    setTokens: async () => undefined,
    deleteTokens: async () => true,
  };

  await new GoogleClientFactory(vault, () => oauth).forAccount(account, "drive");

  const userinfo = preparedRequests.find((request) =>
    String(request.url) === "https://www.googleapis.com/oauth2/v3/userinfo"
  );
  assert.ok(userinfo);
  assert.equal(userinfo.method, "GET");
  const refresh = preparedRequests.find((request) =>
    String(request.url) === "https://oauth2.googleapis.com/token"
  );
  assert.ok(refresh);
  assert.equal(refresh.method, "POST");
});

test("DPoP refreshes are single-flight and never install a bearer refresh token", async () => {
  const oauth = createGoogleOAuthClient();
  let tokenRequests = 0;
  let releaseRefresh!: () => void;
  const refreshMayFinish = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });
  let markRefreshStarted!: () => void;
  const refreshStarted = new Promise<void>((resolve) => {
    markRefreshStarted = resolve;
  });
  oauth.transporter.defaults.adapter = async (options) => {
    const url = String(options.url);
    if (url === "https://oauth2.googleapis.com/token") {
      tokenRequests += 1;
      assert.equal(new Headers(options.headers).get("authorization"), null);
      assert.ok(new Headers(options.headers).get("dpop"));
      if (tokenRequests === 2) {
        markRefreshStarted();
        await refreshMayFinish;
      }
      const data = {
        access_token: `synthetic-test-access-token-${tokenRequests}`,
        expires_in: 3_600,
        token_type: "Bearer",
      };
      return Object.assign(new Response(JSON.stringify(data), { status: 200 }), {
        config: options,
        data,
      }) as never;
    }
    const data = { sub: account.googleSub, email: account.email };
    return Object.assign(new Response(JSON.stringify(data), { status: 200 }), {
      config: options,
      data,
    }) as never;
  };
  const vault: SecretVault = {
    getOAuthClient: async () => ({
      clientId: "test.apps.googleusercontent.com",
      clientSecret: "synthetic-secret",
    }),
    setOAuthClient: async () => undefined,
    getTokens: async () => ({
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: generateDpopPrivateJwk(),
    }),
    setTokens: async () => undefined,
    deleteTokens: async () => true,
  };

  await new GoogleClientFactory(vault, () => oauth).forAccount(account, "drive");
  assert.equal(tokenRequests, 1);
  assert.equal(oauth.credentials.refresh_token, undefined);
  const refreshHandler = oauth.refreshHandler;
  assert.ok(refreshHandler);
  const first = refreshHandler();
  const second = refreshHandler();
  assert.strictEqual(first, second);
  await refreshStarted;
  assert.equal(tokenRequests, 2);
  releaseRefresh();
  const [firstResult, secondResult] = await Promise.all([first, second]);
  assert.deepEqual(firstResult, secondResult);
  assert.equal(tokenRequests, 2);
  assert.equal(oauth.credentials.refresh_token, undefined);
});

test("missing DPoP key fails before any bearer refresh fallback", async () => {
  const oauth = createGoogleOAuthClient();
  let preparedRequests = 0;
  oauth.transporter.defaults.adapter = async () => {
    preparedRequests += 1;
    throw new Error("no request expected");
  };
  const vault: SecretVault = {
    getOAuthClient: async () => ({
      clientId: "test.apps.googleusercontent.com",
      clientSecret: "synthetic-secret",
    }),
    setOAuthClient: async () => undefined,
    // Deliberately bypass the compile-time invariant to exercise corrupted or
    // pre-DPoP credentials that can still exist in an OS credential vault.
    getTokens: async () => ({
      version: 1,
      refreshToken: "legacy-bearer-refresh-token",
    } as unknown as StoredGoogleTokens),
    setTokens: async () => undefined,
    deleteTokens: async () => true,
  };

  await assert.rejects(
    new GoogleClientFactory(vault, () => oauth).forAccount(account, "drive"),
    /bearer refresh is disabled/i,
  );
  assert.equal(preparedRequests, 0);
  assert.equal(oauth.credentials.refresh_token, undefined);
});

test("removed or reconnected account metadata evicts credential-bearing client closures", async () => {
  const replacement: AccountMetadata = {
    ...account,
    id: "22222222-2222-4222-8222-222222222222",
    googleSub: "replacement-google-sub",
    updatedAt: "2026-08-31T01:00:00.000Z",
  };
  const subjects = [account.googleSub, replacement.googleSub];
  let clientsCreated = 0;
  const vault: SecretVault = {
    getOAuthClient: async () => ({
      clientId: "test.apps.googleusercontent.com",
      clientSecret: "synthetic-secret",
    }),
    setOAuthClient: async () => undefined,
    getTokens: async () => ({
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: generateDpopPrivateJwk(),
    }),
    setTokens: async () => undefined,
    deleteTokens: async () => true,
  };
  const factory = new GoogleClientFactory(vault, () => {
    const expectedSub = subjects[clientsCreated];
    assert.ok(expectedSub);
    clientsCreated += 1;
    const oauth = createGoogleOAuthClient();
    oauth.transporter.defaults.adapter = async (options) => {
      const data = String(options.url) === "https://oauth2.googleapis.com/token"
        ? { access_token: "synthetic-access-token", expires_in: 3_600, token_type: "Bearer" }
        : { sub: expectedSub, email: account.email };
      return Object.assign(new Response(JSON.stringify(data), { status: 200 }), {
        config: options,
        data,
      }) as never;
    };
    return oauth;
  });

  await factory.forAccount(account, "drive");
  assert.equal(factory.reconcileAccounts([account]), 0);
  assert.equal(factory.reconcileAccounts([replacement]), 1);
  await factory.forAccount(replacement, "drive");
  assert.equal(clientsCreated, 2);
  assert.equal(factory.reconcileAccounts([]), 1);
});

test("streaming Google errors are rejected before their bodies are buffered", async () => {
  const oauth = createGoogleOAuthClient();
  let bodyReadStarted = false;
  const stream = new Readable({
    read() {
      bodyReadStarted = true;
      this.push(Buffer.alloc(1_000_000));
      this.push(null);
    },
  });
  oauth.transporter.defaults.adapter = async (options) => ({
    config: options,
    data: stream,
    headers: new Headers(),
    status: 500,
    statusText: "Server error",
  }) as never;

  const client = new GoogleAccountClient(account, oauth);
  await assert.rejects(
    client.text({ url: "https://www.googleapis.com/drive/v3/files/test", maxBytes: 100 }),
    /Google API request failed/,
  );
  assert.equal(bodyReadStarted, false);
});
