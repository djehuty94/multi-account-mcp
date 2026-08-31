import assert from "node:assert/strict";
import test from "node:test";
import { createGoogleOAuthClient } from "../src/auth/google-oauth-client.js";
import { revokeGoogleToken } from "../src/auth/oauth.js";
import { LIMITS } from "../src/constants.js";

test("Google OAuth clients bind effective token, refresh, certificate, and revoke transport limits", async () => {
  const client = createGoogleOAuthClient(
    { clientId: "test.apps.googleusercontent.com", clientSecret: "secret" },
    "http://127.0.0.1:12345/oauth2/callback",
  );
  assert.equal(client.transporter.defaults.timeout, LIMITS.requestTimeoutMs);
  assert.equal(client.transporter.defaults.maxRedirects, 0);
  assert.equal(client.transporter.defaults.maxContentLength, 1_000_000);
  assert.equal(client.transporter.defaults.follow, 0);
  assert.equal(client.transporter.defaults.size, 1_000_000);
  assert.equal(client.transporter.defaults.retry, false);

  let prepared: { follow?: number; size?: number; timeout?: number } | undefined;
  client.transporter.defaults.adapter = async (options) => {
    prepared = options;
    return Object.assign(new Response("{}", { status: 200 }), {
      config: options,
      data: {},
    }) as never;
  };
  await client.transporter.request({ url: "https://example.invalid/test" });
  assert.equal(prepared?.follow, 0);
  assert.equal(prepared?.size, 1_000_000);
  assert.equal(prepared?.timeout, LIMITS.requestTimeoutMs);
});

test("Google token revocation posts to the exact unauthenticated revoke endpoint", async () => {
  const client = createGoogleOAuthClient();
  let prepared: {
    url?: string | URL;
    method?: string;
    retry?: boolean;
    maxRedirects?: number;
    timeout?: number;
    headers?: Headers | Record<string, string>;
  } | undefined;
  client.transporter.defaults.adapter = async (options) => {
    prepared = options;
    return Object.assign(new Response("{}", { status: 200 }), {
      config: options,
      data: {},
    }) as never;
  };

  await revokeGoogleToken("synthetic-refresh-token", client);

  assert.ok(prepared);
  const url = new URL(String(prepared.url));
  assert.equal(url.origin, "https://oauth2.googleapis.com");
  assert.equal(url.pathname, "/revoke");
  assert.equal(url.searchParams.get("token"), "synthetic-refresh-token");
  assert.equal(prepared.method, "POST");
  assert.equal(prepared.retry, false);
  assert.equal(prepared.maxRedirects, 0);
  assert.equal(prepared.timeout, LIMITS.requestTimeoutMs);
  const headers = new Headers(prepared.headers);
  assert.equal(headers.has("authorization"), false);
});
