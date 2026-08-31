import assert from "node:assert/strict";
import {
  createHash,
  createPublicKey,
  verify as verifySignature,
  type JsonWebKey,
} from "node:crypto";
import test from "node:test";
import {
  authorizationCodeDpopJti,
  createDpopProof,
  createGoogleOAuthClient,
  exchangeAuthorizationCodeWithDpop,
  generateDpopPrivateJwk,
  GOOGLE_TOKEN_ENDPOINT,
  normalizeDpopPrivateJwk,
  refreshGoogleAccessTokenWithDpop,
} from "../src/auth/google-oauth-client.js";
import { LIMITS } from "../src/constants.js";
import { MultiAccountMcpError } from "../src/errors.js";
import type { DpopPrivateJwk, GoogleOAuthClientCredentials } from "../src/types.js";

const CREDENTIALS: GoogleOAuthClientCredentials = {
  clientId: "test.apps.googleusercontent.com",
  clientSecret: "synthetic-secret",
};

function decodeProof(proof: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
} {
  const [encodedHeader, encodedPayload, encodedSignature, extra] = proof.split(".");
  assert.ok(encodedHeader);
  assert.ok(encodedPayload);
  assert.ok(encodedSignature);
  assert.equal(extra, undefined);
  return {
    header: JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8")) as Record<string, unknown>,
    payload: JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as Record<string, unknown>,
    signingInput: `${encodedHeader}.${encodedPayload}`,
    signature: Buffer.from(encodedSignature, "base64url"),
  };
}

function tokenResponse(
  options: unknown,
  data: Record<string, unknown>,
  nonce?: string,
  status = 200,
) {
  return Object.assign(new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...(nonce ? { "DPoP-Nonce": nonce } : {}),
    },
  }), {
    config: options,
    data,
  }) as never;
}

test("DPoP proofs use an ES256 P-256 public JWK and verifiable RFC 9449 claims", () => {
  const privateJwk = generateDpopPrivateJwk();
  const proof = createDpopProof(privateJwk, {
    jti: "deterministic-jti",
    nonce: "bounded_nonce-123=",
    issuedAt: 1_784_822_025,
  });
  const decoded = decodeProof(proof);

  assert.deepEqual(decoded.header, {
    typ: "dpop+jwt",
    alg: "ES256",
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: privateJwk.x,
      y: privateJwk.y,
    },
  });
  assert.deepEqual(decoded.payload, {
    jti: "deterministic-jti",
    htm: "POST",
    htu: GOOGLE_TOKEN_ENDPOINT,
    nonce: "bounded_nonce-123=",
    iat: 1_784_822_025,
  });
  assert.equal(decoded.signature.length, 64);
  const publicJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: privateJwk.x,
    y: privateJwk.y,
  };
  assert.equal(verifySignature(
    "sha256",
    Buffer.from(decoded.signingInput, "ascii"),
    { key: createPublicKey({ key: publicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
    decoded.signature,
  ), true);
});

test("authorization-code exchange uses the exact Google endpoint, bounded POST, and code-hash jti", async () => {
  const privateJwk = generateDpopPrivateJwk();
  const client = createGoogleOAuthClient(CREDENTIALS, "http://127.0.0.1:12345/oauth2/callback");
  let prepared: {
    url?: string | URL;
    method?: string;
    data?: unknown;
    headers?: Headers | Record<string, string>;
    retry?: boolean;
    maxRedirects?: number;
    maxContentLength?: number;
    follow?: number;
    size?: number;
    timeout?: number;
  } | undefined;
  client.transporter.defaults.adapter = async (options) => {
    prepared = options;
    return tokenResponse(options, {
      access_token: "synthetic-access-token",
      refresh_token: "synthetic-refresh-token",
      id_token: "synthetic-id-token",
      expires_in: 3_600,
      scope: "openid",
      token_type: "Bearer",
    }, "exchange-nonce_123=");
  };

  const code = "synthetic-authorization-code";
  const result = await exchangeAuthorizationCodeWithDpop(
    client,
    CREDENTIALS,
    {
      code,
      codeVerifier: "synthetic-code-verifier",
      redirectUri: "http://127.0.0.1:12345/oauth2/callback",
    },
    privateJwk,
  );

  assert.ok(prepared);
  assert.equal(String(prepared.url), GOOGLE_TOKEN_ENDPOINT);
  assert.equal(prepared.method, "POST");
  assert.equal(prepared.retry, false);
  assert.equal(prepared.maxRedirects, 0);
  assert.equal(prepared.maxContentLength, 1_000_000);
  assert.equal(prepared.follow, 0);
  assert.equal(prepared.size, 1_000_000);
  assert.equal(prepared.timeout, LIMITS.requestTimeoutMs);
  const parameters = prepared.data as URLSearchParams;
  assert.equal(parameters.get("grant_type"), "authorization_code");
  assert.equal(parameters.get("code"), code);
  assert.equal(parameters.get("client_id"), CREDENTIALS.clientId);
  assert.equal(parameters.get("client_secret"), CREDENTIALS.clientSecret);
  assert.equal(parameters.get("code_verifier"), "synthetic-code-verifier");
  const proof = new Headers(prepared.headers).get("dpop");
  assert.ok(proof);
  const decoded = decodeProof(proof);
  assert.equal(decoded.payload.jti, createHash("sha256").update(code).digest("base64url"));
  assert.equal(decoded.payload.jti, authorizationCodeDpopJti(code));
  assert.equal(decoded.payload.nonce, undefined);
  assert.equal(result.nonce, "exchange-nonce_123=");
});

test("refresh handles one bounded DPoP nonce challenge and returns the next nonce", async () => {
  const privateJwk = generateDpopPrivateJwk();
  const client = createGoogleOAuthClient(CREDENTIALS);
  const proofs: string[] = [];
  const submittedParameters: Array<Record<string, string>> = [];
  let calls = 0;
  client.transporter.defaults.adapter = async (options) => {
    calls += 1;
    submittedParameters.push(Object.fromEntries(
      new URLSearchParams(options.data as URLSearchParams),
    ));
    const proof = new Headers(options.headers).get("dpop");
    assert.ok(proof);
    proofs.push(proof);
    assert.equal(String(options.url), GOOGLE_TOKEN_ENDPOINT);
    assert.equal(options.method, "POST");
    assert.equal(options.retry, false);
    assert.equal(options.maxRedirects, 0);
    assert.equal(options.maxContentLength, 1_000_000);
    assert.equal(options.follow, 0);
    assert.equal(options.size, 1_000_000);
    assert.equal(options.timeout, LIMITS.requestTimeoutMs);
    const parameters = options.data as URLSearchParams;
    // Assert the exact form shape on every physical attempt. A regression once
    // reused a URLSearchParams object that Gaxios had redacted after the 400.
    assert.deepEqual([...parameters.keys()].sort(), [
      "client_id",
      "client_secret",
      "grant_type",
      "refresh_token",
    ]);
    assert.equal(parameters.get("client_id"), CREDENTIALS.clientId);
    assert.equal(new Headers(options.headers).get("authorization"), null);
    if (calls === 1) {
      return tokenResponse(options, {
        error: "use_dpop_nonce",
      }, "fresh-challenge_123=", 400) as never;
    }
    return tokenResponse(options, {
      access_token: "synthetic-access-token",
      expires_in: 3_600,
      token_type: "Bearer",
    }, "next-nonce_456=");
  };

  const result = await refreshGoogleAccessTokenWithDpop(client, CREDENTIALS, {
    version: 1,
    refreshToken: "synthetic-refresh-token",
    dpopPrivateJwk: privateJwk,
  }, "exchange-workflow_nonce=");

  assert.equal(calls, 2);
  assert.equal(proofs.length, 2);
  assert.deepEqual(submittedParameters, [
    {
      grant_type: "refresh_token",
      refresh_token: "synthetic-refresh-token",
      client_id: CREDENTIALS.clientId,
      client_secret: CREDENTIALS.clientSecret,
    },
    {
      grant_type: "refresh_token",
      refresh_token: "synthetic-refresh-token",
      client_id: CREDENTIALS.clientId,
      client_secret: CREDENTIALS.clientSecret,
    },
  ]);
  const first = decodeProof(proofs[0] as string).payload;
  const second = decodeProof(proofs[1] as string).payload;
  assert.equal(first.nonce, "exchange-workflow_nonce=");
  assert.equal(second.nonce, "fresh-challenge_123=");
  assert.notEqual(first.jti, second.jti);
  assert.equal(Buffer.from(first.jti as string, "base64url").length, 24);
  assert.equal(Buffer.from(second.jti as string, "base64url").length, 24);
  assert.equal(result.accessToken, "synthetic-access-token");
  assert.equal(result.refreshToken, "synthetic-refresh-token");
  assert.equal(result.nonce, "next-nonce_456=");
});

test("refresh retries a nonce challenge exactly once", async () => {
  const privateJwk = generateDpopPrivateJwk();
  const client = createGoogleOAuthClient(CREDENTIALS);
  let calls = 0;
  client.transporter.defaults.adapter = async (requestOptions) => {
    calls += 1;
    return Object.assign(new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
      status: 400,
      headers: { "DPoP-Nonce": `challenge-${calls}` },
    }), {
      config: requestOptions,
      data: { error: "use_dpop_nonce" },
    }) as never;
  };

  await assert.rejects(
    refreshGoogleAccessTokenWithDpop(client, CREDENTIALS, {
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: privateJwk,
    }),
    (error: unknown) => error instanceof MultiAccountMcpError &&
      error.code === "DPOP_NONCE_RETRY_REJECTED",
  );
  assert.equal(calls, 2);
});

test("malformed DPoP private keys and nonce challenges fail closed", async () => {
  const privateJwk = generateDpopPrivateJwk();
  const mismatched: DpopPrivateJwk = {
    ...privateJwk,
    d: generateDpopPrivateJwk().d,
  };
  assert.throws(
    () => normalizeDpopPrivateJwk(mismatched),
    (error: unknown) => error instanceof MultiAccountMcpError &&
      error.code === "INVALID_DPOP_PRIVATE_KEY",
  );

  const client = createGoogleOAuthClient(CREDENTIALS);
  let calls = 0;
  client.transporter.defaults.adapter = async (options) => {
    calls += 1;
    return Object.assign(new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
      status: 400,
      headers: { "DPoP-Nonce": "not a valid nonce" },
    }), {
      config: options,
      data: { error: "use_dpop_nonce" },
    }) as never;
  };
  await assert.rejects(
    refreshGoogleAccessTokenWithDpop(client, CREDENTIALS, {
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: privateJwk,
    }),
    (error: unknown) => error instanceof MultiAccountMcpError &&
      error.code === "INVALID_DPOP_NONCE",
  );
  assert.equal(calls, 1);
});

test("failed token requests redact refresh credentials and DPoP proofs from thrown errors", async () => {
  const privateJwk = generateDpopPrivateJwk();
  const client = createGoogleOAuthClient(CREDENTIALS);
  let submittedProof = "";
  client.transporter.defaults.adapter = async (options) => {
    submittedProof = new Headers(options.headers).get("dpop") ?? "";
    assert.ok(submittedProof);
    return tokenResponse(options, { error: "invalid_grant" }, undefined, 400) as never;
  };

  await assert.rejects(
    refreshGoogleAccessTokenWithDpop(client, CREDENTIALS, {
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: privateJwk,
    }),
    (error: unknown) => {
      const candidate = error as {
        config?: { data?: unknown; body?: unknown; headers?: unknown };
        response?: { config?: unknown; data?: unknown };
      };
      const serialized = JSON.stringify({
        config: candidate.config,
        responseConfig: candidate.response?.config,
        responseData: candidate.response?.data,
      });
      assert.doesNotMatch(serialized, /synthetic-refresh-token|synthetic-secret/);
      assert.equal(serialized.includes(submittedProof), false);
      assert.match(String(candidate.config?.data), /REDACTED TOKEN REQUEST/);
      assert.equal(
        new Headers(candidate.config?.headers as HeadersInit | undefined).get("dpop"),
        "<<REDACTED TOKEN REQUEST>>",
      );
      assert.deepEqual(candidate.response?.data, {});
      return true;
    },
  );
});
