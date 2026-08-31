import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  AccountService,
  type AccountServiceDependencies,
} from "../src/auth/account-service.js";
import { generateDpopPrivateJwk } from "../src/auth/google-oauth-client.js";
import type { OAuthResult } from "../src/auth/oauth.js";
import { MultiAccountMcpError } from "../src/errors.js";
import { AccountMetadataStore } from "../src/storage/metadata-store.js";
import type {
  AccountMetadata,
  GoogleOAuthClientCredentials,
  SecretVault,
  StoredGoogleTokens,
} from "../src/types.js";

const CLIENT: GoogleOAuthClientCredentials = {
  clientId: "test.apps.googleusercontent.com",
  clientSecret: "test-secret",
};

const DPOP_PRIVATE_JWK = generateDpopPrivateJwk();

function oauthResult(overrides: Partial<OAuthResult["identity"]> = {}): OAuthResult {
  return {
    identity: {
      googleSub: "new-google-sub",
      email: "new@example.com",
      ...overrides,
    },
    tokens: {
      version: 1,
      refreshToken: "new-refresh-token",
      scope: "scope-gmail",
      tokenType: "Bearer",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    },
    grantedScopes: ["scope-gmail"],
  };
}

function existingAccount(): AccountMetadata {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    alias: "personal",
    googleSub: "existing-google-sub",
    email: "existing@example.com",
    scopes: ["scope-gmail"],
    createdAt: "2026-08-31T00:00:00.000Z",
    updatedAt: "2026-08-31T00:00:00.000Z",
  };
}

class MemoryVault implements SecretVault {
  oauthClient: GoogleOAuthClientCredentials | null;
  readonly tokens = new Map<string, StoredGoogleTokens>();
  oauthClientWrites = 0;
  tokenWrites = 0;
  tokenDeletes = 0;

  constructor(oauthClient: GoogleOAuthClientCredentials | null = null) {
    this.oauthClient = oauthClient;
  }

  async getOAuthClient(): Promise<GoogleOAuthClientCredentials | null> {
    return this.oauthClient;
  }

  async setOAuthClient(credentials: GoogleOAuthClientCredentials): Promise<void> {
    this.oauthClientWrites += 1;
    this.oauthClient = credentials;
  }

  async getTokens(alias: string): Promise<StoredGoogleTokens | null> {
    return this.tokens.get(alias) ?? null;
  }

  async setTokens(alias: string, tokens: StoredGoogleTokens): Promise<void> {
    this.tokenWrites += 1;
    this.tokens.set(alias, tokens);
  }

  async deleteTokens(alias: string): Promise<boolean> {
    this.tokenDeletes += 1;
    return this.tokens.delete(alias);
  }
}

class CommitThenThrowStore extends AccountMetadataStore {
  override async transaction<T>(operation: (transaction: {
    list(): Promise<AccountMetadata[]>;
    get(alias: string): Promise<AccountMetadata | null>;
    upsert(account: AccountMetadata): Promise<AccountMetadata>;
    remove(alias: string): Promise<boolean>;
  }) => Promise<T>): Promise<T> {
    return super.transaction((transaction) => operation({
      ...transaction,
      upsert: async (account) => {
        await transaction.upsert(account);
        throw new Error("simulated post-commit metadata failure");
      },
    }));
  }
}

class LostConnectLeaseStore extends AccountMetadataStore {
  private assertions = 0;

  override async connectLease<T>(operation: (
    lease: { assertOwned(): Promise<void> },
  ) => Promise<T>): Promise<T> {
    return operation({
      assertOwned: async () => {
        this.assertions += 1;
        if (this.assertions >= 2) {
          throw new MultiAccountMcpError("simulated lease loss", "CONNECT_LEASE_LOST");
        }
      },
    });
  }
}

function dependencies(
  result: OAuthResult,
  revoked: string[],
): Partial<AccountServiceDependencies> {
  return {
    loadOAuthClientFile: async () => CLIENT,
    runGoogleOAuth: async () => result,
    revokeGoogleToken: async (token) => {
      revoked.push(token);
    },
  };
}

async function rejectsWithCode(promise: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof MultiAccountMcpError);
    assert.equal(error.code, code);
    return true;
  });
}

test("account connection persists client, tokens, and metadata only after explicit confirmation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-success-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const vault = new MemoryVault();
    const revoked: string[] = [];
    const result = oauthResult();
    const injected = dependencies(result, revoked);
    let disclosureObserved = false;
    injected.runGoogleOAuth = async () => {
      assert.equal(disclosureObserved, true);
      await store.transaction(async (transaction) => {
        assert.deepEqual(await transaction.list(), []);
      });
      return result;
    };
    const service = new AccountService(store, vault, injected);
    let confirmationObserved = false;

    const connected = await service.connect({
      alias: "work",
      clientFile: "unused-test-client.json",
      confirmDataUseDisclosure: async (request) => {
        assert.deepEqual(request, { alias: "work", services: ["gmail"] });
        assert.equal(vault.oauthClient, null);
        assert.equal(vault.tokenWrites, 0);
        assert.deepEqual(await store.list(), []);
        disclosureObserved = true;
        return true;
      },
      confirmAccountBinding: async (request) => {
        assert.deepEqual(request, { alias: "work", email: "new@example.com" });
        await store.transaction(async (transaction) => {
          assert.deepEqual(await transaction.list(), []);
        });
        assert.equal(vault.oauthClient, null);
        assert.equal(vault.oauthClientWrites, 0);
        assert.equal(vault.tokenWrites, 0);
        assert.equal(await vault.getTokens("work"), null);
        assert.deepEqual(await store.list(), []);
        confirmationObserved = true;
        return true;
      },
      openBrowser: false,
      services: ["gmail"],
    });

    assert.equal(confirmationObserved, true);
    assert.equal(disclosureObserved, true);
    assert.equal(connected.alias, "work");
    assert.deepEqual(vault.oauthClient, CLIENT);
    assert.equal((await vault.getTokens("work"))?.refreshToken, "new-refresh-token");
    assert.deepEqual((await store.list()).map((account) => account.alias), ["work"]);
    assert.deepEqual(revoked, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("declining the data-use disclosure stops before Google OAuth or persistence", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-disclosure-decline-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const vault = new MemoryVault();
    const revoked: string[] = [];
    const injected = dependencies(oauthResult(), revoked);
    let oauthCalls = 0;
    injected.runGoogleOAuth = async () => {
      oauthCalls += 1;
      return oauthResult();
    };
    const service = new AccountService(store, vault, injected);
    let bindingCalls = 0;

    await rejectsWithCode(service.connect({
      alias: "work",
      clientFile: "unused-test-client.json",
      confirmDataUseDisclosure: async () => false,
      confirmAccountBinding: async () => {
        bindingCalls += 1;
        return true;
      },
      openBrowser: false,
      services: ["gmail"],
    }), "DATA_USE_DISCLOSURE_DECLINED");

    assert.equal(oauthCalls, 0);
    assert.equal(bindingCalls, 0);
    assert.equal(vault.oauthClient, null);
    assert.equal(vault.tokenWrites, 0);
    assert.deepEqual(await store.list(), []);
    assert.deepEqual(revoked, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("the connection lease prevents a second OAuth flow from racing the winner", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-lease-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const vault = new MemoryVault(CLIENT);
    const revoked: string[] = [];
    const firstResult: OAuthResult = {
      ...oauthResult({ googleSub: "google-sub-a", email: "a@example.com" }),
      tokens: { version: 1, refreshToken: "refresh-token-a", dpopPrivateJwk: DPOP_PRIVATE_JWK },
    };
    const secondResult: OAuthResult = {
      ...oauthResult({ googleSub: "google-sub-b", email: "b@example.com" }),
      tokens: { version: 1, refreshToken: "refresh-token-b", dpopPrivateJwk: DPOP_PRIVATE_JWK },
    };
    let releaseFirstConfirmation!: () => void;
    const firstConfirmationReleased = new Promise<void>((resolve) => {
      releaseFirstConfirmation = resolve;
    });
    let firstConfirmationStarted!: () => void;
    const firstAtConfirmation = new Promise<void>((resolve) => {
      firstConfirmationStarted = resolve;
    });
    const first = new AccountService(store, vault, dependencies(firstResult, revoked));
    let secondOAuthCalls = 0;
    const secondDependencies = dependencies(secondResult, revoked);
    secondDependencies.runGoogleOAuth = async () => {
      secondOAuthCalls += 1;
      return secondResult;
    };
    const second = new AccountService(store, vault, secondDependencies);

    const firstConnection = first.connect({
      alias: "shared",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => {
        firstConfirmationStarted();
        await firstConfirmationReleased;
        return true;
      },
      openBrowser: false,
      services: ["gmail"],
    });
    await firstAtConfirmation;
    const secondConnection = second.connect({
      alias: "shared",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => true,
      openBrowser: false,
      services: ["gmail"],
    });

    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    assert.equal(secondOAuthCalls, 0);
    releaseFirstConfirmation();
    const winner = await firstConnection;
    await rejectsWithCode(secondConnection, "ACCOUNT_ALREADY_CONNECTED");

    assert.deepEqual(await store.list(), [winner]);
    assert.equal((await vault.getTokens("shared"))?.refreshToken, "refresh-token-a");
    assert.equal(vault.tokenWrites, 1);
    assert.equal(vault.tokenDeletes, 0);
    assert.deepEqual(revoked, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a queued same-identity OAuth flow cannot revoke the winning alias", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-same-sub-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const vault = new MemoryVault(CLIENT);
    const revoked: string[] = [];
    const winnerResult: OAuthResult = {
      ...oauthResult({ googleSub: "shared-google-sub", email: "same@example.com" }),
      tokens: { version: 1, refreshToken: "winner-refresh-token", dpopPrivateJwk: DPOP_PRIVATE_JWK },
    };
    const duplicateResult: OAuthResult = {
      ...oauthResult({ googleSub: "shared-google-sub", email: "same@example.com" }),
      tokens: { version: 1, refreshToken: "duplicate-refresh-token", dpopPrivateJwk: DPOP_PRIVATE_JWK },
    };
    let releaseWinnerConfirmation!: () => void;
    const winnerMayFinish = new Promise<void>((resolve) => {
      releaseWinnerConfirmation = resolve;
    });
    let markWinnerAtConfirmation!: () => void;
    const winnerAtConfirmation = new Promise<void>((resolve) => {
      markWinnerAtConfirmation = resolve;
    });
    const winner = new AccountService(store, vault, dependencies(winnerResult, revoked));
    let duplicateOAuthCalls = 0;
    const duplicateDependencies = dependencies(duplicateResult, revoked);
    duplicateDependencies.runGoogleOAuth = async () => {
      duplicateOAuthCalls += 1;
      assert.deepEqual((await store.list()).map((account) => account.alias), ["first"]);
      return duplicateResult;
    };
    const duplicate = new AccountService(store, vault, duplicateDependencies);

    const winnerConnection = winner.connect({
      alias: "first",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => {
        markWinnerAtConfirmation();
        await winnerMayFinish;
        return true;
      },
      openBrowser: false,
      services: ["gmail"],
    });
    await winnerAtConfirmation;
    const duplicateConnection = duplicate.connect({
      alias: "second",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => true,
      openBrowser: false,
      services: ["gmail"],
    });

    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    assert.equal(duplicateOAuthCalls, 0);
    releaseWinnerConfirmation();
    const connected = await winnerConnection;
    await rejectsWithCode(duplicateConnection, "GOOGLE_ACCOUNT_ALREADY_CONNECTED");

    assert.equal(duplicateOAuthCalls, 1);
    assert.deepEqual(await store.list(), [connected]);
    assert.equal((await vault.getTokens("first"))?.refreshToken, "winner-refresh-token");
    assert.equal(await vault.getTokens("second"), null);
    assert.equal(vault.tokenWrites, 1);
    assert.equal(vault.tokenDeletes, 0);
    assert.deepEqual(revoked, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("orphan credentials introduced during confirmation are preserved and the new grant is revoked", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-orphan-race-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const vault = new MemoryVault(CLIENT);
    const revoked: string[] = [];
    const service = new AccountService(store, vault, dependencies(oauthResult(), revoked));
    const orphan: StoredGoogleTokens = {
      version: 1,
      refreshToken: "pre-existing-orphan-token",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    };

    await rejectsWithCode(service.connect({
      alias: "work",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => {
        vault.tokens.set("work", orphan);
        return true;
      },
      openBrowser: false,
      services: ["gmail"],
    }), "ORPHAN_ACCOUNT_CREDENTIALS");

    assert.deepEqual(await store.list(), []);
    assert.deepEqual(await vault.getTokens("work"), orphan);
    assert.equal(vault.tokenWrites, 0);
    assert.equal(vault.tokenDeletes, 0);
    assert.deepEqual(revoked, ["new-refresh-token"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("declined binding preserves existing state and revokes only the newly issued token", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-decline-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const existing = existingAccount();
    await store.upsert(existing);
    const vault = new MemoryVault(CLIENT);
    const existingTokens: StoredGoogleTokens = {
      version: 1,
      refreshToken: "existing-refresh-token",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    };
    vault.tokens.set(existing.alias, existingTokens);
    const revoked: string[] = [];
    const service = new AccountService(store, vault, dependencies(oauthResult(), revoked));

    await rejectsWithCode(service.connect({
      alias: "work",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => false,
      openBrowser: false,
      services: ["gmail"],
    }), "ACCOUNT_BINDING_DECLINED");

    assert.deepEqual(await store.list(), [existing]);
    assert.deepEqual(vault.oauthClient, CLIENT);
    assert.deepEqual(await vault.getTokens("personal"), existingTokens);
    assert.equal(await vault.getTokens("work"), null);
    assert.equal(vault.oauthClientWrites, 0);
    assert.equal(vault.tokenWrites, 0);
    assert.deepEqual(revoked, ["new-refresh-token"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("duplicate Google identity neither overwrites nor revokes the existing account grant", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-duplicate-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const existing = existingAccount();
    await store.upsert(existing);
    const vault = new MemoryVault(CLIENT);
    const existingTokens: StoredGoogleTokens = {
      version: 1,
      refreshToken: "existing-refresh-token",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    };
    vault.tokens.set(existing.alias, existingTokens);
    const revoked: string[] = [];
    const duplicateResult = oauthResult({
      googleSub: existing.googleSub,
      email: existing.email,
    });
    const service = new AccountService(store, vault, dependencies(duplicateResult, revoked));
    let confirmationCalls = 0;

    await rejectsWithCode(service.connect({
      alias: "other",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => {
        confirmationCalls += 1;
        return true;
      },
      openBrowser: false,
      services: ["gmail"],
    }), "GOOGLE_ACCOUNT_ALREADY_CONNECTED");

    assert.equal(confirmationCalls, 0);
    assert.deepEqual(await store.list(), [existing]);
    assert.deepEqual(await vault.getTokens("personal"), existingTokens);
    assert.equal(await vault.getTokens("other"), null);
    assert.equal(vault.oauthClientWrites, 0);
    assert.equal(vault.tokenWrites, 0);
    assert.deepEqual(revoked, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("confirmation callback failure leaves no local state and revokes the new grant", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-failure-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    const vault = new MemoryVault();
    const revoked: string[] = [];
    const service = new AccountService(store, vault, dependencies(oauthResult(), revoked));

    await rejectsWithCode(service.connect({
      alias: "work",
      clientFile: "unused-test-client.json",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => {
        throw new Error("simulated prompt failure");
      },
      openBrowser: false,
      services: ["gmail"],
    }), "ACCOUNT_BINDING_CONFIRMATION_FAILED");

    assert.deepEqual(await store.list(), []);
    assert.equal(vault.oauthClient, null);
    assert.equal(await vault.getTokens("work"), null);
    assert.equal(vault.oauthClientWrites, 0);
    assert.equal(vault.tokenWrites, 0);
    assert.deepEqual(revoked, ["new-refresh-token"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("post-commit metadata failure rolls back metadata, tokens, and the new grant", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-post-commit-"));
  try {
    const store = new CommitThenThrowStore(join(directory, "accounts.json"));
    const vault = new MemoryVault();
    const revoked: string[] = [];
    const service = new AccountService(store, vault, dependencies(oauthResult(), revoked));

    await assert.rejects(service.connect({
      alias: "work",
      clientFile: "unused-test-client.json",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => true,
      openBrowser: false,
      services: ["gmail"],
    }), /simulated post-commit metadata failure/);

    assert.deepEqual(await store.list(), []);
    assert.equal(await vault.getTokens("work"), null);
    assert.deepEqual(revoked, ["new-refresh-token"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("lease loss after OAuth gives precise manual recovery without misleading doctor guidance", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-confirm-lost-lease-"));
  try {
    const store = new LostConnectLeaseStore(join(directory, "accounts.json"));
    const vault = new MemoryVault(CLIENT);
    const revoked: string[] = [];
    const service = new AccountService(store, vault, dependencies(oauthResult(), revoked));

    await assert.rejects(service.connect({
      alias: "work",
      confirmDataUseDisclosure: async () => true,
      confirmAccountBinding: async () => true,
      openBrowser: false,
      services: ["gmail"],
    }), (error: unknown) => {
      assert.ok(error instanceof MultiAccountMcpError);
      assert.equal(error.code, "CONNECT_ROLLBACK_INCOMPLETE");
      assert.match(error.message, /Do not retry or delete `\.connect\.lock`/);
      assert.match(error.message, /wait at least 10 minutes/);
      assert.match(error.message, /multi-account-mcp auth list/);
      assert.match(error.message, /Google Account security/);
      assert.doesNotMatch(error.message, /multi-account-mcp doctor/);
      return true;
    });

    assert.equal(await vault.getTokens("work"), null);
    assert.deepEqual(await store.list(), []);
    assert.deepEqual(revoked, []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
