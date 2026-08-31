import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AccountService } from "../src/auth/account-service.js";
import { generateDpopPrivateJwk } from "../src/auth/google-oauth-client.js";
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

const ACCOUNT: AccountMetadata = {
  id: "11111111-1111-4111-8111-111111111111",
  alias: "personal",
  googleSub: "stable-google-sub",
  email: "person@example.com",
  scopes: ["scope-gmail"],
  createdAt: "2026-08-31T00:00:00.000Z",
  updatedAt: "2026-08-31T00:00:00.000Z",
};

class MemoryVault implements SecretVault {
  readonly tokens = new Map<string, StoredGoogleTokens>();

  constructor(private readonly events: string[]) {}

  async getOAuthClient(): Promise<GoogleOAuthClientCredentials | null> {
    return CLIENT;
  }

  async setOAuthClient(): Promise<void> {}

  async getTokens(alias: string): Promise<StoredGoogleTokens | null> {
    return this.tokens.get(alias) ?? null;
  }

  async setTokens(alias: string, tokens: StoredGoogleTokens): Promise<void> {
    this.tokens.set(alias, tokens);
  }

  async deleteTokens(alias: string): Promise<boolean> {
    this.events.push("delete-token");
    return this.tokens.delete(alias);
  }
}

class DirectorySyncFaultStore extends AccountMetadataStore {
  failDirectorySync = false;
  directorySyncCalls = 0;

  constructor(filePath: string, private readonly events: string[]) {
    super(filePath);
  }

  protected override async syncDirectoryAfterRename(directory: string): Promise<void> {
    this.directorySyncCalls += 1;
    if (this.failDirectorySync) {
      this.events.push("metadata-directory-sync");
      throw new Error("simulated directory fsync failure after rename");
    }
    await super.syncDirectoryAfterRename(directory);
  }
}

class LostBeforeRevokeStore extends AccountMetadataStore {
  override async connectLease<T>(operation: (
    lease: { assertOwned(): Promise<void> },
  ) => Promise<T>): Promise<T> {
    return operation({
      assertOwned: async () => {
        throw new MultiAccountMcpError("simulated lease loss", "CONNECT_LEASE_LOST");
      },
    });
  }
}

class MetadataRemoveFaultStore extends AccountMetadataStore {
  failRemove = false;

  override async transaction<T>(operation: (transaction: {
    list(): Promise<AccountMetadata[]>;
    get(alias: string): Promise<AccountMetadata | null>;
    upsert(account: AccountMetadata): Promise<AccountMetadata>;
    remove(alias: string): Promise<boolean>;
  }) => Promise<T>): Promise<T> {
    return super.transaction((transaction) => operation({
      ...transaction,
      remove: async (alias) => {
        if (this.failRemove) throw new Error("simulated metadata remove failure");
        return transaction.remove(alias);
      },
    }));
  }
}

test("disconnect verifies lease ownership before irreversible Google revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-disconnect-lease-"));
  try {
    const events: string[] = [];
    const store = new LostBeforeRevokeStore(join(directory, "accounts.json"));
    await store.upsert(ACCOUNT);
    const vault = new MemoryVault(events);
    vault.tokens.set("personal", {
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    });
    let revokeCalls = 0;
    const service = new AccountService(store, vault, {
      revokeGoogleToken: async () => {
        revokeCalls += 1;
        events.push("revoke-token");
      },
    });

    await assert.rejects(
      service.disconnect("personal"),
      (error: unknown) => error instanceof MultiAccountMcpError &&
        error.code === "CONNECT_LEASE_LOST",
    );

    assert.equal(revokeCalls, 0);
    assert.deepEqual(events, []);
    assert.equal((await vault.getTokens("personal"))?.refreshToken, "synthetic-refresh-token");
    assert.equal((await store.list())[0]?.alias, "personal");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("disconnect reports post-commit ambiguity without retrying after directory fsync fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-disconnect-commit-"));
  try {
    const events: string[] = [];
    const store = new DirectorySyncFaultStore(join(directory, "accounts.json"), events);
    await store.upsert(ACCOUNT);
    const vault = new MemoryVault(events);
    vault.tokens.set("personal", {
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    });
    let revokeCalls = 0;
    const service = new AccountService(store, vault, {
      revokeGoogleToken: async () => {
        revokeCalls += 1;
        events.push("revoke-token");
      },
    });

    store.failDirectorySync = true;
    await assert.rejects(service.disconnect("personal"), (error: unknown) => {
      assert.ok(error instanceof MultiAccountMcpError);
      assert.equal(error.code, "DISCONNECT_COMMIT_UNCERTAIN");
      assert.match(error.message, /Local state may already be removed/);
      assert.match(error.message, /do not retry automatically/i);
      assert.match(error.message, /multi-account-mcp doctor/);
      assert.match(error.message, /Google Account security/);
      assert.doesNotMatch(error.message, /simulated directory fsync failure/);
      assert.deepEqual(error.safeDetails, { metadataMayAlreadyBeRemoved: true });
      return true;
    });

    assert.deepEqual(events, [
      "revoke-token",
      "delete-token",
      "metadata-directory-sync",
    ]);
    assert.equal(revokeCalls, 1);
    assert.equal(store.directorySyncCalls, 2);
    assert.equal(await vault.getTokens("personal"), null);
    assert.deepEqual(await store.list(), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("disconnect gives safe reconciliation guidance after pre-commit metadata cleanup fails", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-disconnect-local-cleanup-"));
  try {
    const events: string[] = [];
    const store = new MetadataRemoveFaultStore(join(directory, "accounts.json"));
    await store.upsert(ACCOUNT);
    const vault = new MemoryVault(events);
    vault.tokens.set("personal", {
      version: 1,
      refreshToken: "synthetic-refresh-token",
      dpopPrivateJwk: DPOP_PRIVATE_JWK,
    });
    let revokeCalls = 0;
    const service = new AccountService(store, vault, {
      revokeGoogleToken: async () => {
        revokeCalls += 1;
        events.push("revoke-token");
      },
    });
    store.failRemove = true;

    await assert.rejects(service.disconnect("personal"), (error: unknown) => {
      assert.ok(error instanceof MultiAccountMcpError);
      assert.equal(error.code, "DISCONNECT_LOCAL_CLEANUP_INCOMPLETE");
      assert.match(error.message, /Do not retry automatically/);
      assert.match(error.message, /multi-account-mcp doctor/);
      assert.match(error.message, /Google Account security/);
      assert.match(error.message, /--local-only/);
      assert.doesNotMatch(error.message, /simulated metadata remove failure/);
      assert.deepEqual(error.safeDetails, {
        googleRevocationCompleted: true,
        localTokenDeletionConfirmed: true,
      });
      return true;
    });

    assert.equal(revokeCalls, 1);
    assert.deepEqual(events, ["revoke-token", "delete-token"]);
    assert.equal(await vault.getTokens("personal"), null);
    assert.equal((await store.list())[0]?.alias, "personal");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
