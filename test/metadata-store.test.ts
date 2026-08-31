import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  lstat,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AccountMetadataStore } from "../src/storage/metadata-store.js";
import type { AccountMetadata } from "../src/types.js";

function account(overrides: Partial<AccountMetadata> = {}): AccountMetadata {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    alias: "personal",
    googleSub: "stable-google-sub",
    email: "person@example.com",
    scopes: ["scope-a"],
    createdAt: "2026-08-31T00:00:00.000Z",
    updatedAt: "2026-08-31T00:00:00.000Z",
    ...overrides,
  };
}

test("metadata is atomic, contains no tokens, and is mode 0600", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-store-"));
  try {
    const filePath = join(directory, "nested", "accounts.json");
    const store = new AccountMetadataStore(filePath);
    await store.upsert(account());
    const raw = await readFile(filePath, "utf8");
    assert.doesNotMatch(raw, /refresh.?token/i);
    assert.equal(JSON.parse(raw).accounts[0].googleSub, "stable-google-sub");
    if (process.platform !== "win32") {
      assert.equal((await lstat(filePath)).mode & 0o777, 0o600);
      assert.equal((await lstat(join(directory, "nested"))).mode & 0o777, 0o700);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stable Google identity cannot be silently rebound to another alias", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-identity-"));
  try {
    const store = new AccountMetadataStore(join(directory, "accounts.json"));
    await store.upsert(account());
    await assert.rejects(
      store.upsert(account({ alias: "other", id: "22222222-2222-4222-8222-222222222222" })),
      /already connected as "personal"/,
    );
    await assert.rejects(
      store.upsert(account({ googleSub: "different-sub" })),
      /already bound/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("concurrent store processes do not lose account updates", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-concurrent-"));
  try {
    const filePath = join(directory, "state", "accounts.json");
    const first = new AccountMetadataStore(filePath);
    const second = new AccountMetadataStore(filePath);
    await Promise.all([
      first.upsert(account()),
      second.upsert(account({
        id: "22222222-2222-4222-8222-222222222222",
        alias: "work",
        googleSub: "second-google-sub",
        email: "person@work.example",
      })),
    ]);
    assert.deepEqual((await first.list()).map((item) => item.alias), ["personal", "work"]);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fresh state-directory initialization is race-safe under contention", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-first-use-race-"));
  try {
    const filePath = join(directory, "state", "accounts.json");
    const contenders = Array.from({ length: 24 }, (_, index) => {
      const sequence = index.toString(16).padStart(12, "0");
      return new AccountMetadataStore(filePath).upsert(account({
        id: `00000000-0000-4000-8000-${sequence}`,
        alias: `account-${index}`,
        googleSub: `google-sub-${index}`,
        email: `person-${index}@example.com`,
      }));
    });

    await Promise.all(contenders);
    const stored = await new AccountMetadataStore(filePath).list();
    assert.equal(stored.length, contenders.length);
    assert.deepEqual(
      stored.map((item) => item.alias),
      Array.from({ length: 24 }, (_, index) => `account-${index}`).sort(),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("writer refuses to create metadata beyond the account-count bound", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-account-bound-"));
  try {
    const store = new AccountMetadataStore(join(directory, "state", "accounts.json"));
    for (let index = 0; index < 100; index += 1) {
      await store.upsert(account({
        id: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
        alias: `account-${index}`,
        googleSub: `google-sub-${index}`,
        email: `person-${index}@example.com`,
      }));
    }

    await assert.rejects(
      store.upsert(account({
        id: "00000000-0000-4000-8000-000000000100",
        alias: "account-100",
        googleSub: "google-sub-100",
        email: "person-100@example.com",
      })),
      (error: unknown) => (error as { code?: string }).code === "INVALID_ACCOUNT_METADATA",
    );
    assert.equal((await store.list()).length, 100);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("writer refuses oversized metadata before committing it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-byte-bound-"));
  try {
    const store = new AccountMetadataStore(join(directory, "state", "accounts.json"));
    await assert.rejects(
      store.upsert(account({ displayName: "x".repeat(1_000_000) })),
      (error: unknown) => (error as { code?: string }).code === "INVALID_ACCOUNT_METADATA",
    );
    assert.deepEqual(await store.list(), []);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("metadata storage refuses a symlink target", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-symlink-"));
  try {
    const target = join(directory, "target.json");
    const link = join(directory, "accounts.json");
    await symlink(target, link);
    const store = new AccountMetadataStore(link);
    await assert.rejects(store.upsert(account()), /Refusing to use symlinked/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("account-connection leases serialize OAuth flows", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-connect-lease-"));
  try {
    const store = new AccountMetadataStore(join(directory, "state", "accounts.json"));
    let releaseFirst!: () => void;
    const firstMayFinish = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let markFirstEntered!: () => void;
    const firstEntered = new Promise<void>((resolve) => {
      markFirstEntered = resolve;
    });
    let secondEntered = false;

    const first = store.connectLease(async () => {
      markFirstEntered();
      await firstMayFinish;
    });
    await firstEntered;
    const second = store.connectLease(async () => {
      secondEntered = true;
    });

    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    assert.equal(secondEntered, false);
    releaseFirst();
    await Promise.all([first, second]);
    assert.equal(secondEntered, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("account-connection leases serialize separate processes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-connect-process-"));
  const filePath = join(directory, "state", "accounts.json");
  const childScript = `
    const { AccountMetadataStore } = await import("./src/storage/metadata-store.ts");
    const store = new AccountMetadataStore(process.argv[1]);
    await store.connectLease(async () => {
      process.stdout.write("LOCKED\\n");
      process.stdin.resume();
      await new Promise((resolve) => process.stdin.once("end", resolve));
    });
  `;
  const child = spawn(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", childScript, filePath],
    {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-4_096);
  });
  let parentLease: Promise<void> | undefined;
  try {
    child.stdout.setEncoding("utf8");
    const childExit = once(child, "exit");
    await Promise.race([
      new Promise<void>((resolve) => {
        child.stdout.on("data", (chunk: string) => {
          if (chunk.includes("LOCKED")) resolve();
        });
      }),
      childExit.then(([code]) => {
        throw new Error(`lease child exited early with ${String(code)}: ${stderr}`);
      }),
    ]);

    const store = new AccountMetadataStore(filePath);
    let parentEntered = false;
    parentLease = store.connectLease(async () => {
      parentEntered = true;
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    assert.equal(parentEntered, false);

    child.stdin.end();
    const [code] = await childExit;
    assert.equal(code, 0, stderr);
    await parentLease;
    assert.equal(parentEntered, true);
  } finally {
    if (child.exitCode === null) child.kill();
    await parentLease?.catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
});

test("account-connection lease recovers a stale lock from a dead process", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-connect-stale-"));
  try {
    const stateDirectory = join(directory, "state");
    const store = new AccountMetadataStore(join(stateDirectory, "accounts.json"));
    await store.connectLease(async () => undefined);

    const lockPath = join(stateDirectory, ".connect.lock");
    await writeFile(lockPath, "2147483647 stale-test-lease\n", { flag: "wx", mode: 0o600 });
    const staleTime = new Date(Date.now() - 11 * 60_000);
    await utimes(lockPath, staleTime, staleTime);

    let entered = false;
    await store.connectLease(async () => {
      entered = true;
    });
    assert.equal(entered, true);
    await assert.rejects(lstat(lockPath), { code: "ENOENT" });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("account-connection lease refuses a symlinked lock", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-connect-symlink-"));
  try {
    const stateDirectory = join(directory, "state");
    const store = new AccountMetadataStore(join(stateDirectory, "accounts.json"));
    await store.connectLease(async () => undefined);

    await symlink(join(directory, "outside-lock"), join(stateDirectory, ".connect.lock"));
    await assert.rejects(
      store.connectLease(async () => undefined),
      /account-connection lease is unsafe/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("account-connection lease detects path replacement and preserves the replacement", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-connect-lost-"));
  try {
    const stateDirectory = join(directory, "state");
    const lockPath = join(stateDirectory, ".connect.lock");
    const displacedPath = join(stateDirectory, ".connect.displaced");
    const store = new AccountMetadataStore(join(stateDirectory, "accounts.json"));

    await assert.rejects(
      store.connectLease(async (lease) => {
        await rename(lockPath, displacedPath);
        await writeFile(lockPath, "2147483647 replacement-lease\n", {
          flag: "wx",
          mode: 0o600,
        });
        await lease.assertOwned();
      }),
      (error: unknown) => {
        assert.equal(
          (error as { code?: string }).code,
          "ACCOUNT_MUTATION_LEASE_CLEANUP_UNCERTAIN",
        );
        assert.match((error as Error).message, /Do not retry automatically or delete `\.connect\.lock`/);
        assert.match((error as Error).message, /wait at least 10 minutes/);
        assert.match((error as Error).message, /multi-account-mcp auth list/);
        assert.match((error as Error).message, /Google Account security/);
        assert.doesNotMatch((error as Error).message, /multi-account-mcp doctor/);
        return true;
      },
    );
    assert.equal(await readFile(lockPath, "utf8"), "2147483647 replacement-lease\n");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
