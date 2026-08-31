import { randomUUID, timingSafeEqual } from "node:crypto";
import {
  constants as fsConstants,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";
import { MultiAccountMcpError } from "../errors.js";
import type { AccountFile, AccountMetadata } from "../types.js";
import { assertValidAlias } from "../policy/input.js";

function defaultConfigDirectory(): string {
  const override = process.env.MULTI_ACCOUNT_MCP_HOME;
  if (override) return join(assertAbsoluteConfigRoot(override, "MULTI_ACCOUNT_MCP_HOME"), "multi-account-mcp");

  if (process.platform === "win32") {
    const appData = process.env.APPDATA;
    if (appData) return join(assertAbsoluteConfigRoot(appData, "APPDATA"), "Multi-Account MCP");
  }

  const xdgConfig = process.env.XDG_CONFIG_HOME;
  return xdgConfig
    ? join(assertAbsoluteConfigRoot(xdgConfig, "XDG_CONFIG_HOME"), "multi-account-mcp")
    : join(homedir(), ".config", "multi-account-mcp");
}

function assertAbsoluteConfigRoot(root: string, variable: string): string {
  if (!isAbsolute(root)) {
    throw new MultiAccountMcpError(
      `${variable} must name an absolute local directory.`,
      "UNSAFE_STORAGE_DIRECTORY",
    );
  }
  return resolve(root);
}

const MAX_METADATA_BYTES = 1_000_000;
const OWNER_MARKER = ".multi-account-mcp-owned";
const LOCK_NAME = ".accounts.lock";
const CONNECT_LOCK_NAME = ".connect.lock";
const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 10 * 60_000;
const CONNECT_LOCK_HEARTBEAT_MS = 30_000;
const MAX_LOCK_BYTES = 128;

async function readMetadataFile(path: string): Promise<string> {
  let handle;
  try {
    const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
    const nonBlocking = "O_NONBLOCK" in fsConstants ? fsConstants.O_NONBLOCK : 0;
    handle = await open(path, fsConstants.O_RDONLY | noFollow | nonBlocking);
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size > MAX_METADATA_BYTES) {
      throw new MultiAccountMcpError(
        "Multi-Account MCP account metadata is not a bounded regular file.",
        "INVALID_ACCOUNT_METADATA",
      );
    }
    if (process.platform !== "win32") {
      if ((stats.mode & 0o077) !== 0 || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
        throw new MultiAccountMcpError(
          "Multi-Account MCP account metadata has unsafe ownership or permissions.",
          "UNSAFE_ACCOUNT_METADATA_PERMISSIONS",
        );
      }
    }

    const buffer = Buffer.alloc(MAX_METADATA_BYTES + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset > MAX_METADATA_BYTES) {
      throw new MultiAccountMcpError(
        "Multi-Account MCP account metadata is unexpectedly large.",
        "INVALID_ACCOUNT_METADATA",
      );
    }
    return buffer.subarray(0, offset).toString("utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ELOOP") {
      throw new MultiAccountMcpError(
        `Refusing to use symlinked security-sensitive path: ${path}`,
        "SYMLINKED_STORAGE_PATH",
      );
    }
    throw error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function parseAccountFile(raw: string): AccountFile {
  if (Buffer.byteLength(raw, "utf8") > MAX_METADATA_BYTES) {
    throw new MultiAccountMcpError("Multi-Account MCP account metadata is unexpectedly large.", "INVALID_ACCOUNT_METADATA");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new MultiAccountMcpError(
      "Multi-Account MCP account metadata is not valid JSON.",
      "INVALID_ACCOUNT_METADATA",
    );
  }

  if (!parsed || typeof parsed !== "object") {
    throw new MultiAccountMcpError("Multi-Account MCP account metadata is malformed.", "INVALID_ACCOUNT_METADATA");
  }

  const candidate = parsed as Partial<AccountFile>;
  if (candidate.version !== 1 || !Array.isArray(candidate.accounts)) {
    throw new MultiAccountMcpError(
      "Multi-Account MCP account metadata uses an unsupported format.",
      "INVALID_ACCOUNT_METADATA",
    );
  }

  if (candidate.accounts.length > 100) {
    throw new MultiAccountMcpError("Multi-Account MCP account metadata contains too many accounts.", "INVALID_ACCOUNT_METADATA");
  }

  const ids = new Set<string>();
  const aliases = new Set<string>();
  const identities = new Set<string>();
  for (const account of candidate.accounts) {
    if (
      !account ||
      typeof account.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(account.id) ||
      typeof account.alias !== "string" ||
      typeof account.googleSub !== "string" || !/^[A-Za-z0-9_-]{1,255}$/.test(account.googleSub) ||
      typeof account.email !== "string" || account.email.length > 320 || !account.email.includes("@") ||
      (account.displayName !== undefined && typeof account.displayName !== "string") ||
      !Array.isArray(account.scopes) ||
      account.scopes.length > 20 ||
      !account.scopes.every((scope) => typeof scope === "string") ||
      typeof account.createdAt !== "string" ||
      Number.isNaN(Date.parse(account.createdAt)) ||
      typeof account.updatedAt !== "string" ||
      Number.isNaN(Date.parse(account.updatedAt))
    ) {
      throw new MultiAccountMcpError("Multi-Account MCP account metadata is malformed.", "INVALID_ACCOUNT_METADATA");
    }
    assertValidAlias(account.alias);
    if (ids.has(account.id) || aliases.has(account.alias) || identities.has(account.googleSub)) {
      throw new MultiAccountMcpError("Multi-Account MCP account metadata contains duplicate identities.", "INVALID_ACCOUNT_METADATA");
    }
    ids.add(account.id);
    aliases.add(account.alias);
    identities.add(account.googleSub);
  }

  return candidate as AccountFile;
}

async function rejectSymlink(path: string): Promise<void> {
  try {
    const stats = await lstat(path);
    if (stats.isSymbolicLink()) {
      throw new MultiAccountMcpError(
        `Refusing to use symlinked security-sensitive path: ${path}`,
        "SYMLINKED_STORAGE_PATH",
      );
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function assertDedicatedDirectory(directory: string): void {
  const resolved = resolve(directory);
  const forbidden = new Set([
    parse(resolved).root,
    resolve(homedir()),
    resolve(tmpdir()),
    resolve(process.cwd()),
  ]);
  if (forbidden.has(resolved)) {
    throw new MultiAccountMcpError(
      `Refusing to use a broad directory for Multi-Account MCP state: ${resolved}`,
      "UNSAFE_STORAGE_DIRECTORY",
    );
  }
}

async function ownerMarkerExistsAndIsSafe(marker: string): Promise<boolean> {
  let markerStats;
  try {
    markerStats = await lstat(marker);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  if (
    markerStats.isSymbolicLink() ||
    !markerStats.isFile() ||
    (process.platform !== "win32" && (
      (markerStats.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && markerStats.uid !== process.getuid())
    ))
  ) {
    throw new MultiAccountMcpError(
      "Multi-Account MCP state ownership marker is unsafe.",
      "UNSAFE_STORAGE_DIRECTORY",
    );
  }
  return true;
}

async function ensureDedicatedDirectory(directory: string): Promise<void> {
  assertDedicatedDirectory(directory);
  await mkdir(dirname(directory), { recursive: true, mode: 0o700 });
  let created = false;
  try {
    await mkdir(directory, { mode: 0o700 });
    created = true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  const stats = await lstat(directory);
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new MultiAccountMcpError(
      "Multi-Account MCP state must use a dedicated, non-symlinked directory.",
      "UNSAFE_STORAGE_DIRECTORY",
    );
  }
  if (process.platform !== "win32") {
    if ((stats.mode & 0o077) !== 0 || (typeof process.getuid === "function" && stats.uid !== process.getuid())) {
      throw new MultiAccountMcpError(
        "Multi-Account MCP state directory has unsafe ownership or permissions.",
        "UNSAFE_STORAGE_DIRECTORY",
      );
    }
  }

  const marker = join(directory, OWNER_MARKER);
  if (!(await ownerMarkerExistsAndIsSafe(marker))) {
    const entries = await readdir(directory);
    if (!created && entries.length > 0) {
      // Another first-use caller may have created the marker and its lock after
      // our initial ENOENT. Re-check before treating the directory as foreign.
      if (!(await ownerMarkerExistsAndIsSafe(marker))) {
        throw new MultiAccountMcpError(
          "Refusing to adopt a non-empty directory as Multi-Account MCP state.",
          "UNSAFE_STORAGE_DIRECTORY",
        );
      }
      return;
    }
    try {
      await writeFile(marker, "multi-account-mcp-state-v1\n", { flag: "wx", mode: 0o600 });
    } catch (writeError) {
      if ((writeError as NodeJS.ErrnoException).code !== "EEXIST") throw writeError;
      if (!(await ownerMarkerExistsAndIsSafe(marker))) {
        throw new MultiAccountMcpError(
          "Multi-Account MCP state ownership marker disappeared during initialization.",
          "UNSAFE_STORAGE_DIRECTORY",
        );
      }
    }
  }
}

interface LockOwnership {
  device: bigint;
  inode: bigint;
  contents: string;
}

function lockIdentityMatches(
  stats: { dev: bigint; ino: bigint },
  expected: Pick<LockOwnership, "device" | "inode">,
): boolean {
  return (
    expected.device !== 0n &&
    expected.inode !== 0n &&
    stats.dev === expected.device &&
    stats.ino === expected.inode
  );
}

async function lockPathMatchesOwnership(path: string, expected: LockOwnership): Promise<boolean> {
  let handle;
  try {
    const initialPathStats = await lstat(path, { bigint: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    });
    if (
      !initialPathStats ||
      initialPathStats.isSymbolicLink() ||
      !initialPathStats.isFile() ||
      !lockIdentityMatches(initialPathStats, expected)
    ) {
      return false;
    }

    const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
    const nonBlocking = "O_NONBLOCK" in fsConstants ? fsConstants.O_NONBLOCK : 0;
    handle = await open(path, fsConstants.O_RDONLY | noFollow | nonBlocking);
    const stats = await handle.stat({ bigint: true });
    if (
      !stats.isFile() ||
      stats.size > BigInt(MAX_LOCK_BYTES) ||
      !lockIdentityMatches(stats, expected)
    ) {
      return false;
    }

    const expectedBytes = Buffer.from(expected.contents, "utf8");
    if (expectedBytes.length === 0 || stats.size !== BigInt(expectedBytes.length)) return false;
    const actual = Buffer.alloc(expectedBytes.length);
    let offset = 0;
    while (offset < actual.length) {
      const { bytesRead } = await handle.read(actual, offset, actual.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== expectedBytes.length || !timingSafeEqual(actual, expectedBytes)) return false;

    const pathStats = await lstat(path, { bigint: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    });
    if (
      !pathStats ||
      pathStats.isSymbolicLink() ||
      !pathStats.isFile() ||
      !lockIdentityMatches(pathStats, expected)
    ) {
      return false;
    }
    return true;
  } catch (error) {
    if (["ENOENT", "ELOOP"].includes((error as NodeJS.ErrnoException).code ?? "")) return false;
    throw error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function assertSafeLockPathIfPresent(path: string, message: string): Promise<void> {
  const stats = await lstat(path).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  });
  if (stats && (stats.isSymbolicLink() || !stats.isFile())) {
    throw new MultiAccountMcpError(message, "UNSAFE_STORAGE_DIRECTORY");
  }
}

async function assertOpenedLockStillOwnsPath(
  path: string,
  ownership: Pick<LockOwnership, "device" | "inode">,
  message: string,
): Promise<void> {
  const stats = await lstat(path, { bigint: true }).catch((error) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  });
  if (
    !stats ||
    stats.isSymbolicLink() ||
    !stats.isFile() ||
    !lockIdentityMatches(stats, ownership)
  ) {
    throw new MultiAccountMcpError(message, "UNSAFE_STORAGE_DIRECTORY");
  }
}

function staleStateLock(): MultiAccountMcpError {
  return new MultiAccountMcpError(
    "Multi-Account MCP found a stale state lock from a process that is no longer running. It was preserved because automatic deletion can race with another process. Stop all Multi-Account MCP processes, confirm none are active, then follow SECURITY.md to remove the exact `.accounts.lock` before retrying.",
    "STALE_ACCOUNT_STATE_LOCK",
  );
}

function stateLockCleanupUncertain(): MultiAccountMcpError {
  return new MultiAccountMcpError(
    "An account metadata operation may have completed, but its state lock could not be safely released. Do not retry automatically or delete `.accounts.lock`. Stop all Multi-Account MCP processes, inspect `multi-account-mcp auth list`, then follow SECURITY.md to reconcile the exact lock before retrying once.",
    "ACCOUNT_STATE_LOCK_CLEANUP_UNCERTAIN",
  );
}

function staleConnectLock(): MultiAccountMcpError {
  return new MultiAccountMcpError(
    "Multi-Account MCP found a stale account-operation lease from a process that is no longer running. It was preserved because automatic deletion can race with another process. Do not retry automatically. Stop all Multi-Account MCP auth commands, run `multi-account-mcp auth list`, review Multi-Account MCP in Google Account security, then follow SECURITY.md to remove the exact `.connect.lock` only after reconciling both states.",
    "STALE_ACCOUNT_CONNECTION_LOCK",
  );
}

async function acquireStateLock(directory: string): Promise<() => Promise<void>> {
  await ensureDedicatedDirectory(directory);
  const lockPath = join(directory, LOCK_NAME);
  const startedAt = Date.now();
  const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
  while (true) {
    try {
      await assertSafeLockPathIfPresent(
        lockPath,
        "Multi-Account MCP's state lock is unsafe.",
      );
      const handle = await open(
        lockPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
        0o600,
      );
      let ownedDevice = 0n;
      let ownedInode = 0n;
      const lockContents = `${process.pid} ${randomUUID()}\n`;
      try {
        const ownedStats = await handle.stat({ bigint: true });
        ownedDevice = ownedStats.dev;
        ownedInode = ownedStats.ino;
        await assertOpenedLockStillOwnsPath(
          lockPath,
          { device: ownedDevice, inode: ownedInode },
          "Multi-Account MCP's state lock changed while it was being acquired.",
        );
        await handle.writeFile(lockContents, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      if (!(await lockPathMatchesOwnership(lockPath, {
        device: ownedDevice,
        inode: ownedInode,
        contents: lockContents,
      }))) {
        throw new MultiAccountMcpError(
          "Multi-Account MCP's state lock changed while it was being acquired.",
          "UNSAFE_STORAGE_DIRECTORY",
        );
      }
      return async () => {
        try {
          if (!(await lockPathMatchesOwnership(lockPath, {
            device: ownedDevice,
            inode: ownedInode,
            contents: lockContents,
          }))) {
            throw stateLockCleanupUncertain();
          }
          await unlink(lockPath);
        } catch (error) {
          if (
            error instanceof MultiAccountMcpError &&
            error.code === "ACCOUNT_STATE_LOCK_CLEANUP_UNCERTAIN"
          ) {
            throw error;
          }
          throw stateLockCleanupUncertain();
        }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const stats = await lstat(lockPath).catch((statError) => {
        if ((statError as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw statError;
      });
      if (stats) {
        if (stats.isSymbolicLink() || !stats.isFile()) {
          throw new MultiAccountMcpError("Multi-Account MCP's state lock is unsafe.", "UNSAFE_STORAGE_DIRECTORY");
        }
        if (Date.now() - stats.mtimeMs > LOCK_STALE_MS) {
          const holderPid = await readLockPid(lockPath);
          if (!holderPid || !processIsAlive(holderPid)) {
            throw staleStateLock();
          }
        }
      }
      if (Date.now() - startedAt >= LOCK_WAIT_MS) {
        throw new MultiAccountMcpError(
          "Another Multi-Account MCP account operation is active. Wait for it to finish and retry.",
          "ACCOUNT_STATE_BUSY",
        );
      }
      await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 50));
    }
  }
}

interface ConnectLease {
  assertOwned(): Promise<void>;
  release(): Promise<void>;
}

async function readLockPid(path: string): Promise<number | null> {
  let handle;
  try {
    const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
    const nonBlocking = "O_NONBLOCK" in fsConstants ? fsConstants.O_NONBLOCK : 0;
    handle = await open(path, fsConstants.O_RDONLY | noFollow | nonBlocking);
    const openedStats = await handle.stat({ bigint: true });
    if (
      !openedStats.isFile() ||
      openedStats.size > BigInt(MAX_LOCK_BYTES) ||
      openedStats.dev === 0n ||
      openedStats.ino === 0n
    ) {
      return null;
    }
    const buffer = Buffer.alloc(MAX_LOCK_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const pathStats = await lstat(path, { bigint: true }).catch((error) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    });
    if (
      !pathStats ||
      pathStats.isSymbolicLink() ||
      !pathStats.isFile() ||
      pathStats.dev !== openedStats.dev ||
      pathStats.ino !== openedStats.ino
    ) {
      return null;
    }
    const match = /^(\d+)\s/.exec(buffer.subarray(0, bytesRead).toString("utf8"));
    if (!match?.[1]) return null;
    const pid = Number(match[1]);
    return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
  } catch (error) {
    if (["ENOENT", "ELOOP"].includes((error as NodeJS.ErrnoException).code ?? "")) return null;
    throw error;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function connectLeaseLost(): MultiAccountMcpError {
  return new MultiAccountMcpError(
    "The account-operation lease was lost. Do not retry automatically or delete `.connect.lock`. Stop all Multi-Account MCP auth commands, wait at least 10 minutes, run `multi-account-mcp auth list`, and review Multi-Account MCP in Google Account security before trying once more.",
    "CONNECT_LEASE_LOST",
  );
}

async function acquireConnectLease(directory: string): Promise<ConnectLease> {
  await ensureDedicatedDirectory(directory);
  const lockPath = join(directory, CONNECT_LOCK_NAME);
  const startedAt = Date.now();
  const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
  while (true) {
    try {
      await assertSafeLockPathIfPresent(
        lockPath,
        "Multi-Account MCP's account-connection lease is unsafe.",
      );
      const handle = await open(
        lockPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | noFollow,
        0o600,
      );
      let ownedDevice = 0n;
      let ownedInode = 0n;
      const lockContents = `${process.pid} ${randomUUID()}\n`;
      try {
        const ownedStats = await handle.stat({ bigint: true });
        ownedDevice = ownedStats.dev;
        ownedInode = ownedStats.ino;
        await assertOpenedLockStillOwnsPath(
          lockPath,
          { device: ownedDevice, inode: ownedInode },
          "Multi-Account MCP's account-connection lease changed while it was being acquired.",
        );
        await handle.writeFile(lockContents, "utf8");
        await handle.sync();
        if (!(await lockPathMatchesOwnership(lockPath, {
          device: ownedDevice,
          inode: ownedInode,
          contents: lockContents,
        }))) {
          throw connectLeaseLost();
        }
      } catch (error) {
        await handle.close().catch(() => undefined);
        try {
          if (await lockPathMatchesOwnership(lockPath, {
            device: ownedDevice,
            inode: ownedInode,
            contents: lockContents,
          })) {
            await unlink(lockPath);
          }
        } catch {
          // Preserve uncertain state. The original error remains the most useful
          // description, and the lock must never be deleted without ownership.
        }
        throw error;
      }

      let heartbeatError: unknown;
      let heartbeatChain = Promise.resolve();
      const renew = async (): Promise<void> => {
        if (heartbeatError) return;
        if (!(await lockPathMatchesOwnership(lockPath, {
          device: ownedDevice,
          inode: ownedInode,
          contents: lockContents,
        }))) {
          throw connectLeaseLost();
        }
        const now = new Date();
        await handle.utimes(now, now);
      };
      const scheduleHeartbeat = (): void => {
        heartbeatChain = heartbeatChain
          .then(renew)
          .catch((error: unknown) => {
            heartbeatError = error;
          });
      };
      const heartbeat = setInterval(scheduleHeartbeat, CONNECT_LOCK_HEARTBEAT_MS);
      heartbeat.unref();

      return {
        assertOwned: async () => {
          scheduleHeartbeat();
          await heartbeatChain;
          if (heartbeatError) throw connectLeaseLost();
        },
        release: async () => {
          clearInterval(heartbeat);
          await heartbeatChain;
          let cleanupError = heartbeatError;
          let ownsCurrentPath = false;
          try {
            ownsCurrentPath = await lockPathMatchesOwnership(lockPath, {
              device: ownedDevice,
              inode: ownedInode,
              contents: lockContents,
            });
          } catch (error) {
            cleanupError ??= error;
          }
          try {
            await handle.close();
          } catch (error) {
            cleanupError ??= error;
          }
          if (ownsCurrentPath) {
            try {
              await unlink(lockPath);
            } catch (error) {
              cleanupError ??= error;
            }
          } else {
            cleanupError ??= connectLeaseLost();
          }
          if (cleanupError) {
            throw new MultiAccountMcpError(
              "An account operation may have completed, but its cross-process lease could not be safely released. Do not retry automatically or delete `.connect.lock`. Stop all Multi-Account MCP auth commands, wait at least 10 minutes, then run `multi-account-mcp auth list` and review Multi-Account MCP in Google Account security. Retry once only after reconciling both states.",
              "ACCOUNT_MUTATION_LEASE_CLEANUP_UNCERTAIN",
            );
          }
        },
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const stats = await lstat(lockPath).catch((statError) => {
        if ((statError as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw statError;
      });
      if (stats) {
        if (stats.isSymbolicLink() || !stats.isFile()) {
          throw new MultiAccountMcpError(
            "Multi-Account MCP's account-connection lease is unsafe.",
            "UNSAFE_STORAGE_DIRECTORY",
          );
        }
        if (Date.now() - stats.mtimeMs > LOCK_STALE_MS) {
          const holderPid = await readLockPid(lockPath);
          if (!holderPid || !processIsAlive(holderPid)) {
            throw staleConnectLock();
          }
        }
      }
      if (Date.now() - startedAt >= LOCK_WAIT_MS) {
        throw new MultiAccountMcpError(
          "Another Multi-Account MCP account connection is active. Finish or cancel it, then retry.",
          "ACCOUNT_STATE_BUSY",
        );
      }
      await new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 50));
    }
  }
}

export class AccountMetadataStore {
  readonly filePath: string;

  constructor(filePath = join(defaultConfigDirectory(), "accounts.json")) {
    this.filePath = resolve(filePath);
  }

  async list(): Promise<AccountMetadata[]> {
    try {
      const file = parseAccountFile(await readMetadataFile(this.filePath));
      return [...file.accounts].sort((a, b) => a.alias.localeCompare(b.alias));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  async get(alias: string): Promise<AccountMetadata | null> {
    assertValidAlias(alias);
    return (await this.list()).find((account) => account.alias === alias) ?? null;
  }

  async connectLease<T>(
    operation: (lease: { assertOwned(): Promise<void> }) => Promise<T>,
  ): Promise<T> {
    await rejectSymlink(this.filePath);
    const lease = await acquireConnectLease(dirname(this.filePath));
    try {
      return await operation({ assertOwned: () => lease.assertOwned() });
    } finally {
      await lease.release();
    }
  }

  async transaction<T>(operation: (transaction: {
    list(): Promise<AccountMetadata[]>;
    get(alias: string): Promise<AccountMetadata | null>;
    upsert(account: AccountMetadata): Promise<AccountMetadata>;
    remove(alias: string): Promise<boolean>;
  }) => Promise<T>): Promise<T> {
    await rejectSymlink(this.filePath);
    const release = await acquireStateLock(dirname(this.filePath));
    try {
      return await operation({
        list: () => this.list(),
        get: (alias) => this.get(alias),
        upsert: (account) => this.upsertUnlocked(account),
        remove: (alias) => this.removeUnlocked(alias),
      });
    } finally {
      await release();
    }
  }

  async upsert(account: AccountMetadata): Promise<AccountMetadata> {
    return this.transaction((transaction) => transaction.upsert(account));
  }

  private async upsertUnlocked(account: AccountMetadata): Promise<AccountMetadata> {
    assertValidAlias(account.alias);
    const accounts = await this.list();
    const aliasMatch = accounts.find((candidate) => candidate.alias === account.alias);
    const identityMatch = accounts.find((candidate) => candidate.googleSub === account.googleSub);

    if (aliasMatch && aliasMatch.googleSub !== account.googleSub) {
      throw new MultiAccountMcpError(
        `Alias "${account.alias}" is already bound to another Google account. Remove it explicitly before reusing the alias.`,
        "ALIAS_ALREADY_BOUND",
      );
    }
    if (identityMatch && identityMatch.alias !== account.alias) {
      throw new MultiAccountMcpError(
        `That Google account is already connected as "${identityMatch.alias}".`,
        "GOOGLE_ACCOUNT_ALREADY_CONNECTED",
      );
    }

    const stored: AccountMetadata = {
      ...account,
      id: aliasMatch?.id ?? account.id,
      createdAt: aliasMatch?.createdAt ?? account.createdAt,
    };
    const next = accounts.filter((candidate) => candidate.alias !== account.alias);
    next.push(stored);
    await this.write({ version: 1, accounts: next });
    return stored;
  }

  async remove(alias: string): Promise<boolean> {
    return this.transaction((transaction) => transaction.remove(alias));
  }

  private async removeUnlocked(alias: string): Promise<boolean> {
    assertValidAlias(alias);
    const accounts = await this.list();
    const next = accounts.filter((account) => account.alias !== alias);
    if (next.length === accounts.length) return false;
    await this.write({ version: 1, accounts: next });
    return true;
  }

  protected async syncDirectoryAfterRename(directory: string): Promise<void> {
    if (process.platform === "win32") return;
    const directoryHandle = await open(directory, fsConstants.O_RDONLY);
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
  }

  private async write(file: AccountFile): Promise<void> {
    const serialized = `${JSON.stringify(file, null, 2)}\n`;
    // Validate the exact bytes that will be committed. This keeps the writer
    // from creating state that the bounded reader would subsequently reject.
    parseAccountFile(serialized);

    const directory = dirname(this.filePath);
    await ensureDedicatedDirectory(directory);
    await rejectSymlink(this.filePath);

    const temporary = join(directory, `.accounts.${randomUUID()}.tmp`);
    let handle;
    try {
      handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
      await handle.writeFile(serialized, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporary, this.filePath);
      try {
        await this.syncDirectoryAfterRename(directory);
      } catch {
        throw new MultiAccountMcpError(
          "Account metadata was renamed into place, but filesystem durability could not be confirmed. The update may already be committed; do not retry automatically.",
          "ACCOUNT_METADATA_COMMIT_UNCERTAIN",
          { commitStage: "after_rename" },
        );
      }
    } finally {
      await handle?.close().catch(() => undefined);
      await unlink(temporary).catch(() => undefined);
    }
  }
}
