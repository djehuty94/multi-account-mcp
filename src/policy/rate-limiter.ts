import { createHash } from "node:crypto";
import { MCP_RATE_LIMITS } from "../constants.js";
import { MultiAccountMcpError } from "../errors.js";
import { assertValidAlias } from "./input.js";

export interface TokenBucketPolicy {
  capacity: number;
  refillPerSecond: number;
}

export interface InvocationRateLimiterOptions {
  clock?: () => number;
  global?: TokenBucketPolicy;
  perAccount?: TokenBucketPolicy;
  listAccounts?: TokenBucketPolicy;
  maxAccountBuckets?: number;
}

interface Bucket {
  tokens: number;
  updatedAtMs: number;
  lastUsed: number;
}

const ONE_TOKEN = 1;

function validatePolicy(name: string, policy: TokenBucketPolicy): TokenBucketPolicy {
  if (
    !Number.isFinite(policy.capacity) ||
    policy.capacity < ONE_TOKEN ||
    !Number.isFinite(policy.refillPerSecond) ||
    policy.refillPerSecond <= 0
  ) {
    throw new Error(`${name} rate-limit policy must have a capacity of at least one and a positive refill rate.`);
  }
  return policy;
}

function accountKey(alias: string): string {
  return createHash("sha256").update(assertValidAlias(alias), "utf8").digest("base64url");
}

function rateLimited(retryAfterSeconds: number): MultiAccountMcpError {
  const safeRetryAfter = Math.max(1, Math.ceil(retryAfterSeconds));
  return new MultiAccountMcpError(
    `MCP invocation rate limit exceeded. Retry after ${safeRetryAfter} seconds.`,
    "MCP_RATE_LIMITED",
    { retryAfterSeconds: safeRetryAfter },
  );
}

export class InvocationRateLimiter {
  private readonly clock: () => number;
  private readonly globalPolicy: TokenBucketPolicy;
  private readonly perAccountPolicy: TokenBucketPolicy;
  private readonly listAccountsPolicy: TokenBucketPolicy;
  private readonly maxAccountBuckets: number;
  private readonly globalBucket: Bucket;
  private readonly listAccountsBucket: Bucket;
  private readonly accountBuckets = new Map<string, Bucket>();
  private lastObservedMs: number;
  private sequence = 0;

  constructor(options: InvocationRateLimiterOptions = {}) {
    this.clock = options.clock ?? (() => performance.now());
    this.globalPolicy = validatePolicy("Global", options.global ?? MCP_RATE_LIMITS.global);
    this.perAccountPolicy = validatePolicy("Per-account", options.perAccount ?? MCP_RATE_LIMITS.perAccount);
    this.listAccountsPolicy = validatePolicy(
      "list_accounts",
      options.listAccounts ?? MCP_RATE_LIMITS.listAccounts,
    );
    this.maxAccountBuckets = options.maxAccountBuckets ?? MCP_RATE_LIMITS.maxAccountBuckets;
    if (!Number.isSafeInteger(this.maxAccountBuckets) || this.maxAccountBuckets < 1) {
      throw new Error("The account rate-limit bucket bound must be a positive safe integer.");
    }

    this.lastObservedMs = this.readClock();
    this.globalBucket = this.newBucket(this.globalPolicy, this.lastObservedMs);
    this.listAccountsBucket = this.newBucket(this.listAccountsPolicy, this.lastObservedMs);
  }

  get accountBucketCount(): number {
    return this.accountBuckets.size;
  }

  consumeListAccounts(): void {
    const now = this.now();
    this.refill(this.listAccountsBucket, this.listAccountsPolicy, now);
    if (this.listAccountsBucket.tokens < ONE_TOKEN) {
      throw rateLimited(this.retryAfter(this.listAccountsBucket, this.listAccountsPolicy, ONE_TOKEN));
    }
    this.listAccountsBucket.tokens -= ONE_TOKEN;
    this.listAccountsBucket.lastUsed = ++this.sequence;
  }

  consumeAccounts(aliases: readonly string[]): void {
    if (aliases.length === 0) {
      throw new MultiAccountMcpError(
        "At least one explicit account alias is required for a data tool.",
        "ACCOUNT_SELECTION_REQUIRED",
      );
    }

    const keys = [...new Set(aliases.map(accountKey))];
    const now = this.now();
    this.refill(this.globalBucket, this.globalPolicy, now);

    const existing = new Map<string, Bucket>();
    for (const key of keys) {
      const bucket = this.accountBuckets.get(key);
      if (bucket) {
        this.refill(bucket, this.perAccountPolicy, now);
        existing.set(key, bucket);
      }
    }

    const newKeyCount = keys.length - existing.size;
    const evictionCount = Math.max(0, this.accountBuckets.size + newKeyCount - this.maxAccountBuckets);
    const requestedKeys = new Set(keys);
    const evictionCandidates = [...this.accountBuckets.entries()]
      .filter(([key]) => !requestedKeys.has(key))
      .map(([key, bucket]) => {
        this.refill(bucket, this.perAccountPolicy, now);
        return { key, bucket };
      })
      .sort((left, right) => left.bucket.lastUsed - right.bucket.lastUsed);

    if (evictionCount > evictionCandidates.length) {
      throw rateLimited(1);
    }

    let retryAfterSeconds = 0;
    if (this.globalBucket.tokens < ONE_TOKEN) {
      retryAfterSeconds = Math.max(
        retryAfterSeconds,
        this.retryAfter(this.globalBucket, this.globalPolicy, ONE_TOKEN),
      );
    }
    for (const bucket of existing.values()) {
      if (bucket.tokens < ONE_TOKEN) {
        retryAfterSeconds = Math.max(
          retryAfterSeconds,
          this.retryAfter(bucket, this.perAccountPolicy, ONE_TOKEN),
        );
      }
    }
    const readyEvictions = evictionCandidates.filter(
      ({ bucket }) => bucket.tokens >= this.perAccountPolicy.capacity,
    );
    if (readyEvictions.length < evictionCount) {
      const refillWaits = evictionCandidates
        .filter(({ bucket }) => bucket.tokens < this.perAccountPolicy.capacity)
        .map(({ bucket }) => this.retryAfter(bucket, this.perAccountPolicy, this.perAccountPolicy.capacity))
        .sort((left, right) => left - right);
      const neededRefills = evictionCount - readyEvictions.length;
      const waitForEnoughBuckets = refillWaits[neededRefills - 1];
      if (waitForEnoughBuckets === undefined) throw rateLimited(1);
      retryAfterSeconds = Math.max(retryAfterSeconds, waitForEnoughBuckets);
    }

    if (retryAfterSeconds > 0) throw rateLimited(retryAfterSeconds);

    for (let index = 0; index < evictionCount; index += 1) {
      const candidate = readyEvictions[index];
      if (!candidate || candidate.bucket.tokens < this.perAccountPolicy.capacity) {
        throw rateLimited(1);
      }
      this.accountBuckets.delete(candidate.key);
    }

    this.globalBucket.tokens -= ONE_TOKEN;
    this.globalBucket.lastUsed = ++this.sequence;
    for (const key of keys) {
      const bucket = existing.get(key) ?? this.newBucket(this.perAccountPolicy, now);
      bucket.tokens -= ONE_TOKEN;
      bucket.lastUsed = ++this.sequence;
      if (!existing.has(key)) this.accountBuckets.set(key, bucket);
    }
  }

  private readClock(): number {
    const value = this.clock();
    if (!Number.isFinite(value) || value < 0) {
      throw new MultiAccountMcpError(
        "The local MCP invocation rate limiter is unavailable.",
        "RATE_LIMITER_UNAVAILABLE",
      );
    }
    return value;
  }

  private now(): number {
    this.lastObservedMs = Math.max(this.lastObservedMs, this.readClock());
    return this.lastObservedMs;
  }

  private newBucket(policy: TokenBucketPolicy, now: number): Bucket {
    return { tokens: policy.capacity, updatedAtMs: now, lastUsed: ++this.sequence };
  }

  private refill(bucket: Bucket, policy: TokenBucketPolicy, now: number): void {
    const elapsedMs = Math.max(0, now - bucket.updatedAtMs);
    bucket.tokens = Math.min(
      policy.capacity,
      bucket.tokens + (elapsedMs / 1_000) * policy.refillPerSecond,
    );
    bucket.updatedAtMs = now;
  }

  private retryAfter(bucket: Bucket, policy: TokenBucketPolicy, targetTokens: number): number {
    return Math.max(0, targetTokens - bucket.tokens) / policy.refillPerSecond;
  }
}
