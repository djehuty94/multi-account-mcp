import assert from "node:assert/strict";
import test from "node:test";
import { MultiAccountMcpError } from "../src/errors.js";
import {
  InvocationRateLimiter,
  type InvocationRateLimiterOptions,
} from "../src/policy/rate-limiter.js";

function limiter(options: InvocationRateLimiterOptions = {}) {
  return new InvocationRateLimiter({
    global: { capacity: 100, refillPerSecond: 100 },
    perAccount: { capacity: 10, refillPerSecond: 10 },
    listAccounts: { capacity: 10, refillPerSecond: 10 },
    ...options,
  });
}

function assertRateLimited(operation: () => void, expectedRetryAfter?: number): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof MultiAccountMcpError);
    assert.equal(error.code, "MCP_RATE_LIMITED");
    assert.equal(typeof error.safeDetails?.retryAfterSeconds, "number");
    if (expectedRetryAfter !== undefined) {
      assert.equal(error.safeDetails?.retryAfterSeconds, expectedRetryAfter);
    }
    assert.match(error.message, /^MCP invocation rate limit exceeded\. Retry after \d+ seconds\.$/);
    return true;
  });
}

test("per-account buckets enforce burst limits and return a safe typed retry interval", () => {
  let now = 0;
  const rateLimiter = limiter({
    clock: () => now,
    perAccount: { capacity: 2, refillPerSecond: 0.1 },
  });

  rateLimiter.consumeAccounts(["private-alias"]);
  rateLimiter.consumeAccounts(["private-alias"]);
  assertRateLimited(() => rateLimiter.consumeAccounts(["private-alias"]), 10);

  try {
    rateLimiter.consumeAccounts(["private-alias"]);
  } catch (error) {
    assert.ok(error instanceof MultiAccountMcpError);
    assert.doesNotMatch(error.message, /private-alias/);
  }
  now += 10_000;
  rateLimiter.consumeAccounts(["private-alias"]);
});

test("refill uses an injected monotonic clock and ignores backward movement", () => {
  let now = 1_000;
  const rateLimiter = limiter({
    clock: () => now,
    perAccount: { capacity: 1, refillPerSecond: 1 },
  });

  rateLimiter.consumeAccounts(["alpha"]);
  now = 500;
  assertRateLimited(() => rateLimiter.consumeAccounts(["alpha"]), 1);
  now = 2_000;
  rateLimiter.consumeAccounts(["alpha"]);
});

test("distinct aliases receive distinct budgets", () => {
  const rateLimiter = limiter({
    clock: () => 0,
    perAccount: { capacity: 1, refillPerSecond: 0.01 },
  });

  rateLimiter.consumeAccounts(["alpha"]);
  rateLimiter.consumeAccounts(["bravo"]);
  assertRateLimited(() => rateLimiter.consumeAccounts(["alpha"]), 100);
});

test("a multi-alias invocation charges every unique alias once", () => {
  const rateLimiter = limiter({
    clock: () => 0,
    perAccount: { capacity: 1, refillPerSecond: 0.01 },
  });

  rateLimiter.consumeAccounts(["alpha", "bravo", "alpha"]);
  assertRateLimited(() => rateLimiter.consumeAccounts(["alpha"]), 100);
  assertRateLimited(() => rateLimiter.consumeAccounts(["bravo"]), 100);
});

test("the global budget applies across distinct aliases", () => {
  let now = 0;
  const rateLimiter = limiter({
    clock: () => now,
    global: { capacity: 2, refillPerSecond: 0.1 },
  });

  rateLimiter.consumeAccounts(["alpha"]);
  rateLimiter.consumeAccounts(["bravo"]);
  assertRateLimited(() => rateLimiter.consumeAccounts(["charlie"]), 10);
  now += 10_000;
  rateLimiter.consumeAccounts(["charlie"]);
});

test("account bucket storage is bounded and only fully-refilled debt is evicted", () => {
  let now = 0;
  const rateLimiter = limiter({
    clock: () => now,
    perAccount: { capacity: 1, refillPerSecond: 1 },
    maxAccountBuckets: 2,
  });

  rateLimiter.consumeAccounts(["alpha"]);
  rateLimiter.consumeAccounts(["bravo"]);
  assert.equal(rateLimiter.accountBucketCount, 2);
  assertRateLimited(() => rateLimiter.consumeAccounts(["charlie"]), 1);
  assert.equal(rateLimiter.accountBucketCount, 2);

  now += 1_000;
  rateLimiter.consumeAccounts(["charlie"]);
  assert.equal(rateLimiter.accountBucketCount, 2);
  rateLimiter.consumeAccounts(["alpha"]);
  assert.equal(rateLimiter.accountBucketCount, 2);
});

test("list_accounts has a separate conservative budget", () => {
  const rateLimiter = limiter({
    clock: () => 0,
    global: { capacity: 1, refillPerSecond: 0.01 },
    perAccount: { capacity: 1, refillPerSecond: 0.01 },
    listAccounts: { capacity: 1, refillPerSecond: 0.01 },
  });

  rateLimiter.consumeListAccounts();
  assertRateLimited(() => rateLimiter.consumeListAccounts(), 100);
  rateLimiter.consumeAccounts(["alpha"]);
});

test("an invalid clock fails closed without exposing inputs", () => {
  assert.throws(
    () => limiter({ clock: () => Number.NaN }),
    (error: unknown) => {
      assert.ok(error instanceof MultiAccountMcpError);
      assert.equal(error.code, "RATE_LIMITER_UNAVAILABLE");
      assert.equal(error.message, "The local MCP invocation rate limiter is unavailable.");
      return true;
    },
  );
});

test("aliases are validated before hashing or bucket allocation", () => {
  const rateLimiter = limiter({ clock: () => 0 });
  const oversizedAlias = `a${"x".repeat(1_000_000)}`;

  assert.throws(
    () => rateLimiter.consumeAccounts([oversizedAlias]),
    (error: unknown) => {
      assert.ok(error instanceof MultiAccountMcpError);
      assert.equal(error.code, "INVALID_ALIAS");
      assert.doesNotMatch(error.message, /x{40}/);
      return true;
    },
  );
  assert.equal(rateLimiter.accountBucketCount, 0);
});
