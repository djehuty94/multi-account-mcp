import assert from "node:assert/strict";
import test from "node:test";
import { PageCursorCodec } from "../src/policy/cursor.js";
import type { AccountMetadata } from "../src/types.js";

const account: AccountMetadata = {
  id: "11111111-1111-4111-8111-111111111111",
  alias: "work",
  googleSub: "stable-google-sub",
  email: "person@company.example",
  scopes: ["scope"],
  createdAt: "2026-08-31T00:00:00.000Z",
  updatedAt: "2026-08-31T00:00:00.000Z",
};

test("pagination cursors are bound to provider, account, and query", () => {
  const codec = new PageCursorCodec();
  const cursor = codec.issue("gmail", account, "from:example.com", "google-page-token");
  assert.equal(codec.consume("gmail", account, "from:example.com", cursor), "google-page-token");
  assert.throws(() => codec.consume("drive", account, "from:example.com", cursor), /invalid, expired/);
  assert.throws(() => codec.consume("gmail", account, "subject:different", cursor), /invalid, expired/);
  const tampered = `${cursor.slice(0, -1)}${cursor.endsWith("a") ? "b" : "a"}`;
  assert.throws(() => codec.consume("gmail", account, "from:example.com", tampered), /invalid, expired/);
});
