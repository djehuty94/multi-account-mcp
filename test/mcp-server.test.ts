import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/mcp/server.js";
import { InvocationRateLimiter } from "../src/policy/rate-limiter.js";
import { AccountMetadataStore } from "../src/storage/metadata-store.js";

function cleanEnvironment(extra: Record<string, string>): Record<string, string> {
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
    ),
    ...extra,
  };
}

async function listToolsForServiceSurface(service: "drive" | "gmail"): Promise<string[]> {
  const directory = await mkdtemp(join(tmpdir(), `multi-account-mcp-${service}-surface-`));
  const client = new Client({ name: `multi-account-mcp-${service}-test`, version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      "--import",
      "tsx",
      resolve("src/cli.ts"),
      "mcp",
      "--services",
      service,
    ],
    env: cleanEnvironment({ MULTI_ACCOUNT_MCP_HOME: directory }),
    stderr: "pipe",
  });

  try {
    await client.connect(transport);
    return (await client.listTools()).tools.map((tool) => tool.name).sort();
  } finally {
    await client.close().catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
}

test("stdio MCP starts, advertises only read tools, and lists isolated metadata", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-test-"));
  const client = new Client({ name: "multi-account-mcp-test", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", resolve("src/cli.ts"), "mcp"],
    env: cleanEnvironment({ MULTI_ACCOUNT_MCP_HOME: directory }),
    stderr: "pipe",
  });

  try {
    await client.connect(transport);
    const listed = await client.listTools();
    assert.deepEqual(
      listed.tools.map((tool) => tool.name).sort(),
      [
        "get_drive_file_metadata",
        "get_gmail_message",
        "get_gmail_thread",
        "list_accounts",
        "read_drive_text",
        "search_drive",
        "search_gmail",
      ],
    );
    for (const tool of listed.tools) {
      assert.equal(tool.annotations?.readOnlyHint, true);
      assert.equal(tool.annotations?.destructiveHint, false);
    }

    const result = await client.callTool({ name: "list_accounts", arguments: {} });
    assert.deepEqual((result.structuredContent as { accounts: unknown[] }).accounts, []);
    assert.equal(
      (result.structuredContent as { security: { untrustedExternalContent: boolean } })
        .security.untrustedExternalContent,
      true,
    );
  } finally {
    await client.close().catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
});

test("drive-only MCP advertises list_accounts and only Drive tools", async () => {
  assert.deepEqual(await listToolsForServiceSurface("drive"), [
    "get_drive_file_metadata",
    "list_accounts",
    "read_drive_text",
    "search_drive",
  ]);
});

test("gmail-only MCP advertises list_accounts and only Gmail tools", async () => {
  assert.deepEqual(await listToolsForServiceSurface("gmail"), [
    "get_gmail_message",
    "get_gmail_thread",
    "list_accounts",
    "search_gmail",
  ]);
});

test("alternating Google services cannot bypass the shared alias limit", async () => {
  class CountingStore extends AccountMetadataStore {
    listCalls = 0;

    override async list() {
      this.listCalls += 1;
      return [];
    }
  }

  const store = new CountingStore(join(tmpdir(), "multi-account-mcp-unused-accounts.json"));
  const rateLimiter = new InvocationRateLimiter({
    clock: () => 0,
    global: { capacity: 100, refillPerSecond: 100 },
    perAccount: { capacity: 1, refillPerSecond: 0.01 },
    listAccounts: { capacity: 10, refillPerSecond: 10 },
    maxAccountBuckets: 10,
  });
  const server = createMcpServer({ store, rateLimiter, services: ["gmail", "drive"] });
  const client = new Client({ name: "multi-account-mcp-rate-limit-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const gmailResult = await client.callTool({
      name: "search_gmail",
      arguments: { accounts: ["not-connected"], query: "" },
    });
    assert.equal(gmailResult.isError, true);
    assert.match(JSON.stringify(gmailResult.content), /ACCOUNT_NOT_FOUND/);
    assert.equal(store.listCalls, 1);

    const driveResult = await client.callTool({
      name: "search_drive",
      arguments: { accounts: ["not-connected"], query: "" },
    });
    assert.equal(driveResult.isError, true);
    const driveError = JSON.stringify(driveResult.content);
    assert.match(driveError, /MCP_RATE_LIMITED/);
    assert.match(driveError, /Retry after 100 seconds/);
    assert.doesNotMatch(driveError, /not-connected/);
    assert.equal(store.listCalls, 1, "rate limiting must run before account resolution");
  } finally {
    await client.close().catch(() => undefined);
    await server.close().catch(() => undefined);
  }
});
