import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

function cleanEnvironment(extra: Record<string, string>): NodeJS.ProcessEnv {
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined),
    ),
    ...extra,
  };
}

async function expectCliFailure(
  args: string[],
  environment: NodeJS.ProcessEnv,
  expected: RegExp,
): Promise<void> {
  await assert.rejects(
    execFileAsync(process.execPath, ["--import", "tsx", resolve("src/cli.ts"), ...args], {
      env: environment,
    }),
    (error: unknown) => {
      const stderr = (error as { stderr?: string }).stderr ?? "";
      assert.match(stderr, expected);
      return true;
    },
  );
}

test("auth add rejects non-interactive input and has no --yes bypass", async () => {
  const directory = await mkdtemp(join(tmpdir(), "multi-account-mcp-cli-confirm-"));
  const environment = cleanEnvironment({ MULTI_ACCOUNT_MCP_HOME: directory });
  try {
    await expectCliFailure(
      ["auth", "add", "personal"],
      environment,
      /INTERACTIVE_TTY_REQUIRED/,
    );
    await expectCliFailure(
      ["auth", "add", "personal", "--yes"],
      environment,
      /INVALID_ARGUMENT: Unexpected argument: --yes/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
