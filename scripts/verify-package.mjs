#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
} from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const TEMP_PREFIX = "multi-account-mcp-package-verify-";
const MAX_COMMAND_OUTPUT_BYTES = 2_000_000;
const COMMAND_TIMEOUT_MS = 5 * 60_000;

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NPM_COMMAND = process.platform === "win32" ? "npm.cmd" : "npm";
const EXPECTED_VERSION = "0.1.0-alpha.1";
const EXPECTED_REPOSITORY = "https://github.com/djehuty94/multi-account-mcp";

const ROOT_FILES = new Set([
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "LICENSE",
  "PRIVACY.md",
  "README.md",
  "SECURITY.md",
  "TERMS.md",
  "package.json",
]);

const DOC_FILES = new Set([
  "docs/ARCHITECTURE.md",
  "docs/GOOGLE_OAUTH_SETUP.md",
  "docs/LANDSCAPE.md",
]);

const RUNTIME_MODULES = new Set([
  "dist/src/auth/account-service",
  "dist/src/auth/google-oauth-client",
  "dist/src/auth/oauth",
  "dist/src/cli",
  "dist/src/constants",
  "dist/src/errors",
  "dist/src/google/client",
  "dist/src/google/concurrency",
  "dist/src/google/drive",
  "dist/src/google/gmail",
  "dist/src/mcp/server",
  "dist/src/policy/content",
  "dist/src/policy/cursor",
  "dist/src/policy/input",
  "dist/src/policy/rate-limiter",
  "dist/src/storage/keyring-vault",
  "dist/src/storage/metadata-store",
  "dist/src/types",
]);

const REQUIRED_FILES = new Set([
  ...ROOT_FILES,
  ...DOC_FILES,
  ...[...RUNTIME_MODULES].map((modulePath) => `${modulePath}.js`),
]);

const EXPECTED_TOOLS = [
  "get_drive_file_metadata",
  "list_accounts",
  "read_drive_text",
  "search_drive",
];

function isAllowedPackageFile(path) {
  if (ROOT_FILES.has(path) || DOC_FILES.has(path)) return true;
  for (const modulePath of RUNTIME_MODULES) {
    if (
      path === `${modulePath}.js` ||
      path === `${modulePath}.js.map` ||
      path === `${modulePath}.d.ts`
    ) {
      return true;
    }
  }
  return false;
}

function assertInsideRoot(root, target, { allowRoot = false } = {}) {
  const resolvedRoot = resolve(root);
  const resolvedTarget = resolve(target);
  const pathFromRoot = relative(resolvedRoot, resolvedTarget);
  const outside = pathFromRoot === ".." || pathFromRoot.startsWith(`..${sep}`) || isAbsolute(pathFromRoot);
  if (outside || (!allowRoot && pathFromRoot === "")) {
    throw new Error(`Refusing filesystem operation outside the exact temporary root: ${resolvedTarget}`);
  }
  return resolvedTarget;
}

async function removeExactTempRoot(root) {
  const resolvedRoot = resolve(root);
  const resolvedTmp = resolve(tmpdir());
  if (dirname(resolvedRoot) !== resolvedTmp || !basename(resolvedRoot).startsWith(TEMP_PREFIX)) {
    throw new Error(`Refusing cleanup of an unrecognized temporary root: ${resolvedRoot}`);
  }
  assertInsideRoot(resolvedRoot, resolvedRoot, { allowRoot: true });
  await rm(resolvedRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
}

function appendBounded(chunks, chunk, state, child) {
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  state.bytes += buffer.length;
  if (state.bytes > MAX_COMMAND_OUTPUT_BYTES) {
    child.kill();
    return;
  }
  chunks.push(buffer);
}

function runCommand(command, args, options) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    const stdoutState = { bytes: 0 };
    const stderrState = { bytes: 0 };
    let timedOut = false;

    child.stdout.on("data", (chunk) => appendBounded(stdoutChunks, chunk, stdoutState, child));
    child.stderr.on("data", (chunk) => appendBounded(stderrChunks, chunk, stderrState, child));

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, options.timeoutMs ?? COMMAND_TIMEOUT_MS);
    timer.unref();

    child.once("error", (error) => {
      clearTimeout(timer);
      rejectRun(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8");
      if (timedOut) {
        rejectRun(new Error(`${command} timed out after ${options.timeoutMs ?? COMMAND_TIMEOUT_MS} ms.`));
        return;
      }
      if (stdoutState.bytes > MAX_COMMAND_OUTPUT_BYTES || stderrState.bytes > MAX_COMMAND_OUTPUT_BYTES) {
        rejectRun(new Error(`${command} exceeded the bounded output limit.`));
        return;
      }
      if (code !== 0) {
        rejectRun(new Error(
          `${command} exited with ${code ?? `signal ${signal ?? "unknown"}`}.\n${stderr.trim()}`,
        ));
        return;
      }
      resolveRun({ stdout, stderr });
    });
  });
}

function readNullTerminated(buffer) {
  const end = buffer.indexOf(0);
  return buffer.subarray(0, end === -1 ? buffer.length : end).toString("utf8");
}

function parseTarOctal(buffer, label) {
  if ((buffer[0] ?? 0) & 0x80) {
    throw new Error(`Unsupported base-256 tar ${label}.`);
  }
  const text = readNullTerminated(buffer).trim();
  if (!/^[0-7]+$/.test(text)) throw new Error(`Invalid tar ${label}.`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Unsafe tar ${label}.`);
  return value;
}

function verifyTarChecksum(header) {
  const expected = parseTarOctal(header.subarray(148, 156), "checksum");
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (actual !== expected) throw new Error("Tar header checksum mismatch.");
}

function parsePaxRecords(buffer) {
  const records = new Map();
  let offset = 0;
  while (offset < buffer.length) {
    const space = buffer.indexOf(0x20, offset);
    if (space === -1) throw new Error("Malformed PAX record length.");
    const lengthText = buffer.subarray(offset, space).toString("ascii");
    if (!/^[1-9][0-9]*$/.test(lengthText)) throw new Error("Malformed PAX record length.");
    const length = Number.parseInt(lengthText, 10);
    const end = offset + length;
    if (!Number.isSafeInteger(length) || end > buffer.length || buffer[end - 1] !== 0x0a) {
      throw new Error("Malformed PAX record boundary.");
    }
    const record = buffer.subarray(space + 1, end - 1).toString("utf8");
    const equals = record.indexOf("=");
    if (equals <= 0) throw new Error("Malformed PAX record.");
    records.set(record.slice(0, equals), record.slice(equals + 1));
    offset = end;
  }
  return records;
}

function normalizeArchivePath(archivePath) {
  if (!archivePath.startsWith("package/") || archivePath.includes("\\") || archivePath.includes("\0")) {
    throw new Error(`Unsafe or unexpected tar path: ${JSON.stringify(archivePath)}`);
  }
  const packagePath = archivePath.slice("package/".length).replace(/\/$/, "");
  if (
    !packagePath ||
    packagePath.startsWith("/") ||
    posix.normalize(packagePath) !== packagePath ||
    packagePath.split("/").includes("..")
  ) {
    throw new Error(`Unsafe package path: ${JSON.stringify(packagePath)}`);
  }
  return packagePath;
}

async function listActualTarballFiles(tarballPath) {
  const compressed = await readFile(tarballPath);
  const archive = gunzipSync(compressed, { maxOutputLength: 20_000_000 });
  const files = [];
  let offset = 0;
  let pendingLongPath;
  let pendingPaxPath;
  let sawEndMarker = false;

  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      sawEndMarker = true;
      break;
    }
    verifyTarChecksum(header);

    const size = parseTarOctal(header.subarray(124, 136), "entry size");
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > archive.length) throw new Error("Tar entry exceeds the archive boundary.");
    const data = archive.subarray(dataStart, dataEnd);
    const type = String.fromCharCode(header[156] ?? 0);
    const shortName = readNullTerminated(header.subarray(0, 100));
    const prefix = readNullTerminated(header.subarray(345, 500));
    const headerPath = prefix ? `${prefix}/${shortName}` : shortName;

    if (type === "L") {
      pendingLongPath = readNullTerminated(data);
    } else if (type === "x") {
      pendingPaxPath = parsePaxRecords(data).get("path");
    } else if (type === "g") {
      const globalRecords = parsePaxRecords(data);
      if (globalRecords.has("path")) throw new Error("Global PAX paths are not allowed.");
    } else if (type === "\0" || type === "0") {
      const archivePath = pendingPaxPath ?? pendingLongPath ?? headerPath;
      files.push(normalizeArchivePath(archivePath));
      pendingLongPath = undefined;
      pendingPaxPath = undefined;
    } else if (type === "5") {
      normalizeArchivePath(pendingPaxPath ?? pendingLongPath ?? headerPath);
      pendingLongPath = undefined;
      pendingPaxPath = undefined;
    } else {
      throw new Error(`Tar entry type ${JSON.stringify(type)} is not allowed.`);
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  if (!sawEndMarker) throw new Error("Tar archive has no end marker.");
  if (pendingLongPath || pendingPaxPath) throw new Error("Tar archive ended with unused path metadata.");
  if (files.length === 0) throw new Error("Tar archive contains no files.");
  if (new Set(files).size !== files.length) throw new Error("Tar archive contains duplicate file paths.");
  return files.sort();
}

function assertPackageContents(files) {
  const unexpected = files.filter((path) => !isAllowedPackageFile(path));
  if (unexpected.length > 0) {
    throw new Error(`Package contains files outside the allowlist:\n${unexpected.join("\n")}`);
  }

  const fileSet = new Set(files);
  const missing = [...REQUIRED_FILES].filter((path) => !fileSet.has(path)).sort();
  if (missing.length > 0) {
    throw new Error(`Package is missing required files:\n${missing.join("\n")}`);
  }

  const forbidden = files.filter((path) =>
    path.startsWith("src/") ||
    path.startsWith("test/") ||
    path.startsWith("dist/test/") ||
    /(^|\/)(?:\.env(?:\.|$)|credentials?|client[_-]?secrets?|tokens?)(?:\.|\/|$)/i.test(path)
  );
  if (forbidden.length > 0) {
    throw new Error(`Package contains explicitly forbidden files:\n${forbidden.join("\n")}`);
  }
}

function parsePackResult(stdout, packDirectory) {
  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("npm pack did not return valid JSON.");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || typeof parsed[0]?.filename !== "string") {
    throw new Error("npm pack returned an unexpected result shape.");
  }
  const tarballPath = assertInsideRoot(packDirectory, join(packDirectory, parsed[0].filename));
  return tarballPath;
}

function cleanChildEnvironment(extra) {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter((entry) => entry[1] !== undefined),
  );
  delete environment.MULTI_ACCOUNT_MCP_ALLOWED_ACCOUNTS;
  return { ...environment, ...extra };
}

async function verifyInstalledMcp(installDirectory, stateDirectory) {
  const packageDirectory = assertInsideRoot(
    installDirectory,
    join(installDirectory, "node_modules", "multi-account-mcp"),
  );
  const manifestPath = assertInsideRoot(installDirectory, join(packageDirectory, "package.json"));
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  assert.equal(manifest.name, "multi-account-mcp");
  assert.equal(manifest.version, EXPECTED_VERSION);
  assert.equal(manifest.private, true, "The alpha package must remain non-publishable on npm.");
  assert.equal(manifest.repository?.type, "git");
  assert.equal(manifest.repository?.url, EXPECTED_REPOSITORY);
  assert.equal(manifest.bin?.["multi-account-mcp"], "./dist/src/cli.js");

  const pluginManifestPath = assertInsideRoot(
    packageDirectory,
    join(packageDirectory, ".codex-plugin", "plugin.json"),
  );
  const pluginManifest = JSON.parse(await readFile(pluginManifestPath, "utf8"));
  assert.equal(pluginManifest.name, manifest.name);
  assert.equal(pluginManifest.version, manifest.version);
  assert.equal(pluginManifest.repository, EXPECTED_REPOSITORY);
  assert.equal(pluginManifest.license, manifest.license);
  assert.equal(pluginManifest.mcpServers, "./.mcp.json");
  assert.deepEqual(pluginManifest.interface?.capabilities, ["Read"]);
  assert.equal(typeof pluginManifest.interface?.privacyPolicyURL, "string");
  assert.equal(typeof pluginManifest.interface?.termsOfServiceURL, "string");

  const mcpManifestPath = assertInsideRoot(packageDirectory, join(packageDirectory, ".mcp.json"));
  const mcpManifest = JSON.parse(await readFile(mcpManifestPath, "utf8"));
  const packagedServer = mcpManifest.mcpServers?.["multi-account-mcp"];
  assert.equal(packagedServer?.command, "node");
  assert.deepEqual(packagedServer?.args, ["./dist/src/cli.js", "mcp"]);

  const cliPath = assertInsideRoot(packageDirectory, join(packageDirectory, manifest.bin["multi-account-mcp"]));
  const cliStats = await lstat(cliPath);
  assert.equal(cliStats.isFile(), true, "Installed CLI entrypoint must be a regular file.");

  const client = new Client({ name: "multi-account-mcp-package-verifier", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cliPath, "mcp", "--services", "drive"],
    env: cleanChildEnvironment({ MULTI_ACCOUNT_MCP_HOME: stateDirectory }),
    stderr: "pipe",
  });
  let primaryError;
  try {
    await client.connect(transport);
    const listed = await client.listTools();
    const names = listed.tools.map((tool) => tool.name).sort();
    assert.deepEqual(names, EXPECTED_TOOLS);
    for (const tool of listed.tools) {
      assert.equal(tool.annotations?.readOnlyHint, true, `${tool.name} must be annotated read-only.`);
      assert.equal(tool.annotations?.destructiveHint, false, `${tool.name} must be non-destructive.`);
    }
  } catch (error) {
    primaryError = error;
  } finally {
    let clientClosed = false;
    try {
      await client.close();
      clientClosed = true;
    } catch (error) {
      if (!primaryError) primaryError = error;
    }
    if (!clientClosed) {
      try {
        await transport.close();
      } catch (error) {
        if (!primaryError) primaryError = error;
      }
    }
  }
  if (primaryError) throw primaryError;
}

async function main() {
  const tempRoot = await mkdtemp(join(tmpdir(), TEMP_PREFIX));
  let primaryError;

  try {
    const packDirectory = assertInsideRoot(tempRoot, join(tempRoot, "pack"));
    const installDirectory = assertInsideRoot(tempRoot, join(tempRoot, "install"));
    const stateDirectory = assertInsideRoot(tempRoot, join(tempRoot, "state"));
    const npmCacheDirectory = assertInsideRoot(tempRoot, join(tempRoot, "npm-cache"));
    await mkdir(packDirectory);
    await mkdir(installDirectory);
    await mkdir(stateDirectory);
    await mkdir(npmCacheDirectory);
    assert.deepEqual(await readdir(installDirectory), [], "Install directory must start empty.");
    const npmEnvironment = cleanChildEnvironment({ NPM_CONFIG_CACHE: npmCacheDirectory });

    const packed = await runCommand(
      NPM_COMMAND,
      ["pack", "--json", "--ignore-scripts", "--pack-destination", packDirectory],
      { cwd: PROJECT_ROOT, env: npmEnvironment },
    );
    const tarballPath = parsePackResult(packed.stdout, packDirectory);
    const tarballStats = await lstat(tarballPath);
    assert.equal(tarballStats.isFile(), true, "npm pack output must be a regular tarball file.");

    const packageFiles = await listActualTarballFiles(tarballPath);
    assertPackageContents(packageFiles);

    await runCommand(
      NPM_COMMAND,
      [
        "install",
        "--ignore-scripts",
        "--no-fund",
        "--no-audit",
        "--package-lock=false",
        tarballPath,
      ],
      { cwd: installDirectory, env: npmEnvironment },
    );

    await verifyInstalledMcp(installDirectory, stateDirectory);
    console.log(`Verified ${packageFiles.length} packaged files and the exact four-tool Drive-only MCP surface.`);
  } catch (error) {
    primaryError = error;
  } finally {
    try {
      await removeExactTempRoot(tempRoot);
    } catch (cleanupError) {
      if (!primaryError) primaryError = cleanupError;
      else console.error(`Cleanup also failed: ${cleanupError instanceof Error ? cleanupError.message : cleanupError}`);
    }
  }

  if (primaryError) throw primaryError;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : error);
  process.exitCode = 1;
});
