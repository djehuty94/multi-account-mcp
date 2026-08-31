import { LIMITS } from "../constants.js";
import { MultiAccountMcpError } from "../errors.js";
import { boundText } from "../policy/content.js";
import { clampInteger, escapeGoogleQueryLiteral } from "../policy/input.js";
import type { GoogleAccountClient } from "./client.js";

const DRIVE_FILES = "https://www.googleapis.com/drive/v3/files";
const FILE_FIELDS = [
  "id",
  "name",
  "mimeType",
  "modifiedTime",
  "createdTime",
  "size",
  "webViewLink",
  "driveId",
  "parents",
  "owners(displayName,emailAddress)",
  "shortcutDetails(targetId,targetMimeType)",
].join(",");

interface DriveFile {
  id?: string;
  name?: string;
  mimeType?: string;
  modifiedTime?: string;
  createdTime?: string;
  size?: string;
  webViewLink?: string;
  driveId?: string;
  parents?: string[];
  owners?: Array<{ displayName?: string; emailAddress?: string }>;
  shortcutDetails?: { targetId?: string; targetMimeType?: string };
}

function withAccount(client: GoogleAccountClient, file: DriveFile) {
  const parsedSize = file.size ? Number(file.size) : Number.NaN;
  return {
    accountId: client.account.id,
    accountAlias: client.account.alias,
    accountEmail: client.account.email,
    id: boundText(file.id ?? "", 512).text,
    name: boundText(file.name ?? "", 2_000).text,
    mimeType: boundText(file.mimeType ?? "", 255).text,
    modifiedTime: file.modifiedTime ?? null,
    createdTime: file.createdTime ?? null,
    size: Number.isSafeInteger(parsedSize) && parsedSize >= 0 ? parsedSize : null,
    webViewLink: file.webViewLink ? boundText(file.webViewLink, 2_048).text : null,
    driveId: file.driveId ? boundText(file.driveId, 512).text : null,
    parents: (file.parents ?? []).slice(0, 100).map((parent) => boundText(parent, 512).text),
    owners: (file.owners ?? []).slice(0, 20).map((owner) => ({
      displayName: owner.displayName ? boundText(owner.displayName, 1_000).text : undefined,
      emailAddress: owner.emailAddress ? boundText(owner.emailAddress, 320).text : undefined,
    })),
    shortcutDetails: file.shortcutDetails
      ? {
          targetId: file.shortcutDetails.targetId
            ? boundText(file.shortcutDetails.targetId, 512).text
            : undefined,
          targetMimeType: file.shortcutDetails.targetMimeType
            ? boundText(file.shortcutDetails.targetMimeType, 255).text
            : undefined,
        }
      : null,
  };
}

export async function searchDrive(
  client: GoogleAccountClient,
  query: string,
  maxResults: number,
  pageToken?: string,
) {
  const limit = clampInteger(maxResults, 1, LIMITS.maxDriveResultsPerAccount);
  const normalized = query.trim();
  const escaped = escapeGoogleQueryLiteral(normalized);
  const q = normalized
    ? `trashed = false and (name contains '${escaped}' or fullText contains '${escaped}')`
    : "trashed = false";
  const result = await client.json<{ files?: DriveFile[]; nextPageToken?: string; incompleteSearch?: boolean }>({
    url: DRIVE_FILES,
    params: {
      q,
      pageSize: limit,
      fields: `nextPageToken,incompleteSearch,files(${FILE_FIELDS})`,
      orderBy: "modifiedTime desc",
      spaces: "drive",
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
      ...(pageToken ? { pageToken } : {}),
    },
  });
  return {
    accountId: client.account.id,
    accountAlias: client.account.alias,
    accountEmail: client.account.email,
    nextPageToken: result.nextPageToken ?? null,
    incompleteSearch: result.incompleteSearch ?? false,
    files: (result.files ?? []).slice(0, limit).map((file) => withAccount(client, file)),
  };
}

export async function getDriveMetadata(client: GoogleAccountClient, fileId: string) {
  if (!fileId) throw new MultiAccountMcpError("file_id is required.", "INVALID_FILE_ID");
  const file = await client.json<DriveFile>({
    url: `${DRIVE_FILES}/${encodeURIComponent(fileId)}`,
    params: { fields: FILE_FIELDS, supportsAllDrives: true },
  });
  return withAccount(client, file);
}

function exportMimeType(mimeType: string): string | null {
  if (mimeType === "application/vnd.google-apps.document") return "text/plain";
  if (mimeType === "application/vnd.google-apps.spreadsheet") return "text/csv";
  if (mimeType === "application/vnd.google-apps.presentation") return "text/plain";
  return null;
}

function isStoredText(mimeType: string): boolean {
  return mimeType.startsWith("text/") ||
    /^(application\/(json|xml|csv|javascript|x-javascript|yaml|x-yaml))$/i.test(mimeType);
}

export async function readDriveText(
  client: GoogleAccountClient,
  fileId: string,
  maxChars: number,
) {
  const limit = clampInteger(maxChars, 1, LIMITS.maxBodyChars);
  const metadata = await getDriveMetadata(client, fileId);
  const exportAs = exportMimeType(metadata.mimeType);
  if (!exportAs && !isStoredText(metadata.mimeType)) {
    throw new MultiAccountMcpError(
      "This file is not a supported text type. Multi-Account MCP reads text files and native Docs, Sheets, and Slides only.",
      "UNSUPPORTED_DRIVE_CONTENT",
    );
  }

  const response = exportAs
    ? await client.text({
        url: `${DRIVE_FILES}/${encodeURIComponent(fileId)}/export`,
        params: { mimeType: exportAs },
      })
    : await client.text({
        url: `${DRIVE_FILES}/${encodeURIComponent(fileId)}`,
        params: { alt: "media", supportsAllDrives: true },
      });
  const bounded = boundText(response.text, limit);
  return {
    ...metadata,
    content: bounded.text,
    contentTruncated: bounded.truncated || response.truncated,
    contentType: response.contentType ?? exportAs ?? metadata.mimeType,
    charsetFallback: response.charsetFallback,
    firstSheetOnly: metadata.mimeType === "application/vnd.google-apps.spreadsheet",
  };
}
