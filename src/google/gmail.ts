import sanitizeHtml from "sanitize-html";
import { decodeHTML } from "entities";
import { StringDecoder } from "node:string_decoder";
import { LIMITS } from "../constants.js";
import { MultiAccountMcpError } from "../errors.js";
import { boundText } from "../policy/content.js";
import { clampInteger } from "../policy/input.js";
import { mapWithConcurrency } from "./concurrency.js";
import type { GoogleAccountClient } from "./client.js";

const GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users/me";
const SEARCH_HEADERS = ["From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID"];

interface GmailHeader {
  name?: string;
  value?: string;
}

interface GmailPart {
  mimeType?: string;
  filename?: string;
  headers?: GmailHeader[];
  body?: { data?: string; size?: number; attachmentId?: string };
  parts?: GmailPart[];
}

interface GmailMessageApi {
  id?: string;
  threadId?: string;
  labelIds?: string[];
  snippet?: string;
  internalDate?: string;
  payload?: GmailPart;
  sizeEstimate?: number;
}

interface GmailThreadApi {
  id?: string;
  historyId?: string;
  messages?: GmailMessageApi[];
}

function headerValue(headers: GmailHeader[] | undefined, name: string): string {
  return headers?.find((header) => header.name?.toLowerCase() === name.toLowerCase())?.value ?? "";
}

function isAttachmentPart(part: GmailPart): boolean {
  const disposition = headerValue(part.headers, "Content-Disposition").trim().toLowerCase();
  return Boolean(part.filename) || disposition.startsWith("attachment");
}

function walkMimeParts(root: GmailPart | undefined): {
  parts: Array<{ part: GmailPart; attachmentBranch: boolean }>;
  truncated: boolean;
} {
  if (!root) return { parts: [], truncated: false };
  const queue: Array<{ part: GmailPart; depth: number; attachmentBranch: boolean }> = [{
    part: root,
    depth: 0,
    attachmentBranch: isAttachmentPart(root),
  }];
  const parts: Array<{ part: GmailPart; attachmentBranch: boolean }> = [];
  let truncated = false;
  while (queue.length > 0 && parts.length < LIMITS.maxMimeParts) {
    const current = queue.shift();
    if (!current) break;
    parts.push({ part: current.part, attachmentBranch: current.attachmentBranch });
    if (current.depth >= LIMITS.maxMimeDepth) {
      if ((current.part.parts?.length ?? 0) > 0) truncated = true;
      continue;
    }
    for (const child of current.part.parts ?? []) {
      queue.push({
        part: child,
        depth: current.depth + 1,
        attachmentBranch: current.attachmentBranch || isAttachmentPart(child),
      });
    }
  }
  if (queue.length > 0) truncated = true;
  return { parts, truncated };
}

function partCharset(part: GmailPart): string {
  const contentType = headerValue(part.headers, "Content-Type");
  const match = /charset\s*=\s*["']?([^;\s"']+)/i.exec(contentType);
  return (match?.[1] ?? "utf-8").toLowerCase();
}

function decodeBoundedBase64Url(
  value: string,
  maximumBytes: number,
  charset: string,
): { text: string; truncated: boolean; charsetFallback: boolean } {
  const maximumEncodedChars = Math.ceil(maximumBytes * 4 / 3) + 4;
  const encoded = value.slice(0, maximumEncodedChars);
  try {
    const decoded = Buffer.from(encoded, "base64url");
    const bounded = decoded.subarray(0, maximumBytes);
    const normalized = charset === "utf8" ? "utf-8" : charset === "latin1" ? "iso-8859-1" : charset;
    const supported = new Set(["utf-8", "us-ascii", "iso-8859-1", "windows-1252"]);
    const charsetFallback = !supported.has(normalized);
    const text = charsetFallback || normalized === "utf-8"
      ? new StringDecoder("utf8").write(bounded)
      : new TextDecoder(normalized).decode(bounded);
    return {
      text,
      truncated: value.length > maximumEncodedChars || decoded.length > maximumBytes,
      charsetFallback,
    };
  } catch {
    return { text: "", truncated: true, charsetFallback: true };
  }
}

function htmlToPlainText(html: string): string {
  const withBoundaries = html
    .replace(/<(br|hr)\b[^>]*>/gi, "\n")
    .replace(/<li\b[^>]*>/gi, "\n• ")
    .replace(/<\/(address|article|aside|blockquote|div|dl|fieldset|figcaption|figure|footer|form|h[1-6]|header|li|main|nav|ol|p|pre|section|table|tr|ul)>/gi, "\n");
  const stripped = sanitizeHtml(withBoundaries, {
    allowedTags: [],
    allowedAttributes: {},
  });
  return decodeHTML(stripped)
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

async function readBodyPart(
  client: GoogleAccountClient,
  messageId: string,
  part: GmailPart,
  maximumBytes: number,
): Promise<{
  text: string;
  truncated: boolean;
  externalized: boolean;
  unavailable: boolean;
  charsetFallback: boolean;
}> {
  if (part.filename || maximumBytes < 1) {
    return {
      text: "",
      truncated: maximumBytes < 1,
      externalized: false,
      unavailable: false,
      charsetFallback: false,
    };
  }
  if (part.body?.data) {
    const decoded = decodeBoundedBase64Url(part.body.data, maximumBytes, partCharset(part));
    return { ...decoded, externalized: false, unavailable: false };
  }
  if (part.body?.attachmentId) {
    if (part.body.attachmentId.length > 4_096) {
      return { text: "", truncated: true, externalized: true, unavailable: true, charsetFallback: false };
    }
    if ((part.body.size ?? 0) > Math.min(maximumBytes, LIMITS.maxDownloadedBytes)) {
      return { text: "", truncated: true, externalized: true, unavailable: true, charsetFallback: false };
    }
    const response = await client.json<{ data?: string; size?: number }>({
      url: `${GMAIL_BASE}/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(part.body.attachmentId)}`,
    });
    if (!response.data) {
      return { text: "", truncated: true, externalized: true, unavailable: true, charsetFallback: false };
    }
    const decoded = decodeBoundedBase64Url(response.data, maximumBytes, partCharset(part));
    return { ...decoded, externalized: true, unavailable: false };
  }
  return { text: "", truncated: false, externalized: false, unavailable: false, charsetFallback: false };
}

async function bodyText(
  client: GoogleAccountClient,
  messageId: string,
  payload: GmailPart | undefined,
  maxChars: number,
): Promise<{
  text: string;
  truncated: boolean;
  externalized: boolean;
  unavailable: boolean;
  mimeStructureTruncated: boolean;
  charsetFallback: boolean;
}> {
  const walked = walkMimeParts(payload);
  const plain = walked.parts
    .filter((entry) => !entry.attachmentBranch && entry.part.mimeType === "text/plain")
    .map((entry) => entry.part);
  const html = walked.parts
    .filter((entry) => !entry.attachmentBranch && entry.part.mimeType === "text/html")
    .map((entry) => entry.part);
  const selected = plain.length > 0 ? plain : html;
  const maximumDecodedBytes = Math.min(LIMITS.maxDownloadedBytes, Math.max(maxChars * 8, 8_192));
  let remaining = maximumDecodedBytes;
  let truncated = walked.truncated || selected.length > LIMITS.maxBodyParts;
  let externalized = false;
  let unavailable = false;
  let charsetFallback = false;
  const chunks: string[] = [];
  for (const part of selected.slice(0, LIMITS.maxBodyParts)) {
    const decoded = await readBodyPart(client, messageId, part, remaining);
    externalized ||= decoded.externalized;
    unavailable ||= decoded.unavailable;
    charsetFallback ||= decoded.charsetFallback;
    truncated ||= decoded.truncated;
    if (decoded.text) {
      chunks.push(decoded.text);
      remaining = Math.max(0, remaining - Buffer.byteLength(decoded.text, "utf8"));
    }
    if (remaining === 0) {
      truncated = true;
      break;
    }
  }
  const joined = chunks.join("\n\n");
  const normalized = plain.length > 0
    ? joined
    : htmlToPlainText(joined);
  const bounded = boundText(normalized, maxChars);
  return {
    text: bounded.text,
    truncated: truncated || bounded.truncated,
    externalized,
    unavailable,
    mimeStructureTruncated: walked.truncated,
    charsetFallback,
  };
}

function attachments(part: GmailPart | undefined): { items: Array<{
  filename: string;
  mimeType: string;
  size: number;
  attachmentId?: string;
}>; truncated: boolean } {
  const walked = walkMimeParts(part);
  const found: Array<{
    filename: string;
    mimeType: string;
    size: number;
    attachmentId?: string;
  }> = [];
  for (const entry of walked.parts) {
    const mimePart = entry.part;
    if (!isAttachmentPart(mimePart)) continue;
    if (found.length >= LIMITS.maxAttachments) {
      return { items: found, truncated: true };
    }
    const rawSize = mimePart.body?.size;
    found.push({
      filename: boundText(mimePart.filename || "(unnamed attachment)", 1_000).text,
      mimeType: boundText(mimePart.mimeType ?? "application/octet-stream", 255).text,
      size: Number.isSafeInteger(rawSize) && (rawSize ?? -1) >= 0 ? rawSize as number : 0,
      ...(mimePart.body?.attachmentId
        ? { attachmentId: boundText(mimePart.body.attachmentId, 4_096).text }
        : {}),
    });
  }
  return { items: found, truncated: walked.truncated };
}

function summarizeMessage(client: GoogleAccountClient, message: GmailMessageApi) {
  const headers = message.payload?.headers;
  const internalDateNumber = Number(message.internalDate);
  const parsedInternalDate = new Date(internalDateNumber);
  const internalDate = Number.isFinite(internalDateNumber) &&
      internalDateNumber >= 0 &&
      Number.isFinite(parsedInternalDate.getTime())
    ? parsedInternalDate.toISOString()
    : null;
  return {
    accountId: client.account.id,
    accountAlias: client.account.alias,
    accountEmail: client.account.email,
    id: boundText(message.id ?? "", 256).text,
    threadId: boundText(message.threadId ?? "", 256).text,
    internalDate,
    from: boundText(headerValue(headers, "From"), 2_000).text,
    to: boundText(headerValue(headers, "To"), 2_000).text,
    subject: boundText(headerValue(headers, "Subject"), 2_000).text,
    date: boundText(headerValue(headers, "Date"), 1_000).text,
    snippet: boundText(message.snippet ?? "", 2_000).text,
    labels: (message.labelIds ?? []).slice(0, 100).map((label) => boundText(label, 255).text),
  };
}

async function getApiMessage(
  client: GoogleAccountClient,
  messageId: string,
  format: "metadata" | "full",
): Promise<GmailMessageApi> {
  if (!messageId) throw new MultiAccountMcpError("message_id is required.", "INVALID_MESSAGE_ID");
  const url = new URL(`${GMAIL_BASE}/messages/${encodeURIComponent(messageId)}`);
  url.searchParams.set("format", format);
  if (format === "metadata") {
    for (const header of SEARCH_HEADERS) url.searchParams.append("metadataHeaders", header);
  }
  return client.json<GmailMessageApi>({
    url: url.toString(),
  });
}

export async function searchGmail(
  client: GoogleAccountClient,
  query: string,
  maxResults: number,
  pageToken?: string,
) {
  const limit = clampInteger(maxResults, 1, LIMITS.maxGmailResultsPerAccount);
  const list = await client.json<{
    messages?: Array<{ id?: string; threadId?: string }>;
    nextPageToken?: string;
    resultSizeEstimate?: number;
  }>({
    url: `${GMAIL_BASE}/messages`,
    params: { q: query, maxResults: limit, ...(pageToken ? { pageToken } : {}) },
  });
  const ids = (list.messages ?? [])
    .slice(0, limit)
    .flatMap((message) => (message.id ? [message.id] : []));
  const messages = await mapWithConcurrency(ids, 5, (id) => getApiMessage(client, id, "metadata"));
  return {
    accountId: client.account.id,
    accountAlias: client.account.alias,
    accountEmail: client.account.email,
    resultSizeEstimate: list.resultSizeEstimate ?? messages.length,
    nextPageToken: list.nextPageToken ?? null,
    messages: messages.map((message) => summarizeMessage(client, message)),
  };
}

export async function getGmailMessage(
  client: GoogleAccountClient,
  messageId: string,
  maxChars: number,
) {
  const limit = clampInteger(maxChars, 1, LIMITS.maxBodyChars);
  const message = await getApiMessage(client, messageId, "full");
  const body = await bodyText(client, message.id ?? messageId, message.payload, limit);
  const attachmentResult = attachments(message.payload);
  return {
    ...summarizeMessage(client, message),
    messageIdHeader: boundText(headerValue(message.payload?.headers, "Message-ID"), 2_000).text,
    cc: boundText(headerValue(message.payload?.headers, "Cc"), 2_000).text,
    bcc: boundText(headerValue(message.payload?.headers, "Bcc"), 2_000).text,
    body: body.text,
    bodyTruncated: body.truncated,
    bodyExternalized: body.externalized,
    bodyUnavailable: body.unavailable,
    charsetFallback: body.charsetFallback,
    mimeStructureTruncated: body.mimeStructureTruncated,
    sizeEstimate: message.sizeEstimate ?? null,
    attachments: attachmentResult.items,
    attachmentsTruncated: attachmentResult.truncated,
  };
}

export async function getGmailThread(
  client: GoogleAccountClient,
  threadId: string,
  maxCharsPerMessage: number,
) {
  if (!threadId) throw new MultiAccountMcpError("thread_id is required.", "INVALID_THREAD_ID");
  const limit = clampInteger(maxCharsPerMessage, 1, LIMITS.maxBodyChars);
  const url = new URL(`${GMAIL_BASE}/threads/${encodeURIComponent(threadId)}`);
  url.searchParams.set("format", "metadata");
  for (const header of SEARCH_HEADERS) url.searchParams.append("metadataHeaders", header);
  const thread = await client.json<GmailThreadApi>({ url: url.toString() });
  const messageRefs = (thread.messages ?? []).slice(0, LIMITS.maxThreadMessages);
  const fullMessages: Array<Record<string, unknown>> = [];
  let remainingChars = LIMITS.maxThreadBodyChars;
  let remainingAttachments = LIMITS.maxThreadAttachments;
  let threadContentTruncated = false;
  for (const message of messageRefs) {
    if (!message.id) continue;
    if (remainingChars < 1 || remainingAttachments < 1) {
      threadContentTruncated = true;
      break;
    }
    const full = await getApiMessage(client, message.id, "full");
    const body = await bodyText(
      client,
      full.id ?? message.id,
      full.payload,
      Math.min(limit, remainingChars),
    );
    const attachmentResult = attachments(full.payload);
    const includedAttachments = attachmentResult.items.slice(0, remainingAttachments);
    const attachmentsTruncated = attachmentResult.truncated ||
      includedAttachments.length < attachmentResult.items.length;
    fullMessages.push({
      ...summarizeMessage(client, full),
      body: body.text,
      bodyTruncated: body.truncated,
      bodyExternalized: body.externalized,
      bodyUnavailable: body.unavailable,
      charsetFallback: body.charsetFallback,
      mimeStructureTruncated: body.mimeStructureTruncated,
      attachments: includedAttachments,
      attachmentsTruncated,
    });
    remainingChars -= body.text.length;
    remainingAttachments -= includedAttachments.length;
    threadContentTruncated ||= body.truncated || attachmentsTruncated;
  }
  return {
    accountId: client.account.id,
    accountAlias: client.account.alias,
    accountEmail: client.account.email,
    threadId: thread.id ?? threadId,
    messages: fullMessages,
    messagesTruncated: fullMessages.length < (thread.messages?.length ?? 0),
    threadContentTruncated,
  };
}
