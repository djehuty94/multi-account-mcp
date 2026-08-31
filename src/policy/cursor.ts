import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { MultiAccountMcpError } from "../errors.js";
import type { AccountMetadata } from "../types.js";

type Provider = "gmail" | "drive";

interface CursorPayload {
  v: 1;
  provider: Provider;
  accountId: string;
  queryHash: string;
  pageToken: string;
  expiresAt: number;
}

function hashQuery(query: string): string {
  return createHash("sha256").update(query).digest("base64url");
}

function invalidCursor(): MultiAccountMcpError {
  return new MultiAccountMcpError(
    "The pagination cursor is invalid, expired, or belongs to another account/query. Start the search again.",
    "INVALID_PAGE_CURSOR",
  );
}

export class PageCursorCodec {
  private readonly key = randomBytes(32);

  issue(provider: Provider, account: AccountMetadata, query: string, pageToken: string): string {
    const payload: CursorPayload = {
      v: 1,
      provider,
      accountId: account.id,
      queryHash: hashQuery(query),
      pageToken,
      expiresAt: Date.now() + 60 * 60_000,
    };
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    const signature = createHmac("sha256", this.key).update(encoded).digest("base64url");
    return `${encoded}.${signature}`;
  }

  consume(provider: Provider, account: AccountMetadata, query: string, cursor: string): string {
    if (cursor.length > 12_000) throw invalidCursor();
    const [encoded, signature, extra] = cursor.split(".");
    if (!encoded || !signature || extra !== undefined) throw invalidCursor();
    const expected = createHmac("sha256", this.key).update(encoded).digest();
    let actual: Buffer;
    try {
      actual = Buffer.from(signature, "base64url");
    } catch {
      throw invalidCursor();
    }
    if (
      actual.toString("base64url") !== signature ||
      actual.length !== expected.length ||
      !timingSafeEqual(actual, expected)
    ) throw invalidCursor();

    let payload: CursorPayload;
    try {
      payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as CursorPayload;
    } catch {
      throw invalidCursor();
    }
    if (
      payload.v !== 1 ||
      payload.provider !== provider ||
      payload.accountId !== account.id ||
      payload.queryHash !== hashQuery(query) ||
      typeof payload.pageToken !== "string" ||
      payload.pageToken.length < 1 ||
      payload.pageToken.length > 4_096 ||
      typeof payload.expiresAt !== "number" ||
      payload.expiresAt < Date.now()
    ) {
      throw invalidCursor();
    }
    return payload.pageToken;
  }
}
