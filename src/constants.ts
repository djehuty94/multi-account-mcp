export const APP_NAME = "Multi-Account MCP";
export const APP_ID = "io.github.djehuty94.multi-account-mcp.google";
export const VERSION = "0.1.0-alpha.1";

export const IDENTITY_SCOPES = [
  "openid",
  "https://www.googleapis.com/auth/userinfo.email",
] as const;

export const SERVICE_SCOPES = {
  gmail: "https://www.googleapis.com/auth/gmail.readonly",
  drive: "https://www.googleapis.com/auth/drive.readonly",
} as const;

export const LIMITS = {
  maxAccountsPerCall: 10,
  maxGmailResultsPerAccount: 20,
  maxDriveResultsPerAccount: 50,
  maxGmailSearchResultsTotal: 50,
  maxDriveSearchResultsTotal: 100,
  maxMcpSerializedChars: 1_000_000,
  defaultBodyChars: 20_000,
  maxBodyChars: 100_000,
  maxDownloadedBytes: 2_000_000,
  maxGoogleJsonBytes: 3_000_000,
  maxMimeParts: 200,
  maxBodyParts: 20,
  maxMimeDepth: 20,
  maxAttachments: 100,
  maxThreadMessages: 25,
  maxThreadBodyChars: 250_000,
  maxThreadAttachments: 200,
  requestTimeoutMs: 30_000,
  oauthTimeoutMs: 10 * 60_000,
} as const;

export const MCP_RATE_LIMITS = {
  global: {
    capacity: 60,
    refillPerSecond: 1,
  },
  perAccount: {
    capacity: 15,
    refillPerSecond: 0.25,
  },
  listAccounts: {
    capacity: 12,
    refillPerSecond: 0.2,
  },
  maxAccountBuckets: 256,
} as const;
