export class MultiAccountMcpError extends Error {
  constructor(
    message: string,
    readonly code: string,
    readonly safeDetails?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "MultiAccountMcpError";
  }
}

export function safeErrorMessage(error: unknown): string {
  if (error instanceof MultiAccountMcpError) return error.message;
  return "Unexpected Multi-Account MCP error.";
}
