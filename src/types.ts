export type GoogleService = "gmail" | "drive";

export interface AccountMetadata {
  id: string;
  alias: string;
  googleSub: string;
  email: string;
  displayName?: string;
  scopes: string[];
  createdAt: string;
  updatedAt: string;
}

export interface AccountFile {
  version: 1;
  accounts: AccountMetadata[];
}

export interface DpopPrivateJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d: string;
}

export interface StoredGoogleTokens {
  version: 1;
  refreshToken: string;
  tokenType?: string;
  scope?: string;
  dpopPrivateJwk: DpopPrivateJwk;
}

export interface GoogleOAuthClientCredentials {
  clientId: string;
  clientSecret: string;
}

export interface SecretVault {
  getOAuthClient(): Promise<GoogleOAuthClientCredentials | null>;
  setOAuthClient(credentials: GoogleOAuthClientCredentials): Promise<void>;
  getTokens(alias: string): Promise<StoredGoogleTokens | null>;
  setTokens(alias: string, tokens: StoredGoogleTokens): Promise<void>;
  deleteTokens(alias: string): Promise<boolean>;
}
