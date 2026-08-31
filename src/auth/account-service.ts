import { randomUUID } from "node:crypto";
import { MultiAccountMcpError } from "../errors.js";
import type {
  AccountMetadata,
  GoogleOAuthClientCredentials,
  GoogleService,
  SecretVault,
} from "../types.js";
import { assertValidAlias } from "../policy/input.js";
import { AccountMetadataStore } from "../storage/metadata-store.js";
import {
  loadOAuthClientFile,
  revokeGoogleToken,
  runGoogleOAuth,
  type OAuthResult,
} from "./oauth.js";

export interface AccountBindingRequest {
  alias: string;
  email: string;
  displayName?: string;
}

export type ConfirmAccountBinding = (
  request: Readonly<AccountBindingRequest>,
) => Promise<boolean>;

export interface DataUseDisclosureRequest {
  alias: string;
  services: GoogleService[];
}

export type ConfirmDataUseDisclosure = (
  request: Readonly<DataUseDisclosureRequest>,
) => Promise<boolean>;

export interface AccountServiceDependencies {
  loadOAuthClientFile: typeof loadOAuthClientFile;
  revokeGoogleToken: typeof revokeGoogleToken;
  runGoogleOAuth: typeof runGoogleOAuth;
}

const DEFAULT_DEPENDENCIES: AccountServiceDependencies = {
  loadOAuthClientFile,
  revokeGoogleToken,
  runGoogleOAuth,
};

function clientsMatch(
  left: GoogleOAuthClientCredentials,
  right: GoogleOAuthClientCredentials,
): boolean {
  return left.clientId === right.clientId && left.clientSecret === right.clientSecret;
}

function duplicateGoogleAccountError(account: AccountMetadata): MultiAccountMcpError {
  return new MultiAccountMcpError(
    `That Google account is already connected as "${account.alias}". Multi-Account MCP did not revoke the newly returned grant because automatic revocation could disconnect the existing alias. Google may have retained broader consent; review Multi-Account MCP in Google Account security.`,
    "GOOGLE_ACCOUNT_ALREADY_CONNECTED",
  );
}

async function revokeRefreshToken(
  refreshToken: string,
  revoke: typeof revokeGoogleToken,
): Promise<boolean> {
  try {
    await revoke(refreshToken);
    return true;
  } catch {
    return false;
  }
}

export class AccountService {
  private readonly dependencies: AccountServiceDependencies;

  constructor(
    private readonly store: AccountMetadataStore,
    private readonly vault: SecretVault,
    dependencies: Partial<AccountServiceDependencies> = {},
  ) {
    this.dependencies = {
      loadOAuthClientFile: dependencies.loadOAuthClientFile ?? DEFAULT_DEPENDENCIES.loadOAuthClientFile,
      revokeGoogleToken: dependencies.revokeGoogleToken ?? DEFAULT_DEPENDENCIES.revokeGoogleToken,
      runGoogleOAuth: dependencies.runGoogleOAuth ?? DEFAULT_DEPENDENCIES.runGoogleOAuth,
    };
  }

  list(): Promise<AccountMetadata[]> {
    return this.store.list();
  }

  private async failAfterOAuth(
    result: OAuthResult,
    error: unknown,
    assertLeaseOwned: () => Promise<void>,
    localRollbackSucceeded = true,
  ): Promise<never> {
    let cleanup:
      | { status: "connected"; account: AccountMetadata }
      | { status: "revoked"; revoked: boolean };
    try {
      cleanup = await this.store.transaction(async (transaction) => {
        const connected = (await transaction.list()).find(
          (account) => account.googleSub === result.identity.googleSub,
        );
        if (connected) return { status: "connected" as const, account: connected };
        await assertLeaseOwned();
        return {
          status: "revoked" as const,
          revoked: await revokeRefreshToken(
            result.tokens.refreshToken,
            this.dependencies.revokeGoogleToken,
          ),
        };
      });
    } catch {
      throw new MultiAccountMcpError(
        "Account connection failed and cleanup was incomplete. Revoke Multi-Account MCP from Google Account security, then run `multi-account-mcp doctor`.",
        "CONNECT_ROLLBACK_INCOMPLETE",
      );
    }

    if (
      !localRollbackSucceeded ||
      (cleanup.status === "revoked" && !cleanup.revoked)
    ) {
      throw new MultiAccountMcpError(
        "Account connection failed and cleanup was incomplete. Revoke Multi-Account MCP from Google Account security, then run `multi-account-mcp doctor`.",
        "CONNECT_ROLLBACK_INCOMPLETE",
      );
    }
    if (cleanup.status === "connected") throw duplicateGoogleAccountError(cleanup.account);
    throw error;
  }

  async connect(options: {
    alias: string;
    clientFile?: string;
    confirmAccountBinding: ConfirmAccountBinding;
    confirmDataUseDisclosure: ConfirmDataUseDisclosure;
    openBrowser: boolean;
    services: GoogleService[];
  }): Promise<AccountMetadata> {
    const alias = assertValidAlias(options.alias);
    if (typeof options.confirmAccountBinding !== "function") {
      throw new MultiAccountMcpError(
        "Account binding requires an explicit interactive confirmation callback.",
        "ACCOUNT_BINDING_CONFIRMATION_REQUIRED",
      );
    }
    if (typeof options.confirmDataUseDisclosure !== "function") {
      throw new MultiAccountMcpError(
        "Google authorization requires an affirmative data-use disclosure confirmation.",
        "DATA_USE_DISCLOSURE_CONFIRMATION_REQUIRED",
      );
    }
    return this.store.connectLease(async (connectLease) => {
      const suppliedClient = options.clientFile
        ? await this.dependencies.loadOAuthClientFile(options.clientFile)
        : null;
      const initialAccounts = await this.store.list();
      if (initialAccounts.some((account) => account.alias === alias)) {
        throw new MultiAccountMcpError(
          `Alias "${alias}" is already connected. To change scopes or credentials, remove it first and add it again.`,
          "ACCOUNT_ALREADY_CONNECTED",
        );
      }
      const initialStoredClient = await this.vault.getOAuthClient();
      const initiallyRotatingClient = Boolean(
        initialStoredClient && suppliedClient && !clientsMatch(initialStoredClient, suppliedClient),
      );
      if (initiallyRotatingClient && initialAccounts.length > 0) {
        throw new MultiAccountMcpError(
          "A different Google OAuth client is already stored. Changing clients would invalidate existing account tokens.",
          "OAUTH_CLIENT_MISMATCH",
        );
      }
      const client = suppliedClient ?? initialStoredClient;
      if (!client) {
        throw new MultiAccountMcpError(
          "No Google OAuth client is configured. Pass --client /path/to/desktop-client.json the first time.",
          "OAUTH_CLIENT_REQUIRED",
        );
      }
      if (await this.vault.getTokens(alias)) {
        throw new MultiAccountMcpError(
          `Credentials already exist for alias "${alias}" without matching metadata. Remove them with \`multi-account-mcp auth remove ${alias} --yes\` before reconnecting.`,
          "ORPHAN_ACCOUNT_CREDENTIALS",
        );
      }

      let disclosureConfirmed: boolean;
      try {
        disclosureConfirmed = await options.confirmDataUseDisclosure({
          alias,
          services: [...options.services],
        });
      } catch {
        throw new MultiAccountMcpError(
          "The pre-authorization data-use disclosure confirmation failed. Google authorization was not opened.",
          "DATA_USE_DISCLOSURE_CONFIRMATION_FAILED",
        );
      }
      if (disclosureConfirmed !== true) {
        throw new MultiAccountMcpError(
          "The data-use disclosure was declined. Google authorization was not opened.",
          "DATA_USE_DISCLOSURE_DECLINED",
        );
      }

      await connectLease.assertOwned();
      const result = await this.dependencies.runGoogleOAuth(client, {
        openBrowser: options.openBrowser,
        services: options.services,
        knownGoogleSubs: initialAccounts.map((account) => account.googleSub),
        beforeRevoke: () => connectLease.assertOwned(),
      });
      const initiallyConnectedIdentity = initialAccounts.find(
        (account) => account.googleSub === result.identity.googleSub,
      );
      if (initiallyConnectedIdentity) throw duplicateGoogleAccountError(initiallyConnectedIdentity);

      let localRollbackSucceeded = true;
      try {
        let confirmed: boolean;
        try {
          confirmed = await options.confirmAccountBinding({
            alias,
            email: result.identity.email,
            ...(result.identity.displayName ? { displayName: result.identity.displayName } : {}),
          });
        } catch {
          throw new MultiAccountMcpError(
            "Account-binding confirmation failed. No account was connected.",
            "ACCOUNT_BINDING_CONFIRMATION_FAILED",
          );
        }
        if (confirmed !== true) {
          throw new MultiAccountMcpError(
            "Account binding was declined. No account was connected.",
            "ACCOUNT_BINDING_DECLINED",
          );
        }

        const now = new Date().toISOString();
        const metadata: AccountMetadata = {
          id: randomUUID(),
          alias,
          googleSub: result.identity.googleSub,
          email: result.identity.email,
          scopes: result.grantedScopes,
          createdAt: now,
          updatedAt: now,
          ...(result.identity.displayName ? { displayName: result.identity.displayName } : {}),
        };

        await connectLease.assertOwned();
        return await this.store.transaction(async (transaction) => {
          const accounts = await transaction.list();
          const connectedIdentity = accounts.find(
            (account) => account.googleSub === result.identity.googleSub,
          );
          if (connectedIdentity) throw duplicateGoogleAccountError(connectedIdentity);
          if (accounts.some((account) => account.alias === alias)) {
            throw new MultiAccountMcpError(
              `Alias "${alias}" was connected while authorization was in progress. No credentials were overwritten.`,
              "ACCOUNT_ALREADY_CONNECTED",
            );
          }

          const storedClient = await this.vault.getOAuthClient();
          const replacingStoredClient = Boolean(
            storedClient && !clientsMatch(storedClient, client),
          );
          if (replacingStoredClient && accounts.length > 0) {
            throw new MultiAccountMcpError(
              "A different Google OAuth client was stored while authorization was in progress. No credentials were overwritten.",
              "OAUTH_CLIENT_MISMATCH",
            );
          }
          if (await this.vault.getTokens(alias)) {
            throw new MultiAccountMcpError(
              `Credentials appeared for alias "${alias}" while authorization was in progress. No credentials were overwritten or deleted.`,
              "ORPHAN_ACCOUNT_CREDENTIALS",
            );
          }

          await connectLease.assertOwned();
          if (!storedClient || replacingStoredClient) await this.vault.setOAuthClient(client);
          let wroteTokens = false;
          try {
            await this.vault.setTokens(alias, result.tokens);
            wroteTokens = true;
            return await transaction.upsert(metadata);
          } catch (error) {
            try {
              const storedMetadata = await transaction.get(alias);
              if (storedMetadata) {
                if (
                  storedMetadata.id === metadata.id &&
                  storedMetadata.googleSub === metadata.googleSub
                ) {
                  await transaction.remove(alias);
                  if (await transaction.get(alias)) localRollbackSucceeded = false;
                } else {
                  localRollbackSucceeded = false;
                }
              }
            } catch {
              localRollbackSucceeded = false;
            }
            try {
              const stored = await this.vault.getTokens(alias);
              if (wroteTokens || stored?.refreshToken === result.tokens.refreshToken) {
                await this.vault.deleteTokens(alias);
                if (await this.vault.getTokens(alias)) localRollbackSucceeded = false;
              }
            } catch {
              localRollbackSucceeded = false;
            }
            throw error;
          }
        });
      } catch (error) {
        if (error instanceof MultiAccountMcpError && error.code === "CONNECT_LEASE_LOST") {
          throw new MultiAccountMcpError(
            "The account-connection lease was lost after Google authorization. Multi-Account MCP did not revoke automatically because another process may now own the same grant. Do not retry or delete `.connect.lock`. Stop all Multi-Account MCP auth commands, wait at least 10 minutes, run `multi-account-mcp auth list`, and review Multi-Account MCP in Google Account security. If the verified account is not listed, revoke the grant there before authorizing again.",
            "CONNECT_ROLLBACK_INCOMPLETE",
          );
        }
        return this.failAfterOAuth(
          result,
          error,
          () => connectLease.assertOwned(),
          localRollbackSucceeded,
        );
      }
    });
  }

  async disconnect(alias: string, revoke = true): Promise<boolean> {
    assertValidAlias(alias);
    let googleRevocationCompleted = false;
    let localTokenDeletionConfirmed = false;
    try {
      return await this.store.connectLease(async (connectLease) => {
        return this.store.transaction(async (transaction) => {
          const account = await transaction.get(alias);
          const tokens = await this.vault.getTokens(alias);
          if (!account && !tokens) return false;
          if (revoke) {
            if (!tokens) {
              throw new MultiAccountMcpError(
                "The local refresh token is missing, so Google revocation cannot be verified. Revoke Multi-Account MCP in Google Account security or retry with --local-only.",
                "TOKEN_REVOCATION_IMPOSSIBLE",
              );
            }
            await connectLease.assertOwned();
            if (!(await revokeRefreshToken(tokens.refreshToken, this.dependencies.revokeGoogleToken))) {
              throw new MultiAccountMcpError(
                "Google token revocation failed. Nothing was deleted locally; retry or use --local-only explicitly.",
                "TOKEN_REVOCATION_FAILED",
              );
            }
            googleRevocationCompleted = true;
          }

          await connectLease.assertOwned();
          await this.vault.deleteTokens(alias);
          if (await this.vault.getTokens(alias)) {
            throw new MultiAccountMcpError(
              "The credential vault did not confirm token deletion, so account metadata was preserved.",
              "KEYRING_DELETE_FAILED",
            );
          }
          localTokenDeletionConfirmed = true;
          if (account) await transaction.remove(alias);
          return true;
        });
      });
    } catch (error) {
      if (
        error instanceof MultiAccountMcpError &&
        error.code === "ACCOUNT_METADATA_COMMIT_UNCERTAIN"
      ) {
        throw new MultiAccountMcpError(
          "Account removal reached its final metadata commit, but filesystem durability could not be confirmed. Local state may already be removed. Do not retry automatically. Run `multi-account-mcp doctor` and review Multi-Account MCP in Google Account security before deciding whether further action is needed.",
          "DISCONNECT_COMMIT_UNCERTAIN",
          { metadataMayAlreadyBeRemoved: true },
        );
      }
      if (
        error instanceof MultiAccountMcpError &&
        error.code === "ACCOUNT_MUTATION_LEASE_CLEANUP_UNCERTAIN"
      ) {
        throw error;
      }
      if (googleRevocationCompleted || localTokenDeletionConfirmed) {
        throw new MultiAccountMcpError(
          "Google revocation or local credential deletion completed, but local account cleanup did not finish. Do not retry automatically. Run `multi-account-mcp doctor`, review Multi-Account MCP in Google Account security, and only after reconciling both states run `multi-account-mcp auth remove <alias> --yes --local-only` once to remove stale local metadata.",
          "DISCONNECT_LOCAL_CLEANUP_INCOMPLETE",
          { googleRevocationCompleted, localTokenDeletionConfirmed },
        );
      }
      throw error;
    }
  }
}
