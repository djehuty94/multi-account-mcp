# Google OAuth setup for personal use

Google requires OAuth clients to be created manually in Google Cloud Console. Multi-Account MCP cannot safely automate this step.

## Why Google Auth Platform for a local MCP?

Google Auth Platform is Google's configuration surface for the consent screen, audience, scopes, and OAuth client. It does not mean Multi-Account MCP is hosted. Choose a **Desktop app** client: the MCP runs on the user's computer, opens Google's hosted consent page, and receives the authorization response through a temporary random-port callback on `127.0.0.1`. There is no hosted application server, permanent redirect URI, remote token broker, or project-operated backend.

Desktop apps are OAuth public clients. Their client ID and nominal client secret cannot be confidential once distributed. This project therefore uses a bring-your-own Google Cloud project/client and never commits or ships a maintainer-owned shared client. The downloaded JSON is still handled as sensitive configuration because exposing it can enable impersonation or abuse of your project identity and quota.

## 1. Create a dedicated project

Use a new Google Cloud project for Multi-Account MCP. Do not reuse a production project with unrelated credentials or users.

Enable:

- Gmail API
- Google Drive API

Google’s [OAuth desktop-app guide](https://developers.google.com/identity/protocols/oauth2/native-app) is the primary reference.

## 2. Configure the consent screen

In Google Auth Platform, configure the app deliberately rather than accepting placeholder ownership details:

- use an app name that clearly identifies this local Multi-Account MCP installation;
- select a **user support email** that you control and want Google to show on the consent screen;
- enter a **developer contact email** that you actively monitor for Google policy and security notices;
- choose **External** if the accounts span unrelated Gmail/Workspace organizations—**Internal** works only when every account belongs to the same Google Workspace/Cloud Identity organization;
- start with publishing status **Testing** and add only the exact sacrificial Google accounts used for the live test as test users; and
- provide working Privacy Policy and Terms of Service URLs when Google requires them for your publishing status, verification, or distribution. For this project, the public repository's `PRIVACY.md` and `TERMS.md` are the source documents once those URLs are public.

The support email, developer contact, and test-user addresses are chosen and entered by the Google Cloud project owner. Never commit them to this repository or record them in public test evidence.

Declare only:

- `openid`
- `userinfo.email`
- `gmail.readonly`
- `drive.readonly`

Gmail and Drive global read scopes are restricted scopes. Do not substitute `gmail.modify`, full `drive`, or `mail.google.com`.

## 3. Choose Testing vs In production

Google documents that an External project in **Testing** is limited to listed test users and its grants/refresh tokens normally expire after seven days for the restricted scopes used here. Testing is appropriate for the initial live test, not dependable daily use.

For durable personal use, move the project to **In production** after the test. An unverified personal-use app can show an unverified warning and remains subject to Google’s user limits/policy. Do not interpret this as permission to distribute a shared public OAuth client.

References: [Manage app audience](https://support.google.com/cloud/answer/15549945), [when verification is not required](https://support.google.com/cloud/answer/13464323), and [verification requirements](https://support.google.com/cloud/answer/13464321).

## 4. Create a Desktop app client

Create an OAuth client with application type **Desktop app** and download the JSON. Multi-Account MCP intentionally rejects Web application client JSON. A Desktop client is the installed-app choice for this local command-line MCP: Google hosts the authorization page, while the local process receives a one-time callback on a temporary `127.0.0.1` port.

Download the file to a local folder outside this repository, any other source checkout, and cloud-synchronized folders. Do not leave an extra copy in Downloads, email, chat, or a password-manager note. Restrict the working copy before use:

```bash
chmod 600 /absolute/path/to/client.json
```

Multi-Account MCP requires the OAuth JSON to be owned by you and unreadable by other local users. Then run:

```bash
multi-account-mcp auth add test-account --services both --client /absolute/path/to/client.json
```

Run `auth add` directly in an interactive terminal. Non-TTY input is rejected and there is no `--yes` bypass. Immediately before the browser opens, the CLI discloses the requested read-only access, local credential handling, and that bounded tool results go to your configured MCP host and may be processed by its model provider. Type the exact requested alias to acknowledge that disclosure; declining stops before Google OAuth opens.

The browser must show:

- the project/app name you just created;
- the Google account you selected;
- read-only Gmail and Drive access.

After Google returns a verified identity, the terminal writes the verified email and requested local alias to stderr. Type the exact alias a second time to approve that account binding. Only after successful authorization **and** this binding confirmation does Multi-Account MCP store the OAuth client, DPoP-bound refresh token, and that grant's P-256 DPoP private JWK in the OS credential vault. It does not copy the downloaded JSON into its config directory. The DPoP key is vault-stored software key material, not a Secure Enclave or hardware-backed key. A mismatch, interruption, or confirmation failure aborts and revokes the newly issued grant. A duplicate already-connected Google identity fails without revocation because revoking that grant could disconnect the existing alias.

After the first account is connected, run `multi-account-mcp doctor`. Once it passes and you have confirmed—without displaying or exporting values—that the OAuth client is present in the OS credential vault, delete the downloaded client JSON and every stray copy. Keep it only long enough to complete the Keychain import and health check; later accounts use the vault-stored client.

## 5. Add each account

```bash
multi-account-mcp auth add personal --services both
multi-account-mcp auth add work --services gmail
multi-account-mcp auth add client-a --services drive
multi-account-mcp auth list
multi-account-mcp doctor
```

`--services` accepts `gmail`, `drive`, or `both` (the default). Each account receives only the selected restricted service scope plus OpenID/email identity scopes. Service profiles are not changed in place: remove/revoke the alias, then add it again with the new profile.

Use a sacrificial/non-sensitive account for the first live test. Verify `list_accounts`, a harmless Gmail query, and a harmless Drive query before connecting valuable accounts.

## 6. Revoke/remove

```bash
multi-account-mcp auth remove test-account --yes
```

On normal success, this revokes the token at Google before deleting local credentials and metadata. Google revocation can remove the project’s grant for that Google account, so a later reconnect requires consent again. `--local-only` skips Google revocation and is only for a deliberately external revocation or the explicit reconciliation path described by a typed error; a failed or interrupted removal must not be assumed complete.

## Public distribution warning

A shared public OAuth client changes the compliance/operational boundary even if the MCP remains entirely local; a hosted token broker changes it further. Global Gmail/Drive access can require Google verification and recurring CASA/security assessment. Start open source with bring-your-own OAuth projects and Desktop clients; do not commit or ship a shared desktop client JSON.

Sources: [OAuth for installed apps](https://developers.google.com/identity/protocols/oauth2/native-app), [Google DPoP adoption](https://developers.google.com/identity/protocols/oauth2/resources/dpop-adoption), [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes), [Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth), [OAuth best practices](https://developers.google.com/identity/protocols/oauth2/resources/best-practices), and [security assessment requirements](https://support.google.com/cloud/answer/13465431).
