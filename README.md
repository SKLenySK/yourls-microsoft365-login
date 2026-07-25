# Microsoft 365 Login for YOURLS

Lets people sign in to the YOURLS admin area with their **Microsoft 365 / Entra ID (Azure AD)**
account, using standard OpenID Connect (Authorization Code flow + PKCE). Access is restricted to
members of one or more **Entra ID groups** you choose. Local username/password accounts defined
in `config.php` keep working as a fallback — this plugin only takes over when a Microsoft 365
login is actually in progress or an active Microsoft 365 session cookie is present.

## How it works

- Adds a "Sign in with Microsoft 365" button above the normal login form.
- On click, redirects to Microsoft's login page (`login.microsoftonline.com`) with PKCE.
- On return, exchanges the authorization code for an ID token, verifies its signature against
  Microsoft's published signing keys (JWKS) and its `iss`/`aud`/`exp`/`nbf` claims, then checks
  the signed-in account's Entra ID **group membership** against an allow-list before granting
  access.
- On success, sets its own signed session cookie (HMAC'd with a key derived from
  `YOURLS_COOKIEKEY`) and logs the user in as their email address.
- No new user database or external service is required beyond Azure AD itself.

**Fails closed**: if no allowed group is configured, no Microsoft 365 account can log in, even
if the app registration is otherwise valid.

## 1. Register an application in Azure

1. Go to **Entra ID** (Azure AD) → **App registrations** → **New registration** in the
   [Azure Portal](https://portal.azure.com).
2. Give it a name (e.g. "YOURLS").
3. Under **Redirect URI**, choose platform **Web** and enter your YOURLS admin URL, exactly:
   ```
   https://your-yourls-domain.example/admin/index.php
   ```
   (Shown for your install under Plugins → Microsoft 365 Login once the plugin is active.)
4. After creation, note the **Application (client) ID** and **Directory (tenant) ID** from the
   Overview page.
5. Go to **Certificates & secrets** → **New client secret**, and copy the secret **value**
   (not the secret ID) immediately — it's only shown once.
6. No API permissions need to be added beyond the default `openid`/`profile`/`email` (delegated,
   already granted by default for any registered app).
7. **Required, since access is group-based:** go to **Token configuration** → **Add groups
   claim** → check **Security groups**. This opens a small table with separate checkbox columns
   **ID / Access / SAML** — make sure the box under **ID** is checked (it's easy to only tick
   "Access" by mistake, in which case the plugin will never see any group information and will
   reject everyone). This is a one-time setting for the app registration.

## 2. Activate and configure the plugin

1. Copy this `microsoft365-login` folder into `user/plugins/` (already done if you're reading
   this from that location).
2. In YOURLS admin, go to **Manage Plugins** and activate **Microsoft 365 Login**.
3. Go to **Plugins → Microsoft 365 Login** and fill in:
   - **Tenant ID** — the Directory (tenant) ID, or your verified domain (e.g.
     `contoso.onmicrosoft.com`).
   - **Application (client) ID**
   - **Client secret**
   - **Allowed Entra ID group(s)** — comma-separated **Object ID** (a GUID, not the group's
     display name) — find it under **Entra ID → Groups → (your group) → Overview**. Required;
     requires step 7 above (the groups claim) to be enabled on the app registration.
4. Save. The "Sign in with Microsoft 365" button now appears on the login page.

### About group-based access

- The plugin checks the `groups` claim in the ID token against the configured group Object
  ID(s) — no extra Microsoft Graph API call or permission is needed.
- **Overage limit**: if an account belongs to a very large number of groups tenant-wide
  (roughly 200+), Microsoft omits the `groups` claim from the token entirely for that sign-in.
  The plugin treats this as "no group information available" and rejects the sign-in (fails
  closed). If this matters for your tenant, prefer a small dedicated group (e.g. "YOURLS
  Admins") over a huge one.
- Group membership is captured at sign-in time and cached in the session cookie for its
  lifetime (default 30 days). Removing someone from the group in Entra ID takes effect the next
  time they sign in again (i.e. once their current session cookie expires or they log out) —
  not instantly on their next click.

## Alternative: configuring via `config.php` instead of the database

If you'd rather not store the tenant/client ID, secret or allowed group(s) in the database,
define any of these constants in `user/config.php` — a defined constant always takes precedence
over the admin settings page (which will show the field as locked/read-only):

```php
define( 'YOURLS_M365_TENANT_ID', 'contoso.onmicrosoft.com' );
define( 'YOURLS_M365_CLIENT_ID', '00000000-0000-0000-0000-000000000000' );
define( 'YOURLS_M365_CLIENT_SECRET', 'your-client-secret-value' );
define( 'YOURLS_M365_ALLOWED_GROUPS', '00000000-0000-0000-0000-000000000000' );
```

## Troubleshooting

Temporarily set `define( 'YOURLS_DEBUG', true );` in `user/config.php` and try signing in again
— the failed-login page will show a debug log at the bottom with the exact reason. Turn it back
off (`false`) once you're done, it shouldn't stay on in production.

- **"this account is not authorized for this site"**, and the debug log shows
  `rejected account not on allow-list: someone@example.com` — that identity either isn't a
  member of any allowed group, or (see next point) the token isn't carrying group information
  at all yet.
- **Same rejection even though the account is a member of an allowed group**, and the debug log
  does *not* mention "overage" — the ID token isn't carrying a `groups` claim at all yet. This
  almost always means step 7 above (Token configuration → Add groups claim) either wasn't done,
  or only the **Access** token column was checked instead of **ID**. Fix it in Azure, then sign
  in again (existing sessions/cached tokens won't retroactively gain the claim).
- **The debug log mentions "overage"** — the account belongs to too many groups tenant-wide for
  Microsoft to list them in the token (roughly 200+). Use a smaller, dedicated group instead.
- **"your login attempt expired"** right after coming back from Microsoft — the state cookie set
  before redirecting to Microsoft didn't come back with the browser. Usually caused by taking
  more than 10 minutes to complete sign-in (MFA prompts, etc.), or by `YOURLS_SITE` in
  `config.php` not matching **exactly** (with/without `www.`, `http` vs `https`) the URL actually
  used in the browser.

## Notes

- The plugin identifies users by the `preferred_username` (or `email`) claim from the ID token,
  lower-cased. That value becomes the YOURLS username (`YOURLS_USER`) for that session — it is
  only used for identification/logging, not for the access decision itself.
- API access (`yourls-api.php` with a signature/timestamp or username/password) is untouched by
  this plugin and keeps working as before.
- Logging out clears both the normal YOURLS cookie and this plugin's session cookie.
