# OpenID Connect

A standalone WordPress plugin published by Byteable. The plugin slug is `openid-connect`; the interface name is **OpenID Connect**. It is configurable for a Keycloak instance and realm of your choice. It contains no hard-coded realm, hostname, company login label, or group hierarchy requirement.

## Installation and configuration

Upload `dist/openid-connect-0.2.0.zip` in **Plugins → Add New → Upload Plugin**, activate it, then open **Settings → OpenID Connect**. It is disabled by default.

| Setting | Purpose |
| --- | --- |
| Issuer URL | Exact realm issuer, for example `https://identity.example.com/realms/community` |
| Client ID | The confidential OIDC client registered in that realm |
| Backchannel issuer | Optional URL for the same realm reachable from the WordPress server/container |
| Group root | Optional role mapping hierarchy; defaults to `/wordpress`, and is editable |
| Login button label | Defaults to “Sign in with OpenID Connect” |
| Create new accounts | Opt-in provisioning after receipt of a verified email |
| Use WordPress groups | Opt-in role synchronization from exact group paths |
| Allow administrator group | Separate, explicit opt-in for administrator privileges |
| Log out of Keycloak | Opt-in browser logout of the provider session after WordPress logout |
| Allow development HTTP | Effective only with `WP_ENVIRONMENT_TYPE=local` or `development` |

Supply the client secret through the `OPENID_CONNECT_CLIENT_SECRET` environment variable or a constant in private `wp-config.php`. The settings page shows only whether a secret is present. Do not commit secrets. Optional `OPENID_CONNECT_BACKCHANNEL_ISSUER` and `OPENID_CONNECT_GROUP_ROOT` constants override their UI settings when an operator deliberately uses configuration-managed values.

The settings page displays the **exact callback URL** generated from the current WordPress login URL. Copy it exactly into the client redirect allowlist; do not use a wildcard. The endpoint is `wp-login.php?action=openid_connect_callback`. Scheme, hostname, port and installation path come from WordPress, not this plugin.

Keycloak client requirements: confidential OpenID Connect, authorization code flow, PKCE S256, client-secret basic authentication, RS256 ID-token signing, and the exact callback. Disable implicit/password grants and service accounts. The plugin requests `openid profile email`. Provisioning requires `email` and boolean `email_verified: true` in the signed ID token. Group synchronization additionally requires a full-path `groups` claim in the ID token.

### Container networking

Keep the public issuer unchanged when WordPress runs in a container. Set the optional backchannel issuer to a verified internally reachable URL for the **same realm**. Only server-side discovery/token/JWKS traffic uses that address. Keycloak may advertise internal token/JWKS endpoints to those requests; the plugin accepts only the explicitly configured alias and continues to check the public issuer exactly. Arbitrary other endpoint hosts are rejected. HTTPS and certificate validation are required outside explicitly enabled local/development HTTP.

## Accounts and roles

Accounts are bound to issuer + immutable subject, never automatically to matching email or username. Existing-email conflicts are rejected; manual linking is not included. New accounts receive an opaque username and random password. No tokens are stored.

With role synchronization off, new users become subscribers and existing roles are preserved. With it on, exact children of the configured group root map to `editor`, `author`, `contributor`, and `subscriber` in that precedence order. `administrator` takes precedence only when separately enabled. No permitted group denies login. Role changes replace the roles of plugin-created accounts on their next successful OIDC login. Disabling synchronization preserves the last assigned roles.

Optional **Enforce SSO** blocks native passwords, resets and application passwords only for accounts explicitly bound by this plugin. Enabling it revokes those accounts’ existing WordPress sessions, application passwords and outstanding reset links. Unmanaged local accounts, including a recovery administrator, retain native authentication. Keep the plugin active to enforce this policy; deactivation removes its hooks. WordPress logout is local by default; optional Keycloak logout is described below. There is no refresh-token storage, background role synchronization, account deletion, multisite support, or provider deployment. Deactivation/uninstall retain account data and settings.

## Optional Keycloak logout

Enable **Settings → OpenID Connect → Log out of Keycloak** after copying the displayed **Exact logout return URL** into the client's **Valid Post Logout Redirect URIs** in Keycloak. The plugin discovers and validates `end_session_endpoint`; no instance-specific logout URL is hard-coded. Development uses `http://127.0.0.1:8090/wp-login.php?loggedout=true`.

Only a browser session signed in through this plugin is eligible. Sign in again after upgrading so the new session carries the issuer/client marker. A normal WordPress password login remains local, even for the same user. WordPress verifies its logout nonce and destroys its session before the external redirect. If discovery is unavailable or the provider configuration has changed, local logout still succeeds and the login page explains that Keycloak may remain signed in.

The logout request sends `client_id` and the exact return URL, without storing or exposing an ID token. Keycloak can require a **Logout** confirmation. Until the user confirms, the provider session may remain active. This may also sign out other applications attached to the same Keycloak SSO session. It does not implement provider-initiated backchannel logout or revoke every browser/device session.

The option is off by default; it is enabled in the current development deployment. Existing instance settings and the user's custom login label were preserved. Keycloak's exact return allowlist was configured and verified; use the checkbox to opt in.

Reference: [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).

## Security and supported profile

Authorization code + PKCE S256; random state and nonce; browser-bound HttpOnly SameSite=Lax cookie; ten-minute transactions; atomic one-use callback claims; RS256 signatures checked using discovered RSA keys; issuer, single-client audience, authorized-party, subject, nonce and time checks. Optional token hashes are validated. Server-side HTTP redirects are not followed. Error pages and plugin logs do not disclose tokens, credentials or provider response bodies.

Pending login state uses non-autoloaded database options so object-cache eviction cannot break the round trip. Expired transactions and replay locks are cleaned through WP-Cron; keep it running. One in-flight login per browser is supported. Repeated sign-in uses the same account. Identity and email locks coordinate provisioning by this plugin, not unrelated account-creation code.

This initial release targets modern Keycloak instances that meet this profile; it is not a claim of support for every OIDC provider, custom authentication flow, or signing algorithm. JWT verification uses locked `firebase/php-jwt` 7.2.1, bundled with its license in release ZIPs.

## Build and tests

Requires PHP 8.2+, OpenSSL, Composer, `zip`, and `shasum`.

```sh
./tools/package.sh
```

The build installs locked dependencies, runs protocol and WordPress-adapter tests plus PHP syntax checks, then generates the ZIP and SHA-256 checksum. Vendor dependencies and generated packages are ignored by Git. Run the suites individually with `php tests/protocol.php`, `php tests/wordpress.php`, and `php tests/account-flow.php`.

Protocol tests cover signed tokens, malicious/invalid claims, algorithms, PKCE, discovery boundaries, internal aliases and group mappings. WordPress-adapter tests cover provisioning, email conflicts, stable identities, role changes, expired/browser-bound/configuration-bound state and replay prevention. The adapter suite uses WordPress function doubles; live acceptance is recorded separately in the development deployment report.

Version 0.1.1 replaces the initial development identifiers and callback, adds configurable instance settings, and fixes container discovery and cache-dependent state handling. The existing development installation was migrated explicitly; no backward-compatible legacy callback alias remains. Update the provider allowlist when upgrading from the unpublished 0.1.0 build.

References: [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), [JWT library](https://github.com/googleapis/php-jwt), [Keycloak Admin API](https://www.keycloak.org/docs-api/latest/rest-api/).

Version 0.1.2 adds optional RP-initiated Keycloak logout, per-WordPress-session provider markers, explicit local-logout fallback, and logout endpoint/return validation.

## Registration and account flow (0.2.0)

Enable **Public account flow** to route public WordPress registration/recovery to the provider sign-in screen, where Register and Forgot Password are available. Native public registration is disabled while this option is active. Configure Keycloak registration, verified email, password recovery, SMTP, and a least-privilege default group separately. This generic plugin does not deploy or configure Keycloak.

Create a page containing `[openid_connect_account]` and set **Account page URL** to its actual permalink. Put `[openid_connect_link]` in a Shortcode block in the header; an optional `label="Sign in / Create account"` changes that placement only. Safe same-origin return URLs retain the page a visitor started from. Without a requested destination, subscribers go to the account page and users with editing rights go to the dashboard. The account page sends no-cache headers; exclude it and authenticated visitors from any external page cache.

**Provider account URL** defaults to the configured issuer’s `/account/` and must stay below that issuer. Verified provider email changes synchronize on subsequent login; conflicting addresses fail safely. Local email/password changes on enforced accounts are ignored. Existing email matches never link accounts automatically. Legacy account migration requires operator verification of the original issuer and subject; do not mark users by email alone.

Keep an unmanaged local administrator and its credentials available. Native login remains at `wp-login.php`; native recovery uses `wp-login.php?action=lostpassword&local_recovery=1`. This form bypass does not permit managed accounts to reset locally. Turning off provider login does not turn off SSO enforcement. Provider logout remains a separate option and can require Keycloak confirmation.
