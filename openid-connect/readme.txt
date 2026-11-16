=== OpenID Connect ===
Contributors: byteable
Tags: oidc, openid-connect, keycloak, login
Requires at least: 6.6
Requires PHP: 8.2
Stable tag: 0.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Small, optional OpenID Connect login for single-site WordPress.

== Description ==
Adds a Sign in with OpenID Connect button. Uses authorization code, PKCE S256, and signed RS256 ID tokens. Normal WordPress login remains available. Account creation and Keycloak group roles are opt-in; existing accounts are never linked by email automatically. Secrets are supplied outside the settings database.

== Installation ==
1. Upload the release ZIP through Plugins > Add New > Upload Plugin.
2. Supply OPENID_CONNECT_CLIENT_SECRET in the server environment or wp-config.php.
3. Open Settings > OpenID Connect and enter your issuer and client ID.
4. Copy the exact callback URL into your provider's redirect allowlist.
5. Enable login and, when appropriate, new-account creation.

== Frequently Asked Questions ==
= Which providers are supported? =
Issuer, client ID, backchannel address, group root and login button label are configurable for your Keycloak instance. It requires RS256, PKCE S256, client_secret_basic, and same-issuer-path discovery endpoints. It is not a general-purpose OIDC conformance implementation.

= Does this replace WordPress login or logout? =
No. WordPress passwords and sessions retain their normal behavior. Logout is local by default. Enable Log out of Keycloak to also visit the provider logout endpoint for OIDC sessions; Keycloak may require confirmation. Register the exact displayed logout return URL first.

= Are existing accounts linked by email? =
No. Existing-email conflicts are rejected. Manual account linking is not included.

== Changelog ==
= 0.2.0 =
Optional Keycloak logout with per-session detection, nonce protection, exact return URL and local-logout fallback.

= 0.1.1 =
Generic interface and identifiers, configurable connection settings, internal discovery aliases, and cache-independent login state.
