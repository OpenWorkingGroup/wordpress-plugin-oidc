# Development acceptance — 2026-11-15

OpenID Connect 0.1.1 is installed and enabled at `http://127.0.0.1:8090`. Byteable is the publisher only; settings and login UI use OpenID Connect. Connection settings are editable and the plugin has no fixed realm or instance hostname.

## Effective development configuration

- Public issuer: `http://localhost:8180/realms/Public`.
- Internal backchannel: `http://syvlocal-sso:8080/realms/Public`.
- Client ID: `syvlocal.com`, following the user's intentional rename of the client created during this task. The same client UUID was retained; no duplicate client was created after the rename.
- Exact callback, read from the installed plugin and verified in its settings page: `http://127.0.0.1:8090/wp-login.php?action=openid_connect_callback`.
- Existing group root: `/syvlocal.com`, selected by the user. Groups were neither renamed nor duplicated.
- Account provisioning and group roles enabled; administrator mapping disabled. Development HTTP explicitly enabled in the existing local environment.
- Secret is in a restricted private file under `/var/lib/wordpress/database/openid-connect-private.php`, outside the web root and Git. A small development MU loader reads it. Instance URLs, client ID, group root and button label are settings, not secret-file overrides.

The existing generic OIDC plugin is inactive. Development startup now selects the installed OpenID Connect plugin when its private configuration exists, retaining the legacy fallback for other installations. The source startup helper and running container copy were both updated. Only WordPress was restarted; Keycloak and database runtimes were not redeployed. No Administrators-realm configuration was changed.

## Observed tests

- Real browser authorization-code + PKCE flow reached the WordPress subscriber dashboard.
- Repeated OIDC login reused the same WordPress account (ID stayed 3 during the test).
- Changing only the temporary test identity to editor granted editor menus on next login; returning it to subscriber removed them.
- An administrator-only group was refused while administrator mapping was disabled; no administrator privileges were granted.
- Invalid callback state was rejected with a generic error.
- WordPress logout worked, and normal local administrator login still worked.
- WordPress restart retained the plugin, settings and private credential. A subsequent real browser login succeeded using the renamed `syvlocal.com` client.
- The final settings page showed OpenID Connect, the configured generic login label, client ID, group root and exact callback without exposing the secret.
- Keycloak Ansible preflight and validation passed. A subsequent apply reported `changed=0` for the renamed client.
- 39 protocol checks, 24 WordPress-adapter checks and 8 Ansible reconciler tests passed. PHP syntax checks and package checksum verification passed; Composer reported no known advisories during dependency resolution.

Live testing found and fixed two integration issues: Keycloak's explicitly configured internal discovery endpoints, and login state lost from the object cache. State now uses non-autoloaded database options with expiry and atomic replay protection. A Keycloak API representation that omits a disabled authorization-services flag is normalized during Ansible validation and covered by a regression test.

The temporary Keycloak and WordPress test accounts were removed after confirming they had no WordPress content. Existing users were preserved. Browser-based token mutation, provider logout, exclusive SSO, and arbitrary custom Keycloak flows were not claimed as tested.

## Operations and rollback material

Private pre-install backup: `~/Workspace/syvlocal.com/.local/oidc-install-backup/` (consistent SQLite snapshot, prior active-plugin/options state, startup helper and Keycloak pre-state). It contains private operational data; keep it out of Git. Restoring the full database would discard later site edits; prefer restoring only relevant settings/files when appropriate.

The development Ansible overlay explicitly selects `syvlocal.com` and `/syvlocal.com`. Exact callback confirmation is in the ignored `~/Workspace/syvlocal.com/.local/identity-development.yml`. Supply a short-lived admin token through the existing secure workflow and run from `~/Workspace/syvlocal.com/shared`:

```sh
ansible-playbook -i localhost, playbooks/identity-validate.yml \
  -e @overlays/identity/development.yml -e @../.local/identity-development.yml
```

The source/package and Ansible fixes are local changes; no commit or publication was performed.

## Optional logout acceptance — version 0.1.2

- New opt-in “Log out of Keycloak” setting; left disabled after testing. Other current settings, including the custom login label, were preserved.
- The installed helper returned `http://127.0.0.1:8090/wp-login.php?loggedout=true`; Ansible registered that exact post-logout redirect on `syvlocal.com`. Validation passed, and a second apply reported no changes.
- With the option enabled, a native WordPress administrator logout stayed local.
- A fresh OIDC subscriber login followed by WordPress logout reached Keycloak's Logout confirmation. Confirming returned to WordPress's logged-out page. The Keycloak Admin API confirmed zero sessions for the test identity, and the next sign-in required credentials again.
- With the option disabled, OIDC logout stayed in WordPress and the Keycloak Admin API confirmed its session remained active.
- Temporary test accounts were removed from WordPress and Keycloak afterward.
- 44 protocol checks, 32 WordPress-adapter checks, and 9 Ansible reconciler tests passed. Coverage includes missing/foreign/traversing logout endpoints, configured internal aliases, default-off/native-session behavior, invalid logout nonce, provider outage, and changed-provider mismatch.
- Prior WordPress settings and logout allowlist were backed up under `~/Workspace/syvlocal.com/.local/oidc-logout-backup/`. No ID tokens are retained for logout. The browser confirmation is intentional; canceling it does not end the provider session.

## Streamlined registration acceptance — version 0.2.0

The current development deployment enables public account flow, exclusive SSO for managed accounts, and optional provider logout. It preserves the custom “Sign in with SYV Connect” login label. Header entry uses “Sign in / Create account”. The new My account page is `http://127.0.0.1:8090/?page_id=9` (the site uses plain permalinks).

Keycloak changes were applied only to Public through the existing Ansible reconciler: email-as-username registration, verified email, password recovery, duplicate-email rejection, and local SMTP. The existing `/syvlocal.com/subscriber` default group was retained. Preflight and validation passed; repeated apply reported zero changes. The existing registration flow collects email/profile first, then email verification and password setup; it was retained.

Mailpit is available only at `http://127.0.0.1:8025`; SMTP is internal to the development container network. It captures mail without delivering externally and loses messages when recreated/restarted. A development-only MU mail adapter also routes WordPress mail to it. No production SMTP is configured.

Observed acceptance:

- Fresh public registration created no WordPress account/session before verification. The emailed verification link and separate password setup completed, provisioning one managed subscriber on the frontend account page.
- Keycloak email password recovery completed and the recovered credentials signed into WordPress.
- Live WordPress checks rejected managed username/email passwords, reset-key creation, and application-password availability. Native recovery administrator login and reset eligibility passed.
- Browser sign-in from the header returned to the original homepage; My account displayed the provider security link and local preferences/logout links.
- 44 protocol, 32 WordPress-adapter, 36 account-flow checks and 10 Ansible tests passed.

The local `admin` recovery account remains unmanaged. The legacy `wp_admin` account was explicitly bound after its stored issuer/subject matched Keycloak. Administrator-group mapping remains disabled: that legacy administrator-only identity cannot sign in through OIDC under the existing role policy; use the local recovery account for administration. No administrator grant was enabled.

Backups are in the ignored `.local/registration-backup/` directory of syvlocal.com: consistent SQLite snapshot, previous settings/header, Keycloak policy/default groups and plugin 0.1.2 package. Restore selectively; full database restore would discard subsequent site changes. Turning enforcement off does not recreate revoked sessions/application passwords. No commit or publication was performed.

Both disposable registration test accounts were removed from WordPress and Public after acceptance, with checks that they were managed subscribers with no posts. Existing users were preserved. The 0.2.0 package was built and installed runtime files matched source. Repeated identity and inbox applies both reported zero changes.

## Administrator mapping enabled — subsequent operator request

Administrator mapping is now enabled in the development plugin settings. Read-only Keycloak checks confirmed wp_admin is enabled, email-verified, and belongs to `/syvlocal.com/administrator`; its immutable subject matches the existing WordPress binding. The installed role resolver now accepts that group as administrator. SSO enforcement stays enabled for this account. No Keycloak settings or memberships were changed.

The unmanaged local admin recovery account’s password hash, roles, and metadata were unchanged; native reset eligibility remains allowed. Previous plugin settings were backed up privately at `/var/lib/wordpress/database/openid-connect-before-admin-mapping.json`. This setting permits any authenticated identity in the configured administrator group to receive the administrator role; it is not a username-specific exception. A fresh browser login as wp_admin was not performed during this settings change.
