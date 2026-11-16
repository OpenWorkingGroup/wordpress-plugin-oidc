<?php
namespace OpenIDConnect;

use RuntimeException;
use Throwable;

final class Plugin
{
    private ?AccountFlow $accountFlow = null;
    private const OPTION = 'openid_connect';
    private ?string $providerLogoutUrl = null;
    private bool $providerLogoutFailed = false;
    private const COOKIE = 'openid_connect_browser';

    public function register(): void
    {
        $this->flow()->register();
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_init', [$this, 'settings']);
        add_action('login_form_logout', [$this, 'prepareLogout']);
        add_filter('logout_redirect', [$this, 'finishLogout'], 999, 3);
        add_filter('login_message', [$this, 'logoutMessage']);
        add_action('login_form', [$this, 'button']);
        add_action('login_form_openid_connect', [$this, 'begin']);
        add_action('login_form_openid_connect_callback', [$this, 'callback']);
        add_action('openid_connect_expire_lock', static fn(string $key) => delete_option($key));
    }

    private function flow(): AccountFlow
    {
        return $this->accountFlow ??= new AccountFlow(fn() => $this->options());
    }

    public static function callbackUrl(): string
    {
        return add_query_arg('action', 'openid_connect_callback', site_url('wp-login.php', 'login'));
    }

    public static function logoutReturnUrl(): string
    {
        return add_query_arg('loggedout', 'true', site_url('wp-login.php', 'login'));
    }

    private function options(): array
    {
        return wp_parse_args(get_option(self::OPTION, []), [
            'enabled' => false, 'issuer' => '', 'client_id' => 'wordpress',
            'group_root' => '/wordpress', 'backchannel_issuer' => '', 'login_label' => 'Sign in with OpenID Connect',
            'public_flow' => false, 'enforce_sso' => false, 'account_url' => '', 'provider_account_url' => '',
            'provider_logout' => false, 'provision' => false, 'sync_roles' => false, 'allow_admin' => false, 'allow_http' => false,
        ]);
    }

    private function config(): array
    {
        $o = $this->options();
        $o['issuer'] = rtrim($o['issuer'], '/');
        $o['secret'] = defined('OPENID_CONNECT_CLIENT_SECRET') ? (string) OPENID_CONNECT_CLIENT_SECRET
            : (string) getenv('OPENID_CONNECT_CLIENT_SECRET');
        $o['redirect_uri'] = self::callbackUrl();
        $o['backchannel_issuer'] = defined('OPENID_CONNECT_BACKCHANNEL_ISSUER') ? rtrim((string) OPENID_CONNECT_BACKCHANNEL_ISSUER, '/') : rtrim($o['backchannel_issuer'], '/');
        $o['group_root'] = defined('OPENID_CONNECT_GROUP_ROOT') ? (string) OPENID_CONNECT_GROUP_ROOT : $o['group_root'];
        $o['allow_http'] = (bool) $o['allow_http'] && in_array(wp_get_environment_type(), ['local', 'development'], true);
        if (is_multisite() || !$o['enabled'] || $o['secret'] === '' || $o['client_id'] === ''
            || !Protocol::validUrl($o['issuer'], $o['allow_http']) || str_contains($o['issuer'], '?')
            || !Protocol::validUrl($o['redirect_uri'], $o['allow_http'])) {
            throw new RuntimeException('OIDC is disabled or incompletely configured.');
        }
        return $o;
    }

    private function protocol(array $config): Protocol
    {
        return new Protocol($config, function (string $method, string $url, array $args) use ($config): array {
            // Optional controller/container transport alias; the public issuer and JWT iss stay unchanged.
            if ($config['backchannel_issuer'] !== '') {
                $backchannel = $config['backchannel_issuer'];
                if (!Protocol::validUrl($backchannel, $config['allow_http']) || str_contains($backchannel, '?')) {
                    throw new RuntimeException('Invalid backchannel configuration.');
                }
                if (!str_starts_with($url, $config['issuer'] . '/')) {
                    throw new RuntimeException('Untrusted provider request.');
                }
                $url = $backchannel . substr($url, strlen($config['issuer']));
            }
            $args = array_merge($args, ['method' => $method, 'timeout' => 15, 'redirection' => 0,
                'sslverify' => true, 'limit_response_size' => 262144, 'cookies' => []]);
            $args['headers'] = array_merge($args['headers'] ?? [], ['Accept' => 'application/json']);
            // URLs come only from privileged configuration and validated same-issuer discovery.
            $response = wp_remote_request($url, $args);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                throw new RuntimeException('Provider request failed.');
            }
            $body = json_decode(wp_remote_retrieve_body($response), true, 64, JSON_THROW_ON_ERROR);
            if (!is_array($body)) { throw new RuntimeException('Invalid provider response.'); }
            return $body;
        });
    }

    public function menu(): void
    {
        add_options_page('OpenID Connect', 'OpenID Connect', 'manage_options', 'openid-connect', [$this, 'page']);
    }

    public function settings(): void
    {
        register_setting('openid_connect', self::OPTION, ['type' => 'array', 'sanitize_callback' => [$this, 'sanitize']]);
    }

    public function sanitize(mixed $input): array
    {
        $input = is_array($input) ? $input : [];
        $result = [];
        foreach (['enabled', 'public_flow', 'enforce_sso', 'provider_logout', 'provision', 'sync_roles', 'allow_admin', 'allow_http'] as $key) {
            $result[$key] = !empty($input[$key]);
        }
        $result['issuer'] = rtrim(trim(is_string($input['issuer'] ?? null) ? $input['issuer'] : ''), '/');
        $result['client_id'] = trim(is_string($input['client_id'] ?? null) ? $input['client_id'] : 'wordpress');
        $local = $result['allow_http'] && in_array(wp_get_environment_type(), ['local', 'development'], true);
        if ($result['issuer'] !== '' && (!Protocol::validUrl($result['issuer'], $local) || str_contains($result['issuer'], '?'))) {
            add_settings_error(self::OPTION, 'issuer', 'Use a valid HTTPS issuer URL. HTTP requires a development environment and the development checkbox.');
            return $this->options();
        }
        if ($result['client_id'] === '' || strlen($result['client_id']) > 255 || preg_match('/[\x00-\x1f\x7f]/', $result['client_id'])) {
            add_settings_error(self::OPTION, 'client', 'Enter a valid client ID.');
            return $this->options();
        }
        $result['backchannel_issuer'] = rtrim(trim(is_string($input['backchannel_issuer'] ?? null) ? $input['backchannel_issuer'] : ''), '/');
        $result['group_root'] = trim(is_string($input['group_root'] ?? null) ? $input['group_root'] : '/wordpress');
        $result['login_label'] = sanitize_text_field(is_string($input['login_label'] ?? null) ? $input['login_label'] : 'Sign in with OpenID Connect');
        if ($result['login_label'] === '') { $result['login_label'] = 'Sign in with OpenID Connect'; }
        if (($result['backchannel_issuer'] !== '' && (!Protocol::validUrl($result['backchannel_issuer'], $local) || str_contains($result['backchannel_issuer'], '?')))
            || !preg_match('~^/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$~D', $result['group_root'])) {
            add_settings_error(self::OPTION, 'advanced', 'Enter a valid backchannel issuer and absolute group root.');
            return $this->options();
        }
        $result['account_url'] = trim(is_string($input['account_url'] ?? null) ? $input['account_url'] : '');
        $result['provider_account_url'] = trim(is_string($input['provider_account_url'] ?? null) ? $input['provider_account_url'] : '');
        if (($result['account_url'] !== '' && AccountFlow::localReturn($result['account_url'], home_url('/'), '') === '')
            || ($result['provider_account_url'] !== '' && (!Protocol::validUrl($result['provider_account_url'], $local) || !str_starts_with($result['provider_account_url'], $result['issuer'] . '/')))) {
            add_settings_error(self::OPTION, 'account_urls', 'Use a same-site account page URL and an account-management URL within the configured issuer.');
            return $this->options();
        }
        return $result;
    }

    public function page(): void
    {
        if (!current_user_can('manage_options')) { return; }
        $o = $this->options();
        echo '<div class="wrap"><h1>OpenID Connect</h1><p>Connect WordPress to your existing identity provider. Normal WordPress login stays available.</p>';
        if (is_multisite()) { echo '<div class="notice notice-error"><p>This version supports single-site WordPress only.</p></div>'; }
        echo '<p><strong>Exact callback URL:</strong> <code>' . esc_html(self::callbackUrl()) . '</code></p>';
        echo '<p><strong>Exact logout return URL:</strong> <code>' . esc_html(self::logoutReturnUrl()) . '</code> — add this to the Keycloak client’s Valid Post Logout Redirect URIs before enabling provider logout.</p>';
        echo '<p>Group root: <code>' . esc_html(defined('OPENID_CONNECT_GROUP_ROOT') ? (string) OPENID_CONNECT_GROUP_ROOT : $o['group_root']) . '</code></p>';
        $hasSecret = defined('OPENID_CONNECT_CLIENT_SECRET') ? (string) OPENID_CONNECT_CLIENT_SECRET !== '' : (bool) getenv('OPENID_CONNECT_CLIENT_SECRET');
        echo '<p>Client secret: <strong>' . ($hasSecret ? 'supplied externally' : 'not supplied') . '</strong>. Set <code>OPENID_CONNECT_CLIENT_SECRET</code> in the server environment or wp-config.php. It is never saved in this form.</p>';
        settings_errors(self::OPTION);
        echo '<form method="post" action="options.php">';
        settings_fields('openid_connect');
        echo '<table class="form-table" role="presentation">';
        foreach (['issuer' => 'Issuer URL', 'client_id' => 'Client ID', 'backchannel_issuer' => 'Backchannel issuer (optional)', 'group_root' => 'Group root', 'login_label' => 'Login button label', 'account_url' => 'WordPress account page URL', 'provider_account_url' => 'Provider account URL (optional)'] as $key => $label) {
            echo '<tr><th scope="row"><label for="bo-' . esc_attr($key) . '">' . esc_html($label) . '</label></th><td><input class="regular-text" id="bo-' . esc_attr($key) . '" name="openid_connect[' . esc_attr($key) . ']" type="text" value="' . esc_attr($o[$key]) . '"></td></tr>';
        }
        $fields = [
            'enabled' => ['Enable OIDC login', 'Show the configured sign-in button on the login page.'],
            'public_flow' => ['Public account flow', 'Use provider sign-in for public registration and password recovery. Local account recovery remains available.'],
            'enforce_sso' => ['Enforce SSO for managed accounts', 'Block local passwords, password resets, application passwords and unmarked sessions for OIDC-managed users. Unmanaged local accounts keep their existing authentication. Enabling this signs managed users out once.'],
            'provider_logout' => ['Log out of Keycloak', 'After an OpenID Connect sign-in, WordPress logout also opens Keycloak logout. Keycloak may ask you to confirm; other applications using that SSO session may be signed out too.'],
            'provision' => ['Create new accounts', 'Create a subscriber after a verified email is received. Existing email addresses are never linked automatically.'],
            'sync_roles' => ['Use WordPress groups', 'Set the highest allowed role from exact configured group paths at each login, for accounts created by this plugin only. No allowed group means login is denied.'],
            'allow_admin' => ['Allow administrator group', 'Allow the configured administrator group to grant full WordPress administrator access when group roles are enabled.'],
            'allow_http' => ['Allow development HTTP', 'Only effective when WP_ENVIRONMENT_TYPE is local or development. Leave off for production.'],
        ];
        foreach ($fields as $key => [$label, $description]) {
            echo '<tr><th scope="row">' . esc_html($label) . '</th><td><label><input type="checkbox" name="openid_connect[' . esc_attr($key) . ']" value="1" ' . checked(!empty($o[$key]), true, false) . '> ' . esc_html($description) . '</label></td></tr>';
        }
        echo '</table><p>Place <code>[openid_connect_account]</code> on your account page and <code>[openid_connect_link]</code> in a header or content block. Leave the provider account URL blank to use the issuer’s account console.</p>';
        submit_button();
        echo '</form><p>Provider logout is optional and applies only to sessions signed in through this plugin. Local WordPress logins remain local. Existing-account linking is not included.</p></div>';
    }

    public function button(): void
    {
        try { $config = $this->config(); } catch (Throwable) { return; }
        echo '<p style="margin:16px 0"><a class="button button-secondary" href="' . esc_url(add_query_arg('action', 'openid_connect', site_url('wp-login.php', 'login'))) . '">' . esc_html($config['login_label']) . '</a></p>';
    }

    private function cookie(string $value, int $expires): void
    {
        if (!setcookie(self::COOKIE, $value, ['expires' => $expires, 'path' => '/',
            'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax'])) {
            throw new RuntimeException('Unable to set login cookie.');
        }
    }

    public function begin(): void
    {
        try {
            $config = $this->config();
            if (is_user_logged_in()) { wp_safe_redirect($this->flow()->destination(wp_get_current_user(), '')); exit; }
            nocache_headers();
            header('Referrer-Policy: no-referrer');
            $protocol = $this->protocol($config);
            $discovery = $protocol->discovery();
            $state = bin2hex(random_bytes(32));
            $browser = bin2hex(random_bytes(32));
            $nonce = bin2hex(random_bytes(32));
            $verifier = Protocol::base64url(random_bytes(32));
            $returnTo = isset($_GET['redirect_to']) && is_string($_GET['redirect_to']) ? AccountFlow::localReturn(wp_unslash($_GET['redirect_to']), home_url('/'), '') : '';
            $stateKey = 'openid_connect_state_' . hash('sha256', $state);
            $stored = add_option($stateKey, [
                'browser' => hash('sha256', $browser), 'nonce' => $nonce, 'verifier' => $verifier,
                'issuer' => $config['issuer'], 'client_id' => $config['client_id'],
                'redirect_uri' => $config['redirect_uri'], 'return_to' => $returnTo, 'expires' => time() + 600,
            ], '', false);
            if (!$stored) { throw new RuntimeException('Unable to save login transaction.'); }
            wp_schedule_single_event(time() + 660, 'openid_connect_expire_lock', [$stateKey]);
            $this->cookie($browser, time() + 600);
            // Intentional external redirect to the validated provider authorization endpoint.
            wp_redirect($protocol->authorizationUrl($discovery, $state, $nonce, $verifier), 302, 'OpenID Connect');
            exit;
        } catch (Throwable) { $this->failure(); }
    }

    /** An atomic option claim makes a state one-use even with concurrent callbacks. */
    private function claim(string $name, int $seconds): void
    {
        if (!add_option($name, time() + $seconds, '', false)) {
            throw new RuntimeException('Transaction already used or in progress.');
        }
        wp_schedule_single_event(time() + $seconds, 'openid_connect_expire_lock', [$name]);
    }

    public function callback(): void
    {
        try {
            nocache_headers();
            header('Referrer-Policy: no-referrer');
            $config = $this->config();
            if (is_user_logged_in()) { throw new RuntimeException('Already signed in.'); }
            $state = isset($_GET['state']) && is_string($_GET['state']) ? wp_unslash($_GET['state']) : '';
            $browser = isset($_COOKIE[self::COOKIE]) && is_string($_COOKIE[self::COOKIE]) ? wp_unslash($_COOKIE[self::COOKIE]) : '';
            $saved = $this->consumeState($state, $browser, $config);
            $this->cookie('', time() - 3600);
            $code = isset($_GET['code']) && is_string($_GET['code']) ? wp_unslash($_GET['code']) : '';
            if (isset($_GET['error']) || $code === '' || strlen($code) > 8192) {
                throw new RuntimeException('Authorization was not completed.');
            }
            $claims = $this->protocol($config)->exchange($code, $saved['verifier'], $saved['nonce']);
            $user = $this->user($claims, $config);
            wp_set_current_user($user->ID);
            $this->setOidcCookie($user->ID, $config);
            do_action('wp_login', $user->user_login, $user);
            wp_safe_redirect($this->flow()->destination($user, is_string($saved['return_to'] ?? null) ? $saved['return_to'] : ''));
            exit;
        } catch (Throwable) { $this->failure(); }
    }

    private function consumeState(string $state, string $browser, array $config): array
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $state) || !preg_match('/^[a-f0-9]{64}$/D', $browser)) {
            throw new RuntimeException('Missing browser-bound login state.');
        }
        $key = 'openid_connect_state_' . hash('sha256', $state);
        $saved = get_option($key);
        if (!is_array($saved) || $saved['expires'] < time()
            || !hash_equals($saved['browser'], hash('sha256', $browser))
            || $saved['issuer'] !== $config['issuer'] || $saved['client_id'] !== $config['client_id']
            || $saved['redirect_uri'] !== $config['redirect_uri']) {
            throw new RuntimeException('Invalid login state.');
        }
        $this->claim('_' . $key, 660);
        delete_option($key);
        wp_clear_scheduled_hook('openid_connect_expire_lock', [$key]);
        return $saved;
    }

    private function user(array $claims, array $config): \WP_User
    {
        $identity = hash('sha256', $config['issuer'] . "\0" . $claims['sub']);
        $role = Protocol::role($claims, (bool) $config['sync_roles'], (bool) $config['allow_admin'], $config['group_root'] ?? '/wordpress');
        if (!get_role($role)) { throw new RuntimeException('Required role is unavailable.'); }
        $lock = '_openid_connect_user_' . $identity;
        $this->claim($lock, 60);
        $emailLock = null;
        try {
            $users = get_users(['meta_key' => '_openid_connect_identity', 'meta_value' => $identity, 'number' => 2]);
            if (count($users) > 1) { throw new RuntimeException('Ambiguous identity.'); }
            if ($users) {
                $user = $users[0];
                if (get_user_meta($user->ID, '_openid_connect_created', true) !== '1') {
                    throw new RuntimeException('Account was not created by this plugin.');
                }
                $this->flow()->syncEmail($user, $claims);
                if ($config['sync_roles']) { $user->set_role($role); }
                return $user;
            }
            if (!$config['provision'] || ($claims['email_verified'] ?? null) !== true
                || !is_string($claims['email'] ?? null) || !is_email($claims['email'])) {
                throw new RuntimeException('New account provisioning is unavailable or email is already registered.');
            }
            $candidateLock = '_openid_connect_email_' . hash('sha256', strtolower($claims['email']));
            $this->claim($candidateLock, 60);
            $emailLock = $candidateLock;
            if (email_exists($claims['email'])) { throw new RuntimeException('Email already belongs to an account.'); }
            $id = wp_insert_user([
                'user_login' => 'oidc_' . substr($identity, 0, 40),
                'user_pass' => wp_generate_password(64, true, true), 'user_email' => $claims['email'],
                'display_name' => sanitize_text_field(is_string($claims['name'] ?? null) ? $claims['name'] : 'Member'),
                'role' => $role, 'meta_input' => ['_openid_connect_identity' => $identity, '_openid_connect_created' => '1'],
            ]);
            if (is_wp_error($id)) { throw new RuntimeException('Could not create account.'); }
            $user = get_user_by('id', $id);
            if (!$user || get_user_meta($id, '_openid_connect_identity', true) !== $identity) {
                throw new RuntimeException('Could not persist identity.');
            }
            return $user;
        } finally {
            if ($emailLock !== null) {
                delete_option($emailLock);
                wp_clear_scheduled_hook('openid_connect_expire_lock', [$emailLock]);
            }
            delete_option($lock);
            wp_clear_scheduled_hook('openid_connect_expire_lock', [$lock]);
        }
    }

    private function setOidcCookie(int $userId, array $config): void
    {
        $marker = static function (array $session, int $id) use ($userId, $config): array {
            if ($id === $userId) {
                $session['openid_connect'] = ['issuer' => $config['issuer'], 'client_id' => $config['client_id']];
            }
            return $session;
        };
        add_filter('attach_session_information', $marker, 10, 2);
        try { wp_set_auth_cookie($userId, false, is_ssl()); }
        finally { remove_filter('attach_session_information', $marker, 10); }
    }

    public function prepareLogout(): void
    {
        $this->providerLogoutUrl = null;
        $this->providerLogoutFailed = false;
        $o = $this->options();
        $nonce = isset($_REQUEST['_wpnonce']) && is_string($_REQUEST['_wpnonce']) ? wp_unslash($_REQUEST['_wpnonce']) : '';
        if (!$o['provider_logout'] || !is_user_logged_in() || !wp_verify_nonce($nonce, 'log-out')) { return; }
        // Read this before WordPress destroys the current session. A local login has no marker.
        $session = \WP_Session_Tokens::get_instance(get_current_user_id())->get(wp_get_session_token());
        $marker = $session['openid_connect'] ?? null;
        if (!is_array($marker)) { return; }
        try {
            $config = $this->config();
            if (($marker['issuer'] ?? null) !== $config['issuer'] || ($marker['client_id'] ?? null) !== $config['client_id']) {
                throw new RuntimeException('Provider configuration changed since sign-in.');
            }
            $this->providerLogoutUrl = $this->protocol($config)->logoutUrl(self::logoutReturnUrl());
        } catch (Throwable) { $this->providerLogoutFailed = true; }
    }

    public function finishLogout(string $redirect, string $requested, $user): string
    {
        if ($this->providerLogoutFailed) {
            return add_query_arg('openid_connect_logout', 'unavailable', self::logoutReturnUrl());
        }
        if ($this->providerLogoutUrl !== null) {
            // Core already verified its logout nonce and destroyed the WordPress session.
            nocache_headers();
            header('Referrer-Policy: no-referrer');
            wp_redirect($this->providerLogoutUrl, 302, 'OpenID Connect');
            exit;
        }
        return $redirect;
    }

    public function logoutMessage(string $message): string
    {
        if (isset($_GET['openid_connect_logout']) && $_GET['openid_connect_logout'] === 'unavailable') {
            $message .= '<p class="message">You are logged out of WordPress. Keycloak logout could not be started; your Keycloak session may still be active.</p>';
        }
        return $message;
    }

    private function failure(): never
    {
        // No token, code, secret, email, or provider error body enters logs or HTML.
        wp_die('Sign-in could not be completed. Please start again, or contact the site administrator. Normal WordPress login remains available.',
            'OpenID Connect', ['response' => 403, 'back_link' => true]);
        exit;
    }
}
