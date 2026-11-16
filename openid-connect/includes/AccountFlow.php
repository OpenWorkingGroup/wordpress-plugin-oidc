<?php
namespace OpenIDConnect;

/** Frontend UX and SSO policy; no site-specific hosts, realms or user IDs. */
final class AccountFlow
{
    private bool $syncingEmail = false;
    public function __construct(private \Closure $options) {}

    public function register(): void
    {
        add_filter('authenticate', [$this, 'authenticate'], PHP_INT_MAX, 3);
        add_filter('check_password', [$this, 'checkPassword'], PHP_INT_MAX, 4);
        add_filter('allow_password_reset', [$this, 'allowReset'], PHP_INT_MAX, 2);
        add_action('validate_password_reset', [$this, 'validateReset'], 10, 2);
        add_filter('wp_is_application_passwords_available_for_user', [$this, 'applicationPasswords'], PHP_INT_MAX, 2);
        add_filter('show_password_fields', [$this, 'passwordFields'], PHP_INT_MAX, 2);
        add_filter('wp_pre_insert_user_data', [$this, 'protectIdentity'], PHP_INT_MAX, 4);
        add_filter('determine_current_user', [$this, 'sessionUser'], PHP_INT_MAX);
        add_action('update_option_openid_connect', [$this, 'policyChanged'], 10, 2);
        add_filter('pre_option_users_can_register', fn($pre) => $this->publicFlow() ? 0 : $pre);
        add_filter('register_url', [$this, 'registrationUrl']);
        add_filter('lostpassword_url', [$this, 'lostPasswordUrl'], 10, 2);
        add_action('login_form_register', [$this, 'routePublicAuth']);
        add_action('login_form_lostpassword', [$this, 'routePublicAuth']);
        add_action('login_form_retrievepassword', [$this, 'routePublicAuth']);
        add_action('lostpassword_form', [$this, 'recoveryField']);
        add_action('login_form', [$this, 'recoveryLink']);
        add_action('show_user_profile', [$this, 'identityNotice']);
        add_action('edit_user_profile', [$this, 'identityNotice']);
        add_action('template_redirect', [$this, 'accountCache']);
        add_shortcode('openid_connect_account', [$this, 'account']);
        add_shortcode('openid_connect_link', [$this, 'link']);
    }

    public static function managed(int $id): bool
    {
        return $id > 0 && get_user_meta($id, '_openid_connect_created', true) === '1'
            && is_string(get_user_meta($id, '_openid_connect_identity', true))
            && get_user_meta($id, '_openid_connect_identity', true) !== '';
    }

    public function protectedUser(int $id): bool
    {
        return !empty(($this->options)()['enforce_sso']) && self::managed($id);
    }

    public function authenticate($result, string $username, string $password)
    {
        $user = $result instanceof \WP_User ? $result : get_user_by('login', $username);
        if (!$user && is_email($username)) { $user = get_user_by('email', $username); }
        return $user && $this->protectedUser((int) $user->ID)
            ? new \WP_Error('openid_connect_sso_required', 'Use the site sign-in button for this account. Local passwords are not accepted.') : $result;
    }

    public function checkPassword(bool $check, string $password, string $hash, $id): bool
    {
        return $this->protectedUser((int) $id) ? false : $check;
    }
    public function allowReset($allow, int $id) { return $this->protectedUser($id) ? false : $allow; }
    public function validateReset($errors, $user): void
    {
        if ($user instanceof \WP_User && $this->protectedUser((int) $user->ID)) {
            $errors->add('openid_connect_sso_required', 'Reset this account’s password through the identity provider.');
        }
    }
    public function applicationPasswords(bool $available, $user): bool
    {
        return $user instanceof \WP_User && $this->protectedUser((int) $user->ID) ? false : $available;
    }
    public function passwordFields(bool $show, $user): bool { return $this->applicationPasswords($show, $user); }

    public function protectIdentity(array $data, bool $update, $id, array $raw): array
    {
        if (!$update || !$this->protectedUser((int) $id)) { return $data; }
        $old = get_userdata($id);
        if (!$old) { return $data; }
        $data['user_pass'] = $old->user_pass;
        $data['user_activation_key'] = '';
        if (!$this->syncingEmail) { $data['user_email'] = $old->user_email; }
        return $data;
    }

    public function syncEmail(\WP_User $user, array $claims): void
    {
        if (($claims['email_verified'] ?? null) !== true || !is_string($claims['email'] ?? null) || !is_email($claims['email'])) {
            throw new \RuntimeException('A verified provider email is required.');
        }
        if (strcasecmp($user->user_email, $claims['email']) === 0) { return; }
        $owner = email_exists($claims['email']);
        if ($owner && (int) $owner !== (int) $user->ID) { throw new \RuntimeException('Provider email conflicts with another account.'); }
        $this->syncingEmail = true;
        try {
            $result = wp_update_user(['ID' => $user->ID, 'user_email' => $claims['email']]);
            if (is_wp_error($result)) { throw new \RuntimeException('Could not synchronize verified email.'); }
        } finally { $this->syncingEmail = false; }
    }

    public function sessionUser($id)
    {
        if (!$id || !$this->protectedUser((int) $id)) { return $id; }
        $session = \WP_Session_Tokens::get_instance((int) $id)->get(wp_get_session_token());
        $marker = $session['openid_connect'] ?? [];
        $o = ($this->options)();
        return ($marker['issuer'] ?? null) === rtrim($o['issuer'], '/') && ($marker['client_id'] ?? null) === $o['client_id'] ? $id : false;
    }

    public function policyChanged($old, $new): void
    {
        if (empty($new['enforce_sso']) || !empty($old['enforce_sso'])) { return; }
        foreach (get_users(['meta_key' => '_openid_connect_created', 'meta_value' => '1', 'fields' => 'ID']) as $id) {
            if (self::managed((int) $id)) {
                \WP_Session_Tokens::get_instance((int) $id)->destroy_all();
                \WP_Application_Passwords::delete_all_application_passwords((int) $id);
                // Invalidate reset links issued before enforcement.
                global $wpdb;
                $wpdb->update($wpdb->users, ['user_activation_key' => ''], ['ID' => (int) $id]);
                clean_user_cache((int) $id);
            }
        }
    }

    /** Exact-origin check independent of third-party allowed_redirect_hosts filters. */
    public static function localReturn(string $candidate, string $home, string $fallback): string
    {
        if ($candidate === '' || preg_match('/[\x00-\x20\x7f\\\\]|%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)/i', $candidate)) { return $fallback; }
        $base = parse_url($home);
        if (!is_array($base) || !isset($base['scheme'], $base['host'])) { return $fallback; }
        if (str_starts_with($candidate, '//')) { return $fallback; }
        if (str_starts_with($candidate, '/')) {
            $candidate = $base['scheme'] . '://' . $base['host'] . (isset($base['port']) ? ':' . $base['port'] : '') . $candidate;
        }
        $p = parse_url($candidate);
        if (!is_array($p) || isset($p['user']) || isset($p['pass'])
            || ($p['scheme'] ?? '') !== $base['scheme'] || strtolower($p['host'] ?? '') !== strtolower($base['host'])
            || ($p['port'] ?? ($p['scheme'] === 'https' ? 443 : 80)) !== ($base['port'] ?? ($base['scheme'] === 'https' ? 443 : 80))
            || preg_match('~(?:^|/)wp-login\\.php$~i', rawurldecode($p['path'] ?? ''))) { return $fallback; }
        return $candidate;
    }

    public function accountUrl(): string
    {
        return self::localReturn((string) (($this->options)()['account_url'] ?? ''), home_url('/'), home_url('/'));
    }
    public function signInUrl(string $return = ''): string
    {
        $url = add_query_arg('action', 'openid_connect', site_url('wp-login.php', 'login'));
        $return = self::localReturn($return, home_url('/'), '');
        return $return === '' ? $url : add_query_arg('redirect_to', $return, $url);
    }
    public function destination($user, string $requested): string
    {
        $fallback = user_can($user, 'edit_posts') ? admin_url() : $this->accountUrl();
        $result = self::localReturn($requested, home_url('/'), $fallback);
        if (!user_can($user, 'edit_posts') && str_starts_with($result, admin_url())) { return $this->accountUrl(); }
        return $result;
    }
    public function managementUrl(): string
    {
        $o = ($this->options)();
        $url = $o['provider_account_url'] ?: rtrim($o['issuer'], '/') . '/account/';
        $allowHttp = !empty($o['allow_http']) && in_array(wp_get_environment_type(), ['local', 'development'], true);
        if (!Protocol::validUrl($url, $allowHttp) || !str_starts_with($url, rtrim($o['issuer'], '/') . '/')) {
            throw new \RuntimeException('Account management URL must be within the configured issuer.');
        }
        return $url;
    }
    private function publicFlow(): bool
    {
        $o = ($this->options)();
        return !empty($o['enabled']) && !empty($o['public_flow']);
    }
    public function registrationUrl(string $url): string { return $this->publicFlow() ? $this->signInUrl($this->accountUrl()) : $url; }
    public function lostPasswordUrl(string $url, $redirect = ''): string
    {
        if (!$this->publicFlow()) { return $url; }
        return $this->localRecovery() ? add_query_arg('local_recovery', '1', $url) : $this->signInUrl($this->accountUrl());
    }
    private function localRecovery(): bool { return isset($_REQUEST['local_recovery']) && $_REQUEST['local_recovery'] === '1'; }
    public function routePublicAuth(): void
    {
        if ($this->publicFlow() && (($_REQUEST['action'] ?? '') === 'register' || !$this->localRecovery())) { wp_safe_redirect($this->signInUrl($this->accountUrl())); exit; }
        // This bypass selects the native form only; managed-account reset remains blocked.
    }
    public function recoveryField(): void
    {
        if ($this->localRecovery()) { echo '<input type="hidden" name="local_recovery" value="1">'; }
    }
    public function recoveryLink(): void
    {
        if ($this->publicFlow()) {
            echo '<p><a href="' . esc_url(add_query_arg(['action' => 'lostpassword', 'local_recovery' => '1'], site_url('wp-login.php', 'login'))) . '">Local account recovery</a></p>';
        }
    }
    public function identityNotice($user): void
    {
        if ($user instanceof \WP_User && $this->protectedUser((int) $user->ID)) {
            echo '<h2>Sign-in and security</h2><p>Your email, password and authentication methods are managed by your identity provider. Local email/password changes are ignored.</p>';
            try { echo '<p><a href="' . esc_url($this->managementUrl()) . '">Manage sign-in and security</a></p>'; } catch (\Throwable) {}
        }
    }
    public function link($attributes = []): string
    {
        $o = ($this->options)();
        if (empty($o['enabled'])) { return ''; }
        $return = isset($_SERVER['REQUEST_URI']) ? self::localReturn(wp_unslash($_SERVER['REQUEST_URI']), home_url('/'), '') : '';
        $url = is_user_logged_in() ? $this->accountUrl() : $this->signInUrl($return);
        $label = is_user_logged_in() ? 'My account' : (is_array($attributes) && !empty($attributes['label']) ? sanitize_text_field($attributes['label']) : ($o['login_label'] ?: 'Sign in / Create account'));
        return '<a class="openid-connect-account-link" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
    }
    public function accountCache(): void
    {
        if (is_singular() && has_shortcode((string) get_post_field('post_content', get_queried_object_id()), 'openid_connect_account')) {
            nocache_headers();
            if (!defined('DONOTCACHEPAGE')) { define('DONOTCACHEPAGE', true); }
        }
    }

    public function account($attributes = []): string
    {
        if (!headers_sent()) { nocache_headers(); }
        if (!defined('DONOTCACHEPAGE')) { define('DONOTCACHEPAGE', true); }
        if (!is_user_logged_in()) {
            return '<section class="openid-connect-account"><p>Sign in or create an account to manage your profile.</p><p><a class="wp-element-button" href="' . esc_url($this->signInUrl($this->accountUrl())) . '">' . esc_html(($this->options)()['login_label']) . '</a></p><p>Registration, email verification and password recovery take place with the identity provider.</p></section>';
        }
        $user = wp_get_current_user();
        $html = '<section class="openid-connect-account"><h2>Welcome, ' . esc_html($user->display_name) . '</h2>';
        if (self::managed((int) $user->ID)) {
            try { $html .= '<p><a class="wp-element-button" href="' . esc_url($this->managementUrl()) . '">Manage sign-in and security</a></p>'; }
            catch (\Throwable) { $html .= '<p>Contact the site administrator for your account-management link.</p>'; }
            $html .= '<p>Manage your email, password and authentication methods with the identity provider.</p>';
        }
        $html .= '<p><a href="' . esc_url(admin_url('profile.php')) . '">WordPress profile and preferences</a></p>';
        if (user_can($user, 'edit_posts')) { $html .= '<p><a href="' . esc_url(admin_url()) . '">Open dashboard</a></p>'; }
        return $html . '<p><a href="' . esc_url(wp_logout_url($this->accountUrl())) . '">Log out</a></p></section>';
    }
}
