<?php
/**
 * Plugin Name: OpenID Connect
 * Description: Simple OpenID Connect login for WordPress, with PKCE and optional Keycloak group roles.
 * Version: 0.2.0
 * Author: Byteable
 * Requires at least: 6.6
 * Requires PHP: 8.2
 * License: GPL-2.0-or-later
 * Text Domain: openid-connect
 */
if (!defined('ABSPATH')) { exit; }

if (!is_readable(__DIR__ . '/vendor/autoload.php') || !extension_loaded('openssl')) {
    add_action('admin_notices', static function () {
        echo '<div class="notice notice-error"><p>OpenID Connect requires its packaged dependencies and PHP OpenSSL.</p></div>';
    });
    return;
}
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/includes/Protocol.php';
require_once __DIR__ . '/includes/AccountFlow.php';
require_once __DIR__ . '/includes/Plugin.php';
(new \OpenIDConnect\Plugin())->register();
