<?php
require __DIR__ . '/../openid-connect/includes/Protocol.php';
require __DIR__ . '/../openid-connect/includes/AccountFlow.php';
require __DIR__ . '/../openid-connect/includes/Plugin.php';
use OpenIDConnect\Plugin;

$options = $users = $meta = $transients = [];
$count = 0;
class WP_User {
    public array $roles;
    public function __construct(public int $ID, public string $user_login, public string $user_email, string $role) { $this->roles = [$role]; }
    public function set_role(string $role): void { $this->roles = [$role]; }
}
function add_option($key, $value, ...$args) { global $options; if (array_key_exists($key, $options)) { return false; } $options[$key] = $value; return true; }
function get_option($key, $default=false) { global $options; return $options[$key] ?? $default; }
function delete_option($key) { global $options; unset($options[$key]); }
function wp_schedule_single_event(...$args) { return true; }
function wp_clear_scheduled_hook(...$args) { return true; }
function get_transient($key) { global $transients; return $options[$key] ?? false; }
function delete_transient($key) { global $transients; unset($options[$key]); }
function get_role($role) { return in_array($role, ['subscriber','contributor','author','editor','administrator'], true); }
function get_users($query) { global $users, $meta; return array_values(array_filter($users, fn($u) => ($meta[$u->ID][$query['meta_key']] ?? '') === $query['meta_value'])); }
function get_user_meta($id, $key, $single) { global $meta; return $meta[$id][$key] ?? ''; }
function is_email($email) { return filter_var($email, FILTER_VALIDATE_EMAIL); }
function email_exists($email) { global $users; foreach ($users as $u) { if (strcasecmp($u->user_email, $email) === 0) { return $u->ID; } } return false; }
function wp_generate_password(...$args) { return bin2hex(random_bytes(32)); }
function sanitize_text_field($s) { return strip_tags($s); }
function wp_insert_user($data) { global $users, $meta; $id = count($users)+1; $users[$id] = new WP_User($id, $data['user_login'], $data['user_email'], $data['role']); $meta[$id] = $data['meta_input']; return $id; }
function is_wp_error($x) { return false; }
function get_user_by($by, $id) { global $users; return $users[$id] ?? false; }
function check($condition, $label) { global $count; if (!$condition) { throw new RuntimeException('FAIL: '.$label); } $count++; }
function rejects(callable $fn, string $label) { try { $fn(); } catch (RuntimeException) { check(true, $label); return; } throw new RuntimeException('FAIL: accepted '.$label); }
$plugin = new Plugin();
$userMethod = new ReflectionMethod($plugin, 'user');
$config = ['issuer' => 'https://id.test/realms/Public', 'provision' => true, 'sync_roles' => false, 'allow_admin' => false];
$claims = ['sub' => 'subject-a', 'email' => 'person@example.test', 'email_verified' => true];
$resolve = fn($c, $o) => $userMethod->invoke($plugin, $c, $o);
rejects(fn() => $resolve($claims, array_merge($config, ['provision' => false])), 'disabled provisioning');
rejects(fn() => $resolve(array_merge($claims, ['email_verified' => false]), $config), 'unverified email');
check(count($users) === 0, 'no users created on rejection');
$u = $resolve($claims, $config);
check($u->roles === ['subscriber'], 'new account is subscriber');
check($resolve($claims, $config)->ID === $u->ID && count($users) === 1, 'stable subject login');
rejects(fn() => $resolve(array_merge($claims, ['sub' => 'attacker']), $config), 'no email auto-link');
rejects(fn() => $resolve($claims, array_merge($config, ['issuer' => 'https://other.test'])), 'issuer-bound identity');
$sync = array_merge($config, ['sync_roles' => true]);
check($resolve(array_merge($claims, ['groups' => ['/wordpress/editor']]), $sync)->roles === ['editor'], 'opt-in role promotion');
check($resolve(array_merge($claims, ['groups' => ['/wordpress/subscriber']]), $sync)->roles === ['subscriber'], 'role demotion');
rejects(fn() => $resolve(array_merge($claims, ['groups' => []]), $sync), 'revoked group denied');
rejects(fn() => $resolve(array_merge($claims, ['groups' => ['/wordpress/administrator']]), $sync), 'admin disabled');
check(count($users) === 1, 'no duplicate users');
$meta[$u->ID]['_openid_connect_created'] = '0';
rejects(fn() => $resolve($claims, $config), 'do not manage external accounts');

$consume = new ReflectionMethod($plugin, 'consumeState');
$state = str_repeat('a', 64); $browser = str_repeat('b', 64);
$key = 'openid_connect_state_' . hash('sha256', $state);
$flowConfig = ['issuer' => 'https://id.test/realms/Public', 'client_id' => 'wordpress', 'redirect_uri' => 'https://wp.test/wp-login.php?action=openid_connect_callback'];
$saved = array_merge($flowConfig, ['browser' => hash('sha256', $browser), 'expires' => time()+600, 'nonce' => 'nonce', 'verifier' => 'verifier']);
$options[$key] = $saved;
$run = fn($s, $b, $c) => $consume->invoke($plugin, $s, $b, $c);
rejects(fn() => $run('bad', $browser, $flowConfig), 'malformed state');
rejects(fn() => $run($state, str_repeat('c', 64), $flowConfig), 'browser binding');
rejects(fn() => $run($state, $browser, array_merge($flowConfig, ['client_id' => 'changed'])), 'configuration binding');
$options[$key]['expires'] = time()-1;
rejects(fn() => $run($state, $browser, $flowConfig), 'expired transaction');
$options[$key] = $saved;
check($run($state, $browser, $flowConfig)['nonce'] === 'nonce', 'valid state consumed');
rejects(fn() => $run($state, $browser, $flowConfig), 'replay rejected');
$options[$key] = $saved; // Simulate a second concurrent request that read a stale transient.
rejects(fn() => $run($state, $browser, $flowConfig), 'atomic replay lock');
function wp_parse_args($value, $defaults) { return array_merge($defaults, is_array($value) ? $value : []); }
function wp_get_environment_type() { return 'local'; }
function add_settings_error(...$args) { $GLOBALS['setting_errors'][] = $args; }
$settings = $plugin->sanitize(['issuer'=>'https://other.example/realms/another','client_id'=>'another-client','group_root'=>'/company','backchannel_issuer'=>'https://internal.example/realms/another','login_label'=>'<b>Company login</b>']);
check($settings['issuer'] === 'https://other.example/realms/another' && $settings['client_id'] === 'another-client', 'generic instance configuration');
check($settings['login_label'] === 'Company login', 'sanitized generic label');
check($settings['group_root'] === '/company' && $settings['backchannel_issuer'] === 'https://internal.example/realms/another', 'editable group and backchannel');
$plugin->sanitize(['issuer'=>'https://id.example/realms/a','group_root'=>'/../root']);
check(!empty($GLOBALS['setting_errors']), 'invalid group root refused in settings');
function add_filter($name,$callback,...$rest) { $GLOBALS['filters'][$name]=$callback; }
function remove_filter($name,$callback,...$rest) { unset($GLOBALS['filters'][$name]); }
function is_ssl() { return false; }
function wp_set_auth_cookie($id,...$args) { $GLOBALS['session']=isset($GLOBALS['filters']['attach_session_information']) ? ($GLOBALS['filters']['attach_session_information'])([], $id) : []; }
function is_user_logged_in() { return true; }
function wp_unslash($s) { return $s; }
function wp_verify_nonce($n,$action) { return $n==='valid' && $action==='log-out'; }
function get_current_user_id() { return 1; }
function wp_get_session_token() { return 'test-session'; }
class WP_Session_Tokens { static function get_instance($id) { return new self(); } function get($token) { return $GLOBALS['session'] ?? []; } }
function site_url($path,$scheme='') { return 'http://127.0.0.1:8090/'.$path; }
function add_query_arg($key,$value,$url) { return $url.(str_contains($url,'?')?'&':'?').urlencode($key).'='.urlencode($value); }
function is_multisite() { return false; }
function wp_remote_request($url,$args) { return $GLOBALS['providerResponse']; }
function wp_remote_retrieve_response_code($r) { return $r['status']; }
function wp_remote_retrieve_body($r) { return json_encode($r['body']); }
define('OPENID_CONNECT_CLIENT_SECRET','unit-test-only');
$logoutConfig=['issuer'=>'https://id.test/realms/Public','client_id'=>'client'];
(new ReflectionMethod($plugin,'setOidcCookie'))->invoke($plugin,1,$logoutConfig);
check($GLOBALS['session']['openid_connect']===$logoutConfig, 'OIDC session tagged without tokens');
check(empty($GLOBALS['filters']), 'session marker filter removed');
$options['openid_connect']=array_merge($logoutConfig,['enabled'=>true,'allow_http'=>true]);
$_REQUEST['_wpnonce']='valid';
$plugin->prepareLogout();
check($plugin->finishLogout('/local','',null)==='/local', 'provider logout off by default');
$options['openid_connect']['provider_logout']=true;
$GLOBALS['session']=[];$plugin->prepareLogout();
check($plugin->finishLogout('/local','',null)==='/local', 'native login stays local');
$GLOBALS['session']=['openid_connect'=>$logoutConfig];$_REQUEST['_wpnonce']='invalid';$plugin->prepareLogout();
check($plugin->finishLogout('/local','',null)==='/local', 'invalid nonce cannot start provider logout');
$_REQUEST['_wpnonce']='valid';
$GLOBALS['providerResponse']=['status'=>503,'body'=>[]];$plugin->prepareLogout();
check(str_contains($plugin->finishLogout('/local','',null),'openid_connect_logout=unavailable'), 'provider outage preserves local logout and warns');
$issuer=$logoutConfig['issuer'];
$GLOBALS['providerResponse']=['status'=>200,'body'=>['issuer'=>$issuer,'response_types_supported'=>['code'],'code_challenge_methods_supported'=>['S256'],'id_token_signing_alg_values_supported'=>['RS256'],'token_endpoint_auth_methods_supported'=>['client_secret_basic'],'authorization_endpoint'=>$issuer.'/auth','token_endpoint'=>$issuer.'/token','jwks_uri'=>$issuer.'/certs','end_session_endpoint'=>$issuer.'/logout']];
$plugin->prepareLogout();
check(str_starts_with((new ReflectionProperty($plugin,'providerLogoutUrl'))->getValue($plugin),$issuer.'/logout?'), 'valid OIDC logout prepared');
$GLOBALS['session']['openid_connect']['client_id']='old-client';$plugin->prepareLogout();
check(str_contains($plugin->finishLogout('/local','',null),'unavailable'), 'changed provider does not log out another session');
echo "WordPress adapter checks passed: $count\n";
