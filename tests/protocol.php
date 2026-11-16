<?php
require __DIR__ . '/../openid-connect/vendor/autoload.php';
require __DIR__ . '/../openid-connect/includes/Protocol.php';
use OpenIDConnect\Protocol;
use Firebase\JWT\JWT;

$count = 0;
function check(bool $condition, string $label): void {
    global $count;
    if (!$condition) { throw new RuntimeException('FAIL: ' . $label); }
    $count++;
}
function rejects(callable $fn, string $label): void {
    try { $fn(); } catch (Throwable) { check(true, $label); return; }
    throw new RuntimeException('FAIL: accepted ' . $label);
}
$config = ['issuer' => 'https://id.example.test/realms/Public', 'client_id' => 'wordpress',
    'secret' => 'test:secret', 'redirect_uri' => 'https://wp.example.test/wp-login.php?action=openid_connect_callback', 'allow_http' => false];
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
openssl_pkey_export($key, $private);
$rsa = openssl_pkey_get_details($key)['rsa'];
$jwks = ['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-key',
    'n' => Protocol::base64url($rsa['n']), 'e' => Protocol::base64url($rsa['e'])]]];
$claims = ['iss' => $config['issuer'], 'aud' => 'wordpress', 'sub' => 'subject-123', 'iat' => time(),
    'exp' => time() + 300, 'nonce' => 'nonce-123', 'email' => 'reader@example.test', 'email_verified' => true,
    'groups' => ['/wordpress/subscriber']];
$sign = fn(array $c) => JWT::encode($c, $private, 'RS256', 'test-key');
$protocol = new Protocol($config, fn() => throw new RuntimeException('Unexpected HTTP'));
check($protocol->verify($sign($claims), $jwks, 'nonce-123', 'access', 'code')['sub'] === 'subject-123', 'valid signed token');
foreach (['iss' => 'https://evil.test', 'aud' => 'other-client', 'nonce' => 'wrong', 'azp' => 'other-client',
          'exp' => time() - 10, 'iat' => time() - 1000, 'sub' => '', 'nbf' => time() + 3600,
          'at_hash' => 'bad', 'c_hash' => 'bad'] as $field => $value) {
    rejects(fn() => $protocol->verify($sign(array_merge($claims, [$field => $value])), $jwks, 'nonce-123', 'access', 'code'), $field);
}
rejects(fn() => $protocol->verify($sign(array_diff_key($claims, ['exp' => 1])), $jwks, 'nonce-123', 'access', 'code'), 'missing exp');
rejects(fn() => $protocol->verify($sign(array_merge($claims, ['aud' => ['wordpress', 'other']])), $jwks, 'nonce-123', 'access', 'code'), 'extra audience');
$parts = explode('.', $sign($claims));
$parts[1] = Protocol::base64url(json_encode(array_merge($claims, ['sub' => 'attacker'])));
rejects(fn() => $protocol->verify(implode('.', $parts), $jwks, 'nonce-123', 'access', 'code'), 'tampered signature');
rejects(fn() => $protocol->verify(JWT::encode($claims, str_repeat('x', 64), 'HS256', 'test-key'), $jwks, 'nonce-123', 'access', 'code'), 'algorithm substitution');
rejects(fn() => $protocol->verify($sign($claims), ['keys' => []], 'nonce-123', 'access', 'code'), 'unknown signing key');
$hashes = $claims;
$hashes['at_hash'] = Protocol::base64url(substr(hash('sha256', 'access', true), 0, 16));
$hashes['c_hash'] = Protocol::base64url(substr(hash('sha256', 'code', true), 0, 16));
check($protocol->verify($sign($hashes), $jwks, 'nonce-123', 'access', 'code')['sub'] === 'subject-123', 'valid token hashes');
check(Protocol::role($claims, true, false) === 'subscriber', 'exact group mapping');
rejects(fn() => Protocol::role(['groups' => ['/wordpress/administrator']], true, false), 'administrator opt-in');
check(Protocol::role(['groups' => ['/wordpress/administrator']], true, true) === 'administrator', 'explicit administrator opt-in');
check(Protocol::role(['groups' => ['/wordpress/subscriber', '/wordpress/editor']], true, false) === 'editor', 'role precedence');
rejects(fn() => Protocol::role(['groups' => ['/other/editor', '/wordpress/editor/child']], true, false), 'no fuzzy group mapping');
check(Protocol::role([], false, true) === 'subscriber', 'default role');
check(!Protocol::validUrl('http://localhost:8180', false), 'HTTP denied by default');
check(Protocol::validUrl('http://localhost:8180', true), 'explicit development HTTP');
check(!Protocol::validUrl('https://user:secret@example.test', false), 'URL credentials rejected');

$d = ['issuer' => $config['issuer'], 'authorization_endpoint' => $config['issuer'] . '/protocol/openid-connect/auth',
    'token_endpoint' => $config['issuer'] . '/protocol/openid-connect/token', 'jwks_uri' => $config['issuer'] . '/protocol/openid-connect/certs',
    'response_types_supported' => ['code'], 'code_challenge_methods_supported' => ['S256'],
    'id_token_signing_alg_values_supported' => ['RS256'], 'token_endpoint_auth_methods_supported' => ['client_secret_basic']];
$requests = [];
$flow = new Protocol($config, function ($method, $url, $args) use (&$requests, $d, $jwks, $sign, $claims) {
    $requests[] = [$method, $url, $args];
    if (str_ends_with($url, 'openid-configuration')) { return $d; }
    if ($url === $d['jwks_uri']) { return $jwks; }
    if ($url === $d['token_endpoint']) { return ['id_token' => $sign($claims), 'access_token' => 'access', 'token_type' => 'Bearer']; }
    throw new RuntimeException('Unexpected endpoint');
});
parse_str(parse_url($flow->authorizationUrl($flow->discovery(), 'state', 'nonce-123', str_repeat('v', 43)), PHP_URL_QUERY), $query);
check($query['code_challenge_method'] === 'S256' && $query['code_challenge'] === Protocol::base64url(hash('sha256', str_repeat('v', 43), true)), 'PKCE challenge');
check($query['redirect_uri'] === $config['redirect_uri'] && $query['state'] === 'state', 'exact callback and state');
check($flow->exchange('code', str_repeat('v', 43), 'nonce-123')['sub'] === 'subject-123', 'full exchange');
check($requests[2][2]['body']['code_verifier'] === str_repeat('v', 43), 'PKCE verifier sent');
check($requests[2][2]['headers']['Authorization'] === 'Basic ' . base64_encode('wordpress:test%3Asecret'), 'client authentication');
$bad = $d; $bad['token_endpoint'] = 'https://evil.test/token';
rejects(fn() => (new Protocol($config, fn() => $bad))->discovery(), 'foreign discovery endpoint');
$bad = $d; $bad['issuer'] = 'https://evil.test';
rejects(fn() => (new Protocol($config, fn() => $bad))->discovery(), 'discovery issuer mismatch');
check(Protocol::role(['groups' => ['/syvlocal.com/editor']], true, false, '/syvlocal.com') === 'editor', 'configured group root');
rejects(fn() => Protocol::role(['groups' => ['/wordpress/editor']], true, false, '/syvlocal.com'), 'other root denied');
rejects(fn() => Protocol::role([], true, false, '/bad/../root'), 'invalid group root');
$internal = $d;
$internal['token_endpoint'] = 'https://internal.test/realms/Public/protocol/openid-connect/token';
$internal['jwks_uri'] = 'https://internal.test/realms/Public/protocol/openid-connect/certs';
$internalConfig = array_merge($config, ['backchannel_issuer' => 'https://internal.test/realms/Public']);
check((new Protocol($internalConfig, fn() => $internal))->discovery()['token_endpoint'] === $d['token_endpoint'], 'explicit internal discovery alias');
rejects(fn() => (new Protocol($config, fn() => $internal))->discovery(), 'unconfigured internal discovery alias');
$foreign = $internal; $foreign['jwks_uri'] = 'https://unknown.test/certs';
rejects(fn() => (new Protocol($internalConfig, fn() => $foreign))->discovery(), 'foreign endpoint still denied with alias');
$logoutDiscovery = $d; $logoutDiscovery['end_session_endpoint'] = $config['issuer'].'/protocol/openid-connect/logout';
$returnUrl = 'https://wp.example.test/wp-login.php?loggedout=true';
$logout = new Protocol($config, fn() => $logoutDiscovery);
parse_str(parse_url($logout->logoutUrl($returnUrl), PHP_URL_QUERY), $logoutQuery);
check($logoutQuery === ['client_id'=>'wordpress','post_logout_redirect_uri'=>$returnUrl], 'token-free exact logout request');
rejects(fn() => (new Protocol($config, fn() => $d))->logoutUrl($returnUrl), 'missing logout endpoint');
$maliciousLogout=$logoutDiscovery; $maliciousLogout['end_session_endpoint']='https://evil.test/logout';
rejects(fn() => (new Protocol($config, fn() => $maliciousLogout))->logoutUrl($returnUrl), 'foreign logout endpoint');
$maliciousLogout['end_session_endpoint']=$config['issuer'].'/../logout';
rejects(fn() => (new Protocol($config, fn() => $maliciousLogout))->logoutUrl($returnUrl), 'logout path traversal');
$internalLogout=$internal; $internalLogout['end_session_endpoint']='https://internal.test/realms/Public/protocol/openid-connect/logout';
check(str_starts_with((new Protocol($internalConfig, fn() => $internalLogout))->logoutUrl($returnUrl), $config['issuer'].'/'), 'logout uses public browser endpoint');
echo "Protocol checks passed: $count\n";
