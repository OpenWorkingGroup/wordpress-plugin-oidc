<?php
namespace OpenIDConnect;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use RuntimeException;

/** Small, deliberately strict OIDC authorization-code / RS256 profile. */
final class Protocol
{
    public function __construct(private array $config, private \Closure $http) {}

    public static function base64url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public static function validUrl(string $value, bool $allowHttp): bool
    {
        $p = parse_url($value);
        return is_array($p) && !empty($p['host']) && !isset($p['user']) && !isset($p['pass']) && !isset($p['fragment'])
            && !preg_match('/[\s\\\\*]/', $value)
            && (isset($p['scheme']) && ($p['scheme'] === 'https' || ($allowHttp && $p['scheme'] === 'http')));
    }

    public function discovery(): array
    {
        $issuer = $this->config['issuer'];
        if (!self::validUrl($issuer, $this->config['allow_http']) || str_contains($issuer, '?')) {
            throw new RuntimeException('Invalid issuer configuration.');
        }
        $d = ($this->http)('GET', $issuer . '/.well-known/openid-configuration', []);
        if (($d['issuer'] ?? null) !== $issuer
            || !in_array('code', $d['response_types_supported'] ?? [], true)
            || !in_array('S256', $d['code_challenge_methods_supported'] ?? [], true)
            || !in_array('RS256', $d['id_token_signing_alg_values_supported'] ?? [], true)
            || !in_array('client_secret_basic', $d['token_endpoint_auth_methods_supported'] ?? [], true)) {
            throw new RuntimeException('Provider does not support the required OIDC profile.');
        }
        // Keycloak may advertise internal token/JWKS URLs to backchannel callers.
        // Trust only the explicitly configured alias, normalize it, then apply the same boundary checks.
        $backchannel = $this->config['backchannel_issuer'] ?? '';
        if ($backchannel !== '') {
            if (!self::validUrl($backchannel, $this->config['allow_http']) || str_contains($backchannel, '?')) {
                throw new RuntimeException('Invalid backchannel issuer.');
            }
            foreach (['token_endpoint', 'jwks_uri', 'end_session_endpoint'] as $field) {
                if (is_string($d[$field] ?? null) && str_starts_with($d[$field], $backchannel . '/')) {
                    $d[$field] = $issuer . substr($d[$field], strlen($backchannel));
                }
            }
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            // This Keycloak-oriented profile keeps endpoints within the configured issuer path.
            if (!is_string($d[$field] ?? null) || !self::validUrl($d[$field], $this->config['allow_http'])
                || !str_starts_with($d[$field], $issuer . '/') || str_contains($d[$field], '?')
                || preg_match('/%(?:2e|2f|5c)/i', $d[$field])
                || preg_match('~(?:/|%2f)(?:\.{1,2}|%2e)(?:/|%2f|$)~i', $d[$field])) {
                throw new RuntimeException('Provider endpoint is outside the trusted issuer.');
            }
        }
        return $d;
    }

    public function logoutUrl(string $returnUrl): string
    {
        $d = $this->discovery();
        $endpoint = $d['end_session_endpoint'] ?? '';
        if (!is_string($endpoint) || !self::validUrl($endpoint, $this->config['allow_http'])
            || !str_starts_with($endpoint, $this->config['issuer'] . '/')
            || str_contains($endpoint, '?') || preg_match('~/(?:\.{1,2})(?:/|$)|%(?:2e|2f|5c)~i', $endpoint)
            || !self::validUrl($returnUrl, $this->config['allow_http'])) {
            throw new RuntimeException('Provider logout endpoint or return URL is invalid.');
        }
        // No ID/access tokens are retained or placed in the browser URL. Keycloak may ask for confirmation.
        return $endpoint . '?' . http_build_query([
            'client_id' => $this->config['client_id'], 'post_logout_redirect_uri' => $returnUrl,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function authorizationUrl(array $d, string $state, string $nonce, string $verifier): string
    {
        return $d['authorization_endpoint'] . '?' . http_build_query([
            'client_id' => $this->config['client_id'], 'redirect_uri' => $this->config['redirect_uri'],
            'response_type' => 'code', 'scope' => 'openid profile email', 'state' => $state,
            'nonce' => $nonce, 'code_challenge' => self::base64url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256', 'response_mode' => 'query',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function exchange(string $code, string $verifier, string $nonce): array
    {
        $d = $this->discovery();
        $token = ($this->http)('POST', $d['token_endpoint'], [
            'headers' => ['Authorization' => 'Basic ' . base64_encode(
                urlencode($this->config['client_id']) . ':' . urlencode($this->config['secret'])
            )],
            'body' => ['grant_type' => 'authorization_code', 'code' => $code,
                'redirect_uri' => $this->config['redirect_uri'], 'code_verifier' => $verifier],
        ]);
        if (!is_string($token['id_token'] ?? null) || !is_string($token['access_token'] ?? null)
            || strcasecmp($token['token_type'] ?? '', 'Bearer') !== 0) {
            throw new RuntimeException('Provider did not return the required tokens.');
        }
        $jwks = ($this->http)('GET', $d['jwks_uri'], []);
        return $this->verify($token['id_token'], $jwks, $nonce, $token['access_token'], $code);
    }

    public function verify(string $token, array $jwks, string $nonce, string $accessToken, string $code): array
    {
        if (strlen($token) > 65536 || count(explode('.', $token)) !== 3) {
            throw new RuntimeException('Malformed ID token.');
        }
        $header = json_decode(JWT::urlsafeB64Decode(explode('.', $token)[0]), true, 16, JSON_THROW_ON_ERROR);
        if (($header['alg'] ?? null) !== 'RS256' || !is_string($header['kid'] ?? null)
            || $header['kid'] === '' || isset($header['crit'])) {
            throw new RuntimeException('Unsupported signing algorithm or key.');
        }
        $keys = [];
        foreach ($jwks['keys'] ?? [] as $key) {
            if (($key['kty'] ?? '') === 'RSA' && ($key['alg'] ?? 'RS256') === 'RS256'
                && ($key['use'] ?? 'sig') === 'sig' && ($key['kid'] ?? null) === $header['kid']
                && (!isset($key['key_ops']) || in_array('verify', $key['key_ops'], true))) {
                $keys[] = $key;
            }
        }
        if (count($keys) !== 1) {
            throw new RuntimeException('Signing key is missing or ambiguous.');
        }
        $claims = (array) JWT::decode($token, JWK::parseKeySet(['keys' => $keys], 'RS256'));
        $aud = $claims['aud'] ?? null;
        $aud = is_string($aud) ? [$aud] : $aud;
        $now = time();
        if (($claims['iss'] ?? null) !== $this->config['issuer']
            || $aud !== [$this->config['client_id']]
            || (isset($claims['azp']) && $claims['azp'] !== $this->config['client_id'])
            || !is_string($claims['sub'] ?? null) || $claims['sub'] === '' || strlen($claims['sub']) > 255
            || !is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce'])
            || !is_int($claims['exp'] ?? null) || $claims['exp'] <= $now
            || !is_int($claims['iat'] ?? null) || $claims['iat'] > $now + 60 || $claims['iat'] < $now - 600
            || (isset($claims['nbf']) && (!is_int($claims['nbf']) || $claims['nbf'] > $now + 60))) {
            throw new RuntimeException('ID token claims did not validate.');
        }
        foreach (['at_hash' => $accessToken, 'c_hash' => $code] as $claim => $value) {
            if (isset($claims[$claim]) && (!is_string($claims[$claim])
                || !hash_equals(self::base64url(substr(hash('sha256', $value, true), 0, 16)), $claims[$claim]))) {
                throw new RuntimeException('Token hash did not validate.');
            }
        }
        return $claims;
    }

    public static function role(array $claims, bool $sync, bool $allowAdmin, string $groupRoot = '/wordpress'): string
    {
        if (!preg_match('~^/[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$~D', $groupRoot)) {
            throw new RuntimeException('Invalid group root.');
        }
        if (!$sync) {
            return 'subscriber';
        }
        $groups = $claims['groups'] ?? [];
        if (!is_array($groups)) {
            throw new RuntimeException('The groups claim must be an array.');
        }
        $roles = $allowAdmin ? ['administrator', 'editor', 'author', 'contributor', 'subscriber']
            : ['editor', 'author', 'contributor', 'subscriber'];
        foreach ($roles as $role) {
            if (in_array($groupRoot . '/' . $role, $groups, true)) {
                return $role;
            }
        }
        throw new RuntimeException('No permitted WordPress group.');
    }
}
