#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
composer install --working-dir=openid-connect --no-dev --prefer-dist --no-interaction --optimize-autoloader
php tests/protocol.php
php tests/wordpress.php
php tests/account-flow.php
find openid-connect -name '*.php' -exec php -l {} \; >/dev/null
mkdir -p dist
archive="dist/openid-connect-0.2.0.zip"
rm -f "$archive"
zip -qr "$archive" openid-connect -x '*/.DS_Store' '*/.git/*'
shasum -a 256 "$archive" > "$archive.sha256"
printf 'Built %s\n' "$archive"
