#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
port=${PHP2SHELL_FPM_ORIGIN_PORT:-9196}
cmd=${1:-id}
artifact_dir="$bundle_dir/artifacts/fpm-4worker-rce"
proof="$artifact_dir/command-output.txt"

case "$port" in
    *[!0-9]*|'') echo "The origin port must be numeric" >&2; exit 2 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 2

live_workers=$(docker top php2shell-fpm-8321 -eo pid,user,comm 2>/dev/null |
    awk '$2 == "www-data" { n++ } END { print n + 0 }')
if [ "$live_workers" -ne 4 ]; then
    echo "Expected four FPM workers, found $live_workers." >&2
    echo "Run ./scripts/up-fpm-4worker-rce.sh first." >&2
    exit 3
fi

exec "$bundle_dir/scripts/test-fpm-multiworker-rce.sh" "$cmd"

