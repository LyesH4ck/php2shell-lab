#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
blocked_port=${PHP2SHELL_FPM_BLOCKED_PORT:-9195}
origin_port=${PHP2SHELL_FPM_ORIGIN_PORT:-9196}

for value in "$blocked_port" "$origin_port"; do
    case "$value" in
        *[!0-9]*|'') echo "Invalid TCP port: $value" >&2; exit 2 ;;
    esac
    [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || {
        echo "TCP port must be in 1..65535: $value" >&2
        exit 2
    }
done
[ "$blocked_port" -ne "$origin_port" ] || {
    echo "Blocked and origin ports must differ" >&2
    exit 2
}

[ "$(uname -m)" = x86_64 ] || {
    echo "This calibrated lab requires a native x86_64 host" >&2
    exit 3
}
case "$(docker info --format '{{.Architecture}}')" in
    x86_64|amd64) ;;
    *) echo "Docker is not native amd64" >&2; exit 3 ;;
esac

export PHP2SHELL_FPM_BLOCKED_PORT=$blocked_port
export PHP2SHELL_FPM_ORIGIN_PORT=$origin_port
"$bundle_dir/scripts/compose-fpm-command.sh" build fpm-target
"$bundle_dir/scripts/compose-fpm-command.sh" down --remove-orphans >/dev/null 2>&1 || true
"$bundle_dir/scripts/compose-fpm-command.sh" up -d fpm-target nginx

attempt=0
until "$bundle_dir/scripts/verify-fpm.sh"; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 20 ] || exit 1
    sleep 1
done
