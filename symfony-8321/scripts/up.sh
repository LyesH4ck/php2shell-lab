#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
port=${PHP2SHELL_SYMFONY_8321_PORT:-9094}
workers=${PHP2SHELL_APACHE_WORKERS:-4}

case "$port" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_SYMFONY_8321_PORT: $port" >&2; exit 2 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || {
    echo "Port must be in 1..65535" >&2
    exit 2
}

case "$workers" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_APACHE_WORKERS: $workers" >&2; exit 2 ;;
esac
[ "$workers" -ge 1 ] && [ "$workers" -le 16 ] || {
    echo "PHP2SHELL_APACHE_WORKERS must be in 1..16" >&2
    exit 2
}

[ "$(uname -m)" = x86_64 ] || {
    echo "This profile requires a native x86_64 host." >&2
    exit 3
}
case "$(docker info --format '{{.Architecture}}')" in
    x86_64|amd64) ;;
    *) echo "Docker is not native amd64." >&2; exit 3 ;;
esac

export PHP2SHELL_SYMFONY_8321_PORT=$port
export PHP2SHELL_APACHE_WORKERS=$workers
"$bundle_dir/scripts/compose-command.sh" build target
"$bundle_dir/scripts/compose-command.sh" down --remove-orphans >/dev/null 2>&1 || true
"$bundle_dir/scripts/compose-command.sh" up -d target relay
"$bundle_dir/scripts/verify.sh"
