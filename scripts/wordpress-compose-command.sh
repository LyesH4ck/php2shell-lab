#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose_file="$bundle_dir/docker-compose.wordpress.yml"
project=php2shell_wordpress_lab

[ -f "$compose_file" ] || {
    echo "Missing WordPress Compose file: $compose_file" >&2
    exit 1
}

cd "$bundle_dir"

if command -v docker-compose >/dev/null 2>&1; then
    exec docker-compose -f "$compose_file" -p "$project" "$@"
fi

if docker compose version >/dev/null 2>&1; then
    exec docker compose -f "$compose_file" -p "$project" "$@"
fi

echo "Docker Compose is required (docker-compose or docker compose)." >&2
exit 127
