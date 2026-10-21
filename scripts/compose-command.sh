#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$bundle_dir"

if command -v docker-compose >/dev/null 2>&1; then
    exec docker-compose "$@"
fi

if docker compose version >/dev/null 2>&1; then
    exec docker compose "$@"
fi

echo "Docker Compose is required (docker-compose or docker compose)." >&2
exit 127

