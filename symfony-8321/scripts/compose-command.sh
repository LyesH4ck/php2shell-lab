#!/bin/sh
set -eu

if docker compose version >/dev/null 2>&1; then
    exec docker compose -p php2shell_symfony_8321_lab -f "$(dirname "$0")/../docker-compose.yml" "$@"
fi

exec docker-compose -p php2shell_symfony_8321_lab -f "$(dirname "$0")/../docker-compose.yml" "$@"
