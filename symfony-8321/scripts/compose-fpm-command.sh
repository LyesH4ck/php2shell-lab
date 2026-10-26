#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose_file="$bundle_dir/docker-compose.fpm.yml"

if docker compose version >/dev/null 2>&1; then
    exec docker compose -p php2shell_fpm_fpm_8321_lab -f "$compose_file" "$@"
fi

exec docker-compose -p php2shell_fpm_fpm_8321_lab -f "$compose_file" "$@"
