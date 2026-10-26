#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
base="$bundle_dir/docker-compose.fpm.yml"
override="$bundle_dir/docker-compose.fpm-4worker-rce.yml"

if docker compose version >/dev/null 2>&1; then
    compose="docker compose"
else
    compose="docker-compose"
fi

# shellcheck disable=SC2086
$compose -p php2shell_fpm_fpm_8321_lab -f "$base" -f "$override" \
    up -d --force-recreate fpm-target nginx

i=0
while [ "$i" -lt 60 ]; do
    workers=$(docker top php2shell-fpm-8321 -eo pid,user,comm 2>/dev/null |
        awk '$2 == "www-data" { n++ } END { print n + 0 }')
    if [ "$workers" -eq 4 ] && \
       curl -fsS --max-time 2 \
           "http://127.0.0.1:${PHP2SHELL_FPM_ORIGIN_PORT:-9196}/plain.php" |
           grep -qx OK; then
        echo "FPM four-worker RCE profile ready: loopback only"
        exit 0
    fi
    i=$((i + 1))
    sleep 1
done

echo "The four-worker FPM profile did not become ready" >&2
exit 1

