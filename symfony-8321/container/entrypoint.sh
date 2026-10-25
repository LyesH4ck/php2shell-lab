#!/bin/sh
set -eu

mkdir -p /tmp/php2shell-sessions /run/apache2 /var/lock/apache2
chmod 0777 /tmp/php2shell-sessions

relay_pid=
apache_pid=

shutdown() {
    status=$1
    trap - INT TERM
    [ -z "$relay_pid" ] || kill -TERM "$relay_pid" 2>/dev/null || :
    [ -z "$apache_pid" ] || kill -TERM "$apache_pid" 2>/dev/null || :
    [ -z "$relay_pid" ] || wait "$relay_pid" 2>/dev/null || :
    [ -z "$apache_pid" ] || wait "$apache_pid" 2>/dev/null || :
    exit "$status"
}

trap 'shutdown 130' INT
trap 'shutdown 143' TERM

socat TCP4-LISTEN:80,bind=0.0.0.0,reuseaddr,fork TCP4:127.0.0.1:8088 &
relay_pid=$!
docker-php-entrypoint apache2-foreground &
apache_pid=$!

while kill -0 "$relay_pid" 2>/dev/null && kill -0 "$apache_pid" 2>/dev/null; do
    sleep 1
done

status=1
if ! kill -0 "$apache_pid" 2>/dev/null; then
    wait "$apache_pid" || status=$?
else
    wait "$relay_pid" || status=$?
fi
shutdown "$status"
