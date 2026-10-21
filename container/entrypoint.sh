#!/bin/sh
set -eu

mkdir -p /tmp/php2shell-sessions /run/apache2 /var/lock/apache2
chmod 0777 /tmp/php2shell-sessions

relay_pid=
apache_pid=

shutdown() {
    status=$1

    trap - INT TERM
    if [ -n "$relay_pid" ]; then
        kill -TERM "$relay_pid" 2>/dev/null || :
    fi
    if [ -n "$apache_pid" ]; then
        kill -TERM "$apache_pid" 2>/dev/null || :
    fi
    if [ -n "$relay_pid" ]; then
        wait "$relay_pid" 2>/dev/null || :
    fi
    if [ -n "$apache_pid" ]; then
        wait "$apache_pid" 2>/dev/null || :
    fi

    exit "$status"
}

trap 'shutdown 130' INT
trap 'shutdown 143' TERM

# Preserve Apache's exact calibrated address while still allowing a standard
# Docker loopback publication on the host.
socat TCP4-LISTEN:80,bind=0.0.0.0,reuseaddr,fork TCP4:127.0.0.1:8088 &
relay_pid=$!

docker-php-entrypoint apache2-foreground &
apache_pid=$!

while kill -0 "$relay_pid" 2>/dev/null \
    && kill -0 "$apache_pid" 2>/dev/null; do
    sleep 1
done

if ! kill -0 "$relay_pid" 2>/dev/null; then
    status=0
    wait "$relay_pid" || status=$?
    echo "php2shell relay exited; stopping Apache" >&2
    kill -TERM "$apache_pid" 2>/dev/null || :
    wait "$apache_pid" 2>/dev/null || :
    if [ "$status" -eq 0 ]; then
        status=1
    fi
    exit "$status"
fi

status=0
wait "$apache_pid" || status=$?
echo "Apache exited; stopping php2shell relay" >&2
kill -TERM "$relay_pid" 2>/dev/null || :
wait "$relay_pid" 2>/dev/null || :
exit "$status"
