#!/bin/sh
set -eu

target=php2shell-symfony-8321-lab
relay=php2shell-symfony-8321-relay
port=${PHP2SHELL_SYMFONY_8321_PORT:-9094}

[ "$(docker inspect -f '{{.State.Status}}' "$target")" = running ]
[ "$(docker inspect -f '{{.State.Status}}' "$relay")" = running ]
[ "$(docker exec "$target" uname -m)" = x86_64 ]
[ "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' php2shell-symfony-lab:7.4.19-php8.3.21-amd64)" = linux/amd64 ]
[ "$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$target")" = '{}' ]
[ "$(docker port "$relay" 80/tcp)" = "127.0.0.1:$port" ]

workers=$(
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$target" |
        awk -F= '$1 == "PHP2SHELL_APACHE_WORKERS" { value = $2 } END { print value }'
)
case "$workers" in
    *[!0-9]*|'') echo "Invalid worker count in target: $workers" >&2; exit 1 ;;
esac
[ "$workers" -ge 1 ] && [ "$workers" -le 16 ] || {
    echo "Unexpected worker count in target: $workers" >&2
    exit 1
}
apache_processes=$(docker exec "$target" pgrep -c apache2)
expected_processes=$((workers + 1))
[ "$apache_processes" -eq "$expected_processes" ] || {
    echo "Expected $workers Apache workers plus one parent; found $apache_processes processes" >&2
    exit 1
}

docker exec "$target" awk '
    NR > 1 && $1 != "lo" && $2 == "00000000" { found = 1 }
    END { exit found ? 1 : 0 }
' /proc/net/route || {
    echo "Target unexpectedly has a default IPv4 route" >&2
    exit 1
}

profile=$(docker exec "$target" php -r 'echo PHP_VERSION,"|",PHP_SAPI,"|",ini_get("display_errors"),"|",ini_get("memory_limit"),"|",ini_get("session.upload_progress.enabled"),"\n";')
[ "$profile" = '8.3.21|cli||8M|1' ] || {
    echo "Unexpected PHP profile: $profile" >&2
    exit 1
}

version=$(docker exec "$target" php -d memory_limit=128M -r 'require "/var/www/html/vendor/autoload.php"; echo Symfony\Component\HttpKernel\Kernel::VERSION;')
[ "$version" = 7.4.19 ] || {
    echo "Unexpected Symfony version: $version" >&2
    exit 1
}

get_body=$(curl --noproxy '*' -fsS -H 'Host: 127.0.0.1:8088' "http://127.0.0.1:$port/index.php")
printf '%s\n' "$get_body" | grep -qx 'symfony=7.4.19'
printf '%s\n' "$get_body" | grep -qx 'php=8.3.21'
printf '%s\n' "$get_body" | grep -qx 'sapi=apache2handler'
printf '%s\n' "$get_body" | grep -qx 'kernel=booted'

post_body=$(curl --noproxy '*' -fsS -X POST -H 'Host: 127.0.0.1:8088' "http://127.0.0.1:$port/index.php")
[ "$post_body" = 'php2shell symfony 8.3.21 parser' ]

printf 'SYMFONY_8321_VERIFY_OK\n%s\n' "$get_body"
printf 'post=%s\n' "$post_body"
printf 'published=127.0.0.1:%s\n' "$port"
printf 'apache_workers=%s\n' "$workers"
