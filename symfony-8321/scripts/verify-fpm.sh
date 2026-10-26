#!/bin/sh
set -eu

target=php2shell-fpm-8321
nginx=php2shell-fpm-topology-nginx
blocked_port=${PHP2SHELL_FPM_BLOCKED_PORT:-9195}
origin_port=${PHP2SHELL_FPM_ORIGIN_PORT:-9196}

[ "$(docker inspect -f '{{.State.Status}}' "$target")" = running ]
[ "$(docker inspect -f '{{.State.Status}}' "$nginx")" = running ]
[ "$(docker exec "$target" uname -m)" = x86_64 ]
[ "$(docker image inspect -f '{{.Os}}/{{.Architecture}}' php2shell-fpm-lab:php8.3.21-symfony7.4.19-amd64)" = linux/amd64 ]
[ "$(docker inspect -f '{{json .HostConfig.PortBindings}}' "$target")" = '{}' ]
[ "$(docker port "$nginx" 8080/tcp)" = "127.0.0.1:$blocked_port" ]
[ "$(docker port "$nginx" 8081/tcp)" = "127.0.0.1:$origin_port" ]

docker exec "$target" awk '
    NR > 1 && $1 != "lo" && $2 == "00000000" { found = 1 }
    END { exit found ? 1 : 0 }
' /proc/net/route || {
    echo "FPM target unexpectedly has a default IPv4 route" >&2
    exit 1
}

profile=$(docker exec "$target" php -r '
echo PHP_VERSION,"|",PHP_SAPI,"|",ini_get("display_errors"),"|",
     ini_get("display_startup_errors"),"|",ini_get("memory_limit"),"|",
     ini_get("post_max_size"),"|",ini_get("upload_max_filesize"),"|",
     ini_get("session.upload_progress.enabled"),"|",
     ini_get("max_multipart_body_parts"),"\n";
')
[ "$profile" = '8.3.21|cli|||128M|8M|2M|1|-1' ] || {
    echo "Unexpected PHP profile: $profile" >&2
    exit 1
}

version=$(docker exec "$target" php -d memory_limit=256M -r 'require "/var/www/html/vendor/autoload.php"; echo Symfony\Component\HttpKernel\Kernel::VERSION;')
[ "$version" = 7.4.19 ] || {
    echo "Unexpected Symfony version: $version" >&2
    exit 1
}

get_body=$(curl --noproxy '*' -fsS "http://127.0.0.1:$blocked_port/index.php")
printf '%s\n' "$get_body" | grep -qx 'symfony=7.4.19'
printf '%s\n' "$get_body" | grep -qx 'php=8.3.21'
printf '%s\n' "$get_body" | grep -qx 'sapi=fpm-fcgi'
printf '%s\n' "$get_body" | grep -qx 'kernel=booted'

post_body=$(curl --noproxy '*' -fsS -X POST "http://127.0.0.1:$origin_port/index.php")
[ "$post_body" = 'php2shell symfony 8.3.21 parser' ]
plain_body=$(curl --noproxy '*' -fsS "http://127.0.0.1:$origin_port/plain.php")
[ "$plain_body" = 'OK' ]
session_body=$(curl --noproxy '*' -fsS "http://127.0.0.1:$origin_port/fpm-index.php")
[ "$session_body" = 'OK' ]
docker exec -u www-data "$target" test -w /var/www/html/public/proof

blocked_status=$(head -c 2097152 /dev/zero | curl --noproxy '*' -sS \
    -o /dev/null -w '%{http_code}' -X POST --data-binary @- \
    "http://127.0.0.1:$blocked_port/index.php")
[ "$blocked_status" = 413 ] || {
    echo "Expected nginx 413 on blocked frontend, got $blocked_status" >&2
    exit 1
}

printf 'FPM_VERIFY_OK\n'
printf 'php=8.3.21\nsapi=fpm-fcgi\nsymfony=7.4.19\n'
printf 'display_errors=Off\nmemory_limit=128M\npost_max_size=8M\n'
printf 'blocked=127.0.0.1:%s (client_max_body_size=512k)\n' "$blocked_port"
printf 'origin=127.0.0.1:%s (client_max_body_size=32m)\n' "$origin_port"
