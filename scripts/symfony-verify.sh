#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
target=php2shell-symfony-lab
relay=php2shell-symfony-relay
host_port=${PHP2SHELL_SYMFONY_HOST_PORT:-9093}
profile=symfony-7.4.21-php-8.4.26-amd64

case "$host_port" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_SYMFONY_HOST_PORT: $host_port" >&2; exit 2 ;;
esac

for container in "$target" "$relay"; do
    state=$(docker inspect -f '{{.State.Status}}' "$container")
    [ "$state" = running ] || {
        echo "$container is not running: $state" >&2
        exit 1
    }
done

python3 - "$target" "$relay" "$host_port" "$profile" <<'PY'
import json
import subprocess
import sys

target_name, relay_name, port, profile = sys.argv[1:]

def inspect(kind, name):
    return json.loads(subprocess.check_output(["docker", kind, "inspect", name]))[0]

def require(value, message):
    if not value:
        raise SystemExit(message)

target = inspect("container", target_name)
relay = inspect("container", relay_name)
for role, container in (("target", target), ("relay", relay)):
    host = container["HostConfig"]
    require(host.get("Privileged") is False, f"{role} is privileged")
    require(host.get("ReadonlyRootfs") is True, f"{role} rootfs is writable")
    require("ALL" in (host.get("CapDrop") or []), f"{role} does not drop all capabilities")
    require(
        any(option.startswith("no-new-privileges") for option in host.get("SecurityOpt") or []),
        f"{role} lacks no-new-privileges",
    )

require(not (target["HostConfig"].get("PortBindings") or {}), "target publishes a port")
require(not [
    mount for mount in target.get("Mounts") or []
    if mount.get("Type") in {"bind", "volume"}
], "target has a host or volume mount")
require(
    target["Config"]["Labels"].get("io.php2shell.profile") == profile,
    "target profile label is wrong",
)
expected = {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]}
require(relay["HostConfig"].get("PortBindings") == expected, "relay binding is wrong")
require(relay["NetworkSettings"].get("Ports") == expected, "active relay binding is wrong")

target_networks = target["NetworkSettings"]["Networks"]
require(len(target_networks) == 1, "target must have one network")
isolated_name, target_endpoint = next(iter(target_networks.items()))
require(target_endpoint.get("IPAddress") == "172.31.252.2", "target address is wrong")
require(target_endpoint.get("Gateway") in (None, ""), "target has a gateway")
isolated = inspect("network", isolated_name)
require(isolated.get("Internal") is True, "target network is not internal")
require(
    (isolated.get("Options") or {}).get(
        "com.docker.network.bridge.gateway_mode_ipv4"
    ) == "isolated",
    "target network is not gateway-isolated",
)
relay_networks = relay["NetworkSettings"]["Networks"]
require(len(relay_networks) == 2, "relay must have two networks")
require(isolated_name in relay_networks, "relay cannot reach the target network")
PY

[ "$(docker port "$relay" 80/tcp)" = "127.0.0.1:$host_port" ] || {
    echo "relay publication is not loopback-only" >&2
    exit 1
}

docker exec "$target" awk '
    NR > 1 && $1 != "lo" && $2 == "00000000" { found = 1 }
    END { exit found ? 1 : 0 }
' /proc/net/route || {
    echo "target has a default IPv4 route" >&2
    exit 1
}

expected_libphp=ff3ea77fb119541f6d10ddf0fa7e9e3fd6a3043e049a536b530dbbec35db68d6
actual_libphp=$(docker exec "$target" sha256sum /usr/lib/apache2/modules/libphp.so | awk '{print $1}')
[ "$actual_libphp" = "$expected_libphp" ] || {
    echo "libphp mismatch: $actual_libphp" >&2
    exit 1
}

expected_modules=0ced2e32cd135bf75be5b4793bd1ef05cdedbe15a6b3aadf02cbe3ac0979de68
actual_modules=$(docker exec "$target" php -m | sha256sum | awk '{print $1}')
[ "$actual_modules" = "$expected_modules" ] || {
    echo "PHP module profile mismatch: $actual_modules" >&2
    exit 1
}

effective=$(docker exec "$target" php -r 'echo PHP_VERSION,"|",PHP_ZTS,"|",ini_get("display_errors"),"|",ini_get("memory_limit"),"|",ini_get("session.save_path"),"|",ini_get("session.upload_progress.enabled"),"|",ini_get("session.upload_progress.name"),"\n";')
[ "$effective" = '8.4.26|||8M|/tmp/php2shell-sessions|1|PHP_SESSION_UPLOAD_PROGRESS' ] || {
    echo "unexpected PHP profile: $effective" >&2
    exit 1
}

symfony_version=$(docker exec "$target" php -d memory_limit=128M -r 'require "/var/www/html/vendor/autoload.php"; echo Symfony\Component\HttpKernel\Kernel::VERSION;')
[ "$symfony_version" = 7.4.21 ] || {
    echo "unexpected Symfony version: $symfony_version" >&2
    exit 1
}
docker exec "$target" env APP_ENV=prod APP_DEBUG=0 \
    php -d memory_limit=128M /var/www/html/bin/console debug:router lab_index \
    >/dev/null

body_file=$(mktemp "${TMPDIR:-/tmp}/php2shell-symfony-body.XXXXXX")
post_file=$(mktemp "${TMPDIR:-/tmp}/php2shell-symfony-post.XXXXXX")
trap 'rm -f "$body_file" "$post_file"' EXIT HUP INT TERM

attempt=1
while [ "$attempt" -le 30 ]; do
    if curl --noproxy '*' -fsS -H 'Host: 127.0.0.1:8088' \
        "http://127.0.0.1:$host_port/index.php" -o "$body_file"; then
        body_hash=$(sha256sum "$body_file" | awk '{print $1}')
        [ "$body_hash" = f6598deb85cb9ad4fe7cc2cc97e82c8a734c54d40693af6dc96b4d07dd9c9363 ] && break
    fi
    [ "$attempt" -lt 30 ] || {
        echo "Symfony HTTP body check failed" >&2
        exit 1
    }
    sleep 1
    attempt=$((attempt + 1))
done

curl --noproxy '*' -fsS -X POST -H 'Host: 127.0.0.1:8088' \
    "http://127.0.0.1:$host_port/index.php" -o "$post_file"
[ "$(cat "$post_file")" = "php2shell symfony parser" ] || {
    echo "Symfony parser-only POST branch is not active" >&2
    exit 1
}

configured_workers=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$target" |
    sed -n 's/^PHP2SHELL_APACHE_WORKERS=//p' | tail -n 1)
workers=$(docker top "$target" -eo pid,user,comm |
    awk '($2=="www-data" || $2=="33") && $3=="apache2" {n++} END {print n+0}')
[ "$workers" = "$configured_workers" ] || {
    echo "expected $configured_workers Apache workers, got $workers" >&2
    exit 1
}

if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -H -ltn "sport = :$host_port" || true)
    if printf '%s\n' "$listeners" | grep -Eq "(^|[[:space:]])(0\.0\.0\.0|\[::\]|\*):$host_port([[:space:]]|$)"; then
        echo "refusing wildcard listener on port $host_port" >&2
        exit 1
    fi
fi

rm -f "$body_file" "$post_file"
trap - EXIT HUP INT TERM

printf 'SYMFONY_VERIFY_OK\n'
printf 'url=http://127.0.0.1:%s/index.php\n' "$host_port"
printf 'application=symfony-%s\n' "$symfony_version"
printf 'profile=%s\n' "$effective"
printf 'libphp_sha256=%s\n' "$actual_libphp"
printf 'php_modules_sha256=%s\n' "$actual_modules"
printf 'body_sha256=%s\n' "$body_hash"
printf 'worker_count=%s\n' "$workers"
printf 'network_isolation=gateway_mode_ipv4=isolated,no_default_route\n'
printf 'published=127.0.0.1:%s->relay:80\n' "$host_port"
