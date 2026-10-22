#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
target=php2shell-wordpress-lab
relay=php2shell-wordpress-relay
host_port=${PHP2SHELL_WORDPRESS_HOST_PORT:-9091}
profile=wordpress-7.1.3-sqlite-3.1.1-php-8.4.26-amd64

case "$host_port" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_WORDPRESS_HOST_PORT: $host_port" >&2; exit 2 ;;
esac
host_port=$(python3 - "$host_port" <<'PY'
import sys

port = int(sys.argv[1])
if not 1 <= port <= 65535:
    raise SystemExit(
        f"PHP2SHELL_WORDPRESS_HOST_PORT must be in 1..65535, got {port}"
    )
print(port)
PY
)

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

target_name, relay_name, expected_port, expected_profile = sys.argv[1:]


def inspect(kind, name):
    return json.loads(subprocess.check_output(
        ["docker", kind, "inspect", name]
    ))[0]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def php2shell_labels(container):
    return {
        key: value
        for key, value in (container["Config"].get("Labels") or {}).items()
        if key.startswith("io.php2shell.")
    }


def require_hardening(container, role):
    host = container["HostConfig"]
    require(host.get("Privileged") is False, f"{role} is privileged")
    require(host.get("ReadonlyRootfs") is True, f"{role} rootfs is writable")
    require(
        "ALL" in (host.get("CapDrop") or []),
        f"{role} does not drop all capabilities",
    )
    require(
        any(
            option.startswith("no-new-privileges")
            for option in host.get("SecurityOpt") or []
        ),
        f"{role} lacks no-new-privileges",
    )
    require(not (host.get("ExtraHosts") or []), f"{role} has host aliases")


target = inspect("container", target_name)
relay = inspect("container", relay_name)
target_host = target["HostConfig"]
relay_host = relay["HostConfig"]

require_hardening(target, "target")
require_hardening(relay, "relay")
require(not (target_host.get("PortBindings") or {}), "target publishes a host port")

require(
    php2shell_labels(target)
    == {
        "io.php2shell.lab": "true",
        "io.php2shell.profile": expected_profile,
        "io.php2shell.wordpress": "true",
    },
    f"unexpected target labels: {php2shell_labels(target)}",
)
require(
    php2shell_labels(relay)
    == {
        "io.php2shell.profile": expected_profile,
        "io.php2shell.relay": "true",
        "io.php2shell.wordpress": "true",
    },
    f"unexpected relay labels: {php2shell_labels(relay)}",
)

wordpress_tmpfs = target_host.get("Tmpfs") or {}
database_mount = wordpress_tmpfs.get("/var/lib/php2shell-wordpress", "")
for option in ("nosuid", "nodev", "noexec", "uid=33", "gid=33", "mode=0700"):
    require(option in database_mount.split(","), f"SQLite tmpfs lacks {option}")
external_mounts = [
    mount
    for mount in target.get("Mounts") or []
    if mount.get("Type") in {"bind", "volume"}
]
require(not external_mounts, f"target has host/volume mounts: {external_mounts}")

target_networks = target["NetworkSettings"]["Networks"]
require(len(target_networks) == 1, "target must have exactly one network")
isolated_name, target_endpoint = next(iter(target_networks.items()))
require(target_endpoint.get("IPAddress") == "172.31.254.2", "target IP is wrong")
require(target_endpoint.get("Gateway") in (None, ""), "target has an IPv4 gateway")
require(target_host.get("NetworkMode") == isolated_name, "target network mode is wrong")

isolated = inspect("network", isolated_name)
isolated_options = isolated.get("Options") or {}
require(isolated.get("Driver") == "bridge", "target network is not a bridge")
require(isolated.get("Internal") is True, "target network is not internal")
require(
    isolated_options.get("com.docker.network.bridge.gateway_mode_ipv4")
    == "isolated",
    "target bridge is not in isolated gateway mode",
)
require(
    all(not item.get("Gateway") for item in isolated["IPAM"].get("Config") or []),
    "target bridge IPAM declares a gateway",
)
require(
    any(
        item.get("Subnet") == "172.31.254.0/28"
        for item in isolated["IPAM"].get("Config") or []
    ),
    "target bridge subnet is wrong",
)

require(relay_host.get("NetworkMode") != "host", "relay uses host networking")
require(
    relay["Config"].get("Entrypoint") == ["/usr/bin/socat"],
    "relay entrypoint is wrong",
)
require(
    relay["Config"].get("Cmd")
    == [
        "TCP4-LISTEN:80,bind=0.0.0.0,reuseaddr,fork",
        "TCP4:172.31.254.2:80",
    ],
    f"relay command is wrong: {relay['Config'].get('Cmd')}",
)
expected_binding = {
    "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": expected_port}]
}
require(
    (relay_host.get("PortBindings") or {}) == expected_binding,
    f"unexpected relay port binding: {relay_host.get('PortBindings')}",
)
require(
    (relay["NetworkSettings"].get("Ports") or {}) == expected_binding,
    f"unexpected active relay publication: {relay['NetworkSettings'].get('Ports')}",
)

relay_networks = relay["NetworkSettings"]["Networks"]
require(len(relay_networks) == 2, "relay must have exactly two networks")
require(isolated_name in relay_networks, "relay is not attached to target network")
relay_isolated = relay_networks[isolated_name]
require(relay_isolated.get("IPAddress") == "172.31.254.3", "relay target IP is wrong")
require(relay_isolated.get("Gateway") in (None, ""), "relay target endpoint has a gateway")
require(
    relay_isolated.get("NetworkID") == target_endpoint.get("NetworkID"),
    "relay and target do not share the isolated bridge",
)

ingress_names = set(relay_networks) - {isolated_name}
require(len(ingress_names) == 1, "relay ingress network is ambiguous")
ingress_name = ingress_names.pop()
ingress_endpoint = relay_networks[ingress_name]
ingress = inspect("network", ingress_name)
require(relay_host.get("NetworkMode") == ingress_name, "relay ingress is not primary")
require(ingress_endpoint.get("IPAddress") == "172.31.253.2", "relay ingress IP is wrong")
require(ingress.get("Driver") == "bridge", "relay ingress is not a bridge")
require(ingress.get("Internal") is False, "relay ingress is internal")
require(
    (ingress.get("Options") or {}).get(
        "com.docker.network.bridge.host_binding_ipv4"
    ) == "127.0.0.1",
    "relay ingress does not default to loopback binding",
)
require(
    set(isolated.get("Containers") or {}) == {target["Id"], relay["Id"]},
    "isolated bridge membership is not exactly target and relay",
)
require(
    set(ingress.get("Containers") or {}) == {relay["Id"]},
    "ingress bridge membership is not exactly the relay",
)

route_text = subprocess.check_output(
    ["docker", "exec", target_name, "cat", "/proc/net/route"], text=True
)
routes = []
for line in route_text.splitlines()[1:]:
    columns = line.split()
    if len(columns) >= 8 and columns[0] != "lo":
        routes.append(columns)
require(len(routes) == 1, f"unexpected target IPv4 routes: {routes}")
require(routes[0][1] == "00FE1FAC", f"unexpected target route: {routes[0]}")
require(routes[0][2] == "00000000", f"target route uses a gateway: {routes[0]}")
require(routes[0][7] == "F0FFFFFF", f"unexpected target route mask: {routes[0]}")

ipv6_text = subprocess.check_output(
    ["docker", "exec", target_name, "cat", "/proc/net/if_inet6"], text=True
)
ipv6_interfaces = [
    line.split()[-1] for line in ipv6_text.splitlines() if line.split()
]
require(
    all(interface == "lo" for interface in ipv6_interfaces),
    f"target has non-loopback IPv6: {ipv6_interfaces}",
)

probe_code = (
    '$s=@stream_socket_client("tcp://172.31.254.1:22",$e,$m,0.5,'
    'STREAM_CLIENT_CONNECT);if(is_resource($s)){fclose($s);exit(1);}exit(0);'
)
probe = subprocess.run(
    ["docker", "exec", target_name, "php", "-r", probe_code],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    timeout=5,
)
require(
    probe.returncode == 0,
    "target can connect to the former host gateway 172.31.254.1:22",
)
PY

published=$(docker port "$relay" 80/tcp)
[ "$published" = "127.0.0.1:$host_port" ] || {
    echo "unexpected relay publication: $published" >&2
    exit 1
}

expected_libphp=ff3ea77fb119541f6d10ddf0fa7e9e3fd6a3043e049a536b530dbbec35db68d6
actual_libphp=$(docker exec "$target" sha256sum /usr/lib/apache2/modules/libphp.so | awk '{print $1}')
[ "$actual_libphp" = "$expected_libphp" ] || {
    echo "libphp mismatch: $actual_libphp" >&2
    exit 1
}

expected_php_modules=0ced2e32cd135bf75be5b4793bd1ef05cdedbe15a6b3aadf02cbe3ac0979de68
actual_php_modules=$(docker exec "$target" php -m | sha256sum | awk '{print $1}')
[ "$actual_php_modules" = "$expected_php_modules" ] || {
    echo "PHP module profile mismatch: $actual_php_modules" >&2
    exit 1
}

expected_exploit=19f956c3f122c7596c457296767084b9d45e54916dd048671e6e348e70fcee39
actual_exploit=$(sha256sum "$bundle_dir/exploit/exploit_off.py" | awk '{print $1}')
[ "$actual_exploit" = "$expected_exploit" ] || {
    echo "exploit mismatch: $actual_exploit" >&2
    exit 1
}

effective=$(docker exec "$target" php -r 'echo PHP_VERSION,"|",PHP_ZTS,"|",ini_get("display_errors"),"|",ini_get("memory_limit"),"|",ini_get("session.save_path"),"|",ini_get("session.upload_progress.enabled"),"|",ini_get("session.upload_progress.name"),"\n";')
[ "$effective" = '8.4.26|||8M|/tmp/php2shell-sessions|1|PHP_SESSION_UPLOAD_PROGRESS' ] || {
    echo "unexpected PHP profile: $effective" >&2
    exit 1
}

wordpress_version=$(docker exec "$target" php -r 'require "/var/www/html/wp-includes/version.php"; echo $wp_version;')
[ "$wordpress_version" = 7.1.3 ] || {
    echo "unexpected WordPress version: $wordpress_version" >&2
    exit 1
}
pdo_sqlite_loaded=$(docker exec "$target" php -r 'echo extension_loaded("pdo_sqlite") ? "1" : "0";')
[ "$pdo_sqlite_loaded" = 1 ] || {
    echo "pdo_sqlite extension is not loaded" >&2
    exit 1
}
mysqli_loaded=$(docker exec "$target" php -r 'echo extension_loaded("mysqli") ? "1" : "0";')
[ "$mysqli_loaded" = 0 ] || {
    echo "mysqli unexpectedly changes the calibrated PHP module set" >&2
    exit 1
}

database_state=$(docker exec --user www-data "$target" \
    php -d memory_limit=128M -r '
        define("WP_USE_THEMES", false);
        require "/var/www/html/wp-load.php";
        clearstatcache(true, DB_PATH);
        printf(
            "%d|%s|%d|%d",
            function_exists("is_blog_installed") && is_blog_installed() ? 1 : 0,
            defined("SQLITE_DRIVER_VERSION") ? SQLITE_DRIVER_VERSION : "missing",
            (string) $GLOBALS["wpdb"]->get_var("SELECT 1") === "1" ? 1 : 0,
            is_file(DB_PATH) && filesize(DB_PATH) >= 4096 ? 1 : 0
        );
    ')
[ "$database_state" = '1|3.1.1|1|1' ] || {
    echo "unexpected WordPress/SQLite state: $database_state" >&2
    exit 1
}

database_header=$(docker exec --user www-data "$target" php -r \
    'echo bin2hex(file_get_contents("/var/lib/php2shell-wordpress/wordpress.sqlite", false, null, 0, 16));')
[ "$database_header" = 53514c69746520666f726d6174203300 ] || {
    echo "invalid SQLite database header: $database_header" >&2
    exit 1
}
database_owner=$(docker exec "$target" stat -c '%u:%g' /var/lib/php2shell-wordpress/wordpress.sqlite)
[ "$database_owner" = 33:33 ] || {
    echo "unexpected SQLite database owner: $database_owner" >&2
    exit 1
}
database_dir_mode=$(docker exec "$target" stat -c '%a' /var/lib/php2shell-wordpress)
[ "$database_dir_mode" = 700 ] || {
    echo "unexpected SQLite database directory mode: $database_dir_mode" >&2
    exit 1
}
docker exec "$target" awk '
    $2 == "/var/lib/php2shell-wordpress" && $3 == "tmpfs" { found = 1 }
    END { exit found ? 0 : 1 }
' /proc/mounts || {
    echo "WordPress SQLite directory is not a tmpfs" >&2
    exit 1
}

body_file=$(mktemp "${TMPDIR:-/tmp}/php2shell-wordpress-body.XXXXXX")
trap 'rm -f "$body_file"' EXIT HUP INT TERM
attempt=1
while [ "$attempt" -le 30 ]; do
    if curl --noproxy '*' -fsS -H 'Host: 127.0.0.1:8088' \
        "http://127.0.0.1:${host_port}/index.php" -o "$body_file"; then
        body_hash=$(sha256sum "$body_file" | awk '{print $1}')
        [ "$body_hash" = 0cab4b9edc46a4c17ba60cf00ebfb234eaec0abffa89e5c00bfa10aaf401b123 ] && break
    fi
    [ "$attempt" -lt 30 ] || {
        echo "WordPress HTTP body check failed" >&2
        exit 1
    }
    sleep 1
    attempt=$((attempt + 1))
done
rm -f "$body_file"
trap - EXIT HUP INT TERM

if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -H -ltn "sport = :$host_port" || true)
    if printf '%s\n' "$listeners" | grep -Eq "(^|[[:space:]])(0\.0\.0\.0|\[::\]|\*):$host_port([[:space:]]|$)"; then
        echo "refusing wildcard listener on port $host_port" >&2
        exit 1
    fi
fi

workers=$(docker top "$target" -eo pid,user,comm | awk '($2=="www-data" || $2=="33") && $3=="apache2" {n++} END {print n+0}')
[ "$workers" = 1 ] || {
    echo "expected one Apache worker, got $workers" >&2
    exit 1
}

printf 'WORDPRESS_VERIFY_OK\n'
printf 'url=http://127.0.0.1:%s/index.php\n' "$host_port"
printf 'application=wordpress-%s\n' "$wordpress_version"
printf 'database=sqlite-installed,tmpfs,unpublished\n'
printf 'sqlite_plugin=%s\n' 3.1.1
printf 'pdo_sqlite=%s\n' "$pdo_sqlite_loaded"
printf 'mysqli=%s\n' "$mysqli_loaded"
printf 'profile=%s\n' "$effective"
printf 'libphp_sha256=%s\n' "$actual_libphp"
printf 'php_modules_sha256=%s\n' "$actual_php_modules"
printf 'exploit_sha256=%s\n' "$actual_exploit"
printf 'body_sha256=%s\n' "$body_hash"
printf 'worker_count=%s\n' "$workers"
printf 'network_isolation=gateway_mode_ipv4=isolated,no_default_route\n'
printf 'published=127.0.0.1:%s->relay:80\n' "$host_port"
