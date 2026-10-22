#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
container=php2shell-vulnerable-lab
relay=php2shell-loopback-relay

if [ -z "${PHP2SHELL_HOST_PORT+x}" ] && [ -f "$bundle_dir/.env" ]; then
    PHP2SHELL_HOST_PORT=$(sed -n 's/^PHP2SHELL_HOST_PORT=//p' "$bundle_dir/.env" | tail -n 1)
fi
host_port=${PHP2SHELL_HOST_PORT:-9090}
case "$host_port" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_HOST_PORT: $host_port" >&2; exit 2 ;;
esac
host_port=$(python3 - "$host_port" <<'PY'
import sys

port = int(sys.argv[1])
if not 1 <= port <= 65535:
    raise SystemExit(f"PHP2SHELL_HOST_PORT must be in 1..65535, got {port}")
print(port)
PY
)

state=$(docker inspect -f '{{.State.Status}}' "$container")
[ "$state" = running ] || { echo "container is not running: $state" >&2; exit 1; }
relay_state=$(docker inspect -f '{{.State.Status}}' "$relay")
[ "$relay_state" = running ] || { echo "relay is not running: $relay_state" >&2; exit 1; }

python3 - "$container" "$relay" "$host_port" <<'PY'
import json
import subprocess
import sys

container, relay_name, expected_port = sys.argv[1:]


def inspect(kind, name):
    return json.loads(subprocess.check_output(
        ["docker", kind, "inspect", name]
    ))[0]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


target = inspect("container", container)
relay = inspect("container", relay_name)
target_host = target["HostConfig"]
relay_host = relay["HostConfig"]

require(target_host.get("Privileged") is False, "target is privileged")
require(target_host.get("ReadonlyRootfs") is True, "target rootfs is writable")
require("ALL" in (target_host.get("CapDrop") or []), "target does not drop all capabilities")
require(
    any(x.startswith("no-new-privileges") for x in target_host.get("SecurityOpt") or []),
    "target lacks no-new-privileges",
)
require(not (target_host.get("PortBindings") or {}), "target publishes a host port")
require(not (target_host.get("ExtraHosts") or []), "target has host aliases")
target_labels = target["Config"].get("Labels") or {}
require(target_labels.get("io.php2shell.lab") == "true", "target lab label is missing")
require(
    target_labels.get("io.php2shell.profile")
    == "php-8.4.26-amd64-clean-terminal",
    "target profile label is wrong",
)

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
require(relay_host.get("Privileged") is False, "relay is privileged")
require(relay_host.get("ReadonlyRootfs") is True, "relay rootfs is writable")
require("ALL" in (relay_host.get("CapDrop") or []), "relay does not drop all capabilities")
require(
    any(x.startswith("no-new-privileges") for x in relay_host.get("SecurityOpt") or []),
    "relay lacks no-new-privileges",
)
require(
    (relay["Config"].get("Labels") or {}).get("io.php2shell.relay") == "true",
    "relay label is missing",
)
require(relay["Config"].get("Entrypoint") == ["/usr/bin/socat"], "relay entrypoint is wrong")
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
    set((isolated.get("Containers") or {})) == {target["Id"], relay["Id"]},
    "unexpected container attached to target bridge",
)

route_text = subprocess.check_output(
    ["docker", "exec", container, "cat", "/proc/net/route"], text=True
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
    ["docker", "exec", container, "cat", "/proc/net/if_inet6"], text=True
)
ipv6_interfaces = [line.split()[-1] for line in ipv6_text.splitlines() if line.split()]
require(
    all(interface == "lo" for interface in ipv6_interfaces),
    f"target has non-loopback IPv6: {ipv6_interfaces}",
)

probe_code = (
    '$s=@stream_socket_client("tcp://172.31.254.1:22",$e,$m,0.5,'
    'STREAM_CLIENT_CONNECT);if(is_resource($s)){fclose($s);exit(1);}exit(0);'
)
probe = subprocess.run(
    ["docker", "exec", container, "php", "-r", probe_code],
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
actual_libphp=$(docker exec "$container" sha256sum /usr/lib/apache2/modules/libphp.so | awk '{print $1}')
[ "$actual_libphp" = "$expected_libphp" ] || {
    echo "libphp mismatch: $actual_libphp" >&2
    exit 1
}

expected_exploit=2de1bdd1287167f9789507711badc9e5f5b1cac228312714ba0c0a31c7920980
actual_exploit=$(sha256sum "$bundle_dir/exploit/exploit_off.py" | awk '{print $1}')
[ "$actual_exploit" = "$expected_exploit" ] || {
    echo "exploit mismatch: $actual_exploit" >&2
    exit 1
}

effective=$(docker exec "$container" php -r 'echo PHP_VERSION,"|",PHP_ZTS,"|",ini_get("display_errors"),"|",ini_get("memory_limit"),"|",ini_get("session.save_path"),"\n";')
[ "$effective" = '8.4.26|||8M|/tmp/php2shell-sessions' ] || {
    echo "unexpected PHP profile: $effective" >&2
    exit 1
}

attempt=1
while [ "$attempt" -le 30 ]; do
    if curl --noproxy '*' -fsS -H 'Host: 127.0.0.1:8088' \
        "http://127.0.0.1:${host_port}/index.php" |
        grep -Fxq 'php2shell isolated lab'; then
        break
    fi
    [ "$attempt" -lt 30 ] || { echo "HTTP health check failed" >&2; exit 1; }
    sleep 1
    attempt=$((attempt + 1))
done

if command -v ss >/dev/null 2>&1; then
    listeners=$(ss -H -ltn "sport = :$host_port" || true)
    if printf '%s\n' "$listeners" | grep -Eq "(^|[[:space:]])(0\.0\.0\.0|\[::\]|\*):$host_port([[:space:]]|$)"; then
        echo "refusing wildcard listener on port $host_port" >&2
        exit 1
    fi
fi

configured_workers=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" |
    sed -n 's/^PHP2SHELL_APACHE_WORKERS=//p' | tail -n 1)
case "$configured_workers" in
    *[!0-9]*|'')
        echo "invalid configured Apache worker count: $configured_workers" >&2
        exit 1
        ;;
esac
[ "$configured_workers" -ge 1 ] && [ "$configured_workers" -le 16 ] || {
    echo "configured Apache worker count is outside 1..16: $configured_workers" >&2
    exit 1
}
worker_wait=1
while [ "$worker_wait" -le 30 ]; do
    workers=$(docker top "$container" -eo pid,user,comm | awk '($2=="www-data" || $2=="33") && $3=="apache2" {n++} END {print n+0}')
    [ "$workers" = "$configured_workers" ] && break
    [ "$worker_wait" -lt 30 ] || break
    sleep 1
    worker_wait=$((worker_wait + 1))
done
[ "$workers" = "$configured_workers" ] || {
    echo "expected $configured_workers Apache workers, got $workers" >&2
    exit 1
}

printf 'VERIFY_OK\n'
printf 'url=http://127.0.0.1:%s/index.php\n' "$host_port"
printf 'profile=%s\n' "$effective"
printf 'libphp_sha256=%s\n' "$actual_libphp"
printf 'exploit_sha256=%s\n' "$actual_exploit"
printf 'worker_count=%s\n' "$workers"
printf 'network_isolation=gateway_mode_ipv4=isolated,no_default_route\n'
printf 'published=127.0.0.1:%s->relay:80\n' "$host_port"
