#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="$bundle_dir/scripts/wordpress-compose-command.sh"
target=php2shell-wordpress-lab
relay=php2shell-wordpress-relay
host_port=${PHP2SHELL_WORDPRESS_HOST_PORT:-9091}

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
export PHP2SHELL_WORDPRESS_HOST_PORT="$host_port"

host_arch=$(uname -m)
if [ "$host_arch" != x86_64 ] && [ "${ALLOW_EMULATION:-0}" != 1 ]; then
    echo "This calibrated exploit requires native x86_64." >&2
    echo "Set ALLOW_EMULATION=1 only for target smoke tests, not ASLR proof." >&2
    exit 3
fi

docker info >/dev/null
[ "$(docker info --format '{{.OSType}}')" = linux ] || {
    echo "The lab requires a Linux Docker server." >&2
    exit 4
}
server_version=$(docker version --format '{{.Server.Version}}')
server_major=${server_version%%.*}
case "$server_major" in
    *[!0-9]*|'')
        echo "Cannot determine Docker Engine major version: $server_version" >&2
        exit 4
        ;;
esac
[ "$server_major" -ge 28 ] || {
    echo "Docker Engine 28+ is required for gateway_mode_ipv4=isolated (found $server_version)." >&2
    exit 4
}
server_arch=$(docker info --format '{{.Architecture}}')
case "$server_arch" in
    x86_64|amd64) ;;
    *)
        if [ "${ALLOW_EMULATION:-0}" != 1 ]; then
            echo "Docker server is $server_arch, not native amd64." >&2
            echo "Set ALLOW_EMULATION=1 only for target smoke tests, not ASLR proof." >&2
            exit 3
        fi
        ;;
esac

if docker inspect php2shell-vulnerable-lab >/dev/null 2>&1; then
    echo "The minimal lab still exists and uses the calibrated network." >&2
    echo "Run ./scripts/down.sh before starting the WordPress profile." >&2
    exit 5
fi

succeeded=0
cleanup_on_failure() {
    [ "$succeeded" -eq 1 ] && return
    "$compose" down --remove-orphans >/dev/null 2>&1 || true
    echo "WordPress lab setup failed; all lab services were stopped." >&2
}
trap cleanup_on_failure EXIT
trap 'exit 130' HUP INT TERM

"$compose" config >/dev/null
"$compose" build --pull target

# Remove only this Compose project, including an obsolete database service from
# an earlier profile.  Evidence below results/ is not touched.
"$compose" down --remove-orphans >/dev/null 2>&1 || true

python3 - "$host_port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind(("127.0.0.1", port))
except PermissionError as exc:
    raise SystemExit(
        f"127.0.0.1:{port} cannot be bound by the current user: {exc}. "
        "Choose an unprivileged port, for example "
        "PHP2SHELL_WORDPRESS_HOST_PORT=9091."
    )
except OSError as exc:
    raise SystemExit(f"127.0.0.1:{port} is unavailable: {exc}")
finally:
    sock.close()
PY

"$compose" up --no-start

python3 - "$target" "$relay" "$host_port" <<'PY'
import json
import subprocess
import sys

target_name, relay_name, expected_port = sys.argv[1:]


def inspect(kind, name):
    return json.loads(subprocess.check_output(
        ["docker", kind, "inspect", name]
    ))[0]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


target = inspect("container", target_name)
relay = inspect("container", relay_name)

for name, container in (
    ("target", target),
    ("relay", relay),
):
    require(
        container["State"]["Status"] in ("created", "exited"),
        f"{name} unexpectedly running before topology verification",
    )

target_networks = target["NetworkSettings"]["Networks"]
require(len(target_networks) == 1, "target must have exactly one network")
isolated_name, target_endpoint = next(iter(target_networks.items()))
isolated = inspect("network", isolated_name)
require(isolated.get("Driver") == "bridge", "target network is not a bridge")
require(isolated.get("Internal") is True, "target network is not internal")
require(
    (isolated.get("Options") or {}).get(
        "com.docker.network.bridge.gateway_mode_ipv4"
    ) == "isolated",
    "target bridge is not in isolated gateway mode",
)
require(
    all(not item.get("Gateway") for item in isolated["IPAM"].get("Config") or []),
    "target network declares a host gateway",
)
require(
    (target_endpoint.get("IPAMConfig") or {}).get("IPv4Address")
    == "172.31.254.2",
    "target does not request the calibrated isolated address",
)
require(
    not (target["HostConfig"].get("PortBindings") or {}),
    "target publishes a port",
)

relay_host = relay["HostConfig"]
require(relay_host.get("NetworkMode") != "host", "relay uses host networking")
expected_binding = {
    "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": expected_port}]
}
require(
    (relay_host.get("PortBindings") or {}) == expected_binding,
    f"unexpected relay port binding: {relay_host.get('PortBindings')}",
)
relay_networks = relay["NetworkSettings"]["Networks"]
require(
    len(relay_networks) in (1, 2),
    "relay must have ingress alone or ingress plus target network before start",
)
if isolated_name in relay_networks:
    require(
        (relay_networks[isolated_name].get("IPAMConfig") or {}).get("IPv4Address")
        == "172.31.254.3",
        "relay has an unexpected target-network address",
    )
ingress_names = set(relay_networks) - {isolated_name}
require(len(ingress_names) == 1, "relay ingress network is ambiguous")
ingress_name = ingress_names.pop()
ingress = inspect("network", ingress_name)
require(ingress.get("Driver") == "bridge", "relay ingress is not a bridge")
require(ingress.get("Internal") is False, "relay ingress is unexpectedly internal")
require(
    (ingress.get("Options") or {}).get(
        "com.docker.network.bridge.host_binding_ipv4"
    ) == "127.0.0.1",
    "relay ingress does not default to loopback binding",
)
require(
    (relay_networks[ingress_name].get("IPAMConfig") or {}).get("IPv4Address")
    == "172.31.253.2",
    "relay has an unexpected ingress address",
)
require(
    relay_host.get("NetworkMode") == ingress_name,
    "relay ingress is not its primary network",
)
PY

"$compose" start target
docker exec --user www-data "$target" \
    php -d memory_limit=128M /opt/php2shell/wordpress/install.php
"$compose" start relay

PHP2SHELL_WORDPRESS_HOST_PORT="$host_port" \
    "$bundle_dir/scripts/wordpress-verify.sh"

succeeded=1
trap - EXIT HUP INT TERM
printf 'WordPress lab is ready at http://127.0.0.1:%s/index.php\n' "$host_port"
