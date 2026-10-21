#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="$bundle_dir/scripts/compose-command.sh"

if [ -z "${PHP2SHELL_HOST_PORT+x}" ] && [ -f "$bundle_dir/.env" ]; then
    PHP2SHELL_HOST_PORT=$(sed -n 's/^PHP2SHELL_HOST_PORT=//p' "$bundle_dir/.env" | tail -n 1)
fi
host_port=${PHP2SHELL_HOST_PORT:-80}
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
export PHP2SHELL_HOST_PORT="$host_port"

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
            exit 3
        fi
        ;;
esac

# Refuse to reuse a running target attached to the old, host-addressable
# internal bridge. The operator can remove it with scripts/down.sh first.
python3 - <<'PY'
import json
import subprocess

name = "php2shell-vulnerable-lab"
try:
    target = json.loads(subprocess.check_output(
        ["docker", "inspect", name], stderr=subprocess.DEVNULL
    ))[0]
except subprocess.CalledProcessError:
    raise SystemExit(0)

if not target["State"]["Running"]:
    raise SystemExit(0)

networks = target["NetworkSettings"]["Networks"]
if len(networks) != 1:
    raise SystemExit(
        "Refusing to reuse running target with unexpected networks; run scripts/down.sh first."
    )
network_name, endpoint = next(iter(networks.items()))
network = json.loads(subprocess.check_output(
    ["docker", "network", "inspect", network_name]
))[0]
option = (network.get("Options") or {}).get(
    "com.docker.network.bridge.gateway_mode_ipv4"
)
if (
    network.get("Driver") != "bridge"
    or network.get("Internal") is not True
    or option != "isolated"
    or endpoint.get("Gateway") not in (None, "")
):
    raise SystemExit(
        "Refusing to reuse host-addressable target network; run scripts/down.sh first."
    )
PY

relay_running=false
if docker inspect php2shell-loopback-relay >/dev/null 2>&1; then
    relay_running=$(docker inspect -f '{{.State.Running}}' php2shell-loopback-relay)
fi
if [ "$relay_running" != true ]; then
    python3 - "$host_port" <<'PY'
import socket, sys
port = int(sys.argv[1])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", port))
except OSError as exc:
    raise SystemExit(f"127.0.0.1:{port} is unavailable: {exc}")
finally:
    s.close()
PY
fi

"$compose" config >/dev/null
"$compose" build --pull

# Create the networks and containers without starting the vulnerable process.
# This lets us reject a silently reused or misconfigured bridge before exposure.
if ! "$compose" up --no-start; then
    "$compose" stop >/dev/null 2>&1 || true
    echo "Pre-start creation failed; services were stopped." >&2
    exit 1
fi
if ! python3 - "$host_port" <<'PY'
import json
import subprocess
import sys

expected_port = sys.argv[1]


def inspect(kind, name):
    return json.loads(subprocess.check_output(
        ["docker", kind, "inspect", name]
    ))[0]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


target = inspect("container", "php2shell-vulnerable-lab")
relay = inspect("container", "php2shell-loopback-relay")

target_host = target["HostConfig"]
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
require(not (target_host.get("PortBindings") or {}), "target publishes a port")

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
then
    "$compose" stop >/dev/null 2>&1 || true
    echo "Pre-start isolation check failed; services were stopped." >&2
    exit 1
fi

if ! "$compose" start; then
    "$compose" stop >/dev/null 2>&1 || true
    echo "Lab start failed; services were stopped." >&2
    exit 1
fi
if ! "$bundle_dir/scripts/verify.sh"; then
    "$compose" stop >/dev/null 2>&1 || true
    echo "Verification failed; services were stopped." >&2
    exit 1
fi
