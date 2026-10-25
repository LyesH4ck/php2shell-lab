#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
compose="$bundle_dir/scripts/symfony-compose-command.sh"
target=php2shell-symfony-lab
relay=php2shell-symfony-relay
host_port=${PHP2SHELL_SYMFONY_HOST_PORT:-9093}

case "$host_port" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_SYMFONY_HOST_PORT: $host_port" >&2; exit 2 ;;
esac
host_port=$(python3 - "$host_port" <<'PY'
import sys
port = int(sys.argv[1])
if not 1 <= port <= 65535:
    raise SystemExit(f"PHP2SHELL_SYMFONY_HOST_PORT must be in 1..65535, got {port}")
print(port)
PY
)
export PHP2SHELL_SYMFONY_HOST_PORT="$host_port"

if [ -z "${PHP2SHELL_APACHE_WORKERS+x}" ] && [ -f "$bundle_dir/.env" ]; then
    PHP2SHELL_APACHE_WORKERS=$(sed -n 's/^PHP2SHELL_APACHE_WORKERS=//p' "$bundle_dir/.env" | tail -n 1)
fi
apache_workers=${PHP2SHELL_APACHE_WORKERS:-1}
case "$apache_workers" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_APACHE_WORKERS: $apache_workers" >&2; exit 2 ;;
esac
apache_workers=$(python3 - "$apache_workers" <<'PY'
import sys
workers = int(sys.argv[1])
if not 1 <= workers <= 16:
    raise SystemExit(f"PHP2SHELL_APACHE_WORKERS must be in 1..16, got {workers}")
print(workers)
PY
)
export PHP2SHELL_APACHE_WORKERS="$apache_workers"

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
server_arch=$(docker info --format '{{.Architecture}}')
case "$server_arch" in
    x86_64|amd64) ;;
    *)
        [ "${ALLOW_EMULATION:-0}" = 1 ] || {
            echo "Docker server is $server_arch, not native amd64." >&2
            exit 3
        }
        ;;
esac
server_version=$(docker version --format '{{.Server.Version}}')
server_major=${server_version%%.*}
case "$server_major" in
    *[!0-9]*|'') echo "Cannot determine Docker Engine version: $server_version" >&2; exit 4 ;;
esac
[ "$server_major" -ge 28 ] || {
    echo "Docker Engine 28+ is required (found $server_version)." >&2
    exit 4
}

succeeded=0
cleanup_on_failure() {
    [ "$succeeded" -eq 1 ] && return
    "$compose" down --remove-orphans >/dev/null 2>&1 || true
    echo "Symfony lab setup failed; its services were stopped." >&2
}
trap cleanup_on_failure EXIT
trap 'exit 130' HUP INT TERM

"$compose" config >/dev/null
"$compose" build --pull target
"$compose" down --remove-orphans >/dev/null 2>&1 || true

python3 - "$host_port" <<'PY'
import socket
import sys
port = int(sys.argv[1])
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind(("127.0.0.1", port))
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

target_name, relay_name, port = sys.argv[1:]

def inspect(kind, name):
    return json.loads(subprocess.check_output(["docker", kind, "inspect", name]))[0]

def require(value, message):
    if not value:
        raise SystemExit(message)

target = inspect("container", target_name)
relay = inspect("container", relay_name)
require(not (target["HostConfig"].get("PortBindings") or {}), "target publishes a port")
require(
    relay["HostConfig"].get("PortBindings") == {
        "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": port}]
    },
    "relay is not bound to the requested loopback port",
)
target_networks = target["NetworkSettings"]["Networks"]
require(len(target_networks) == 1, "target must have exactly one network")
isolated_name = next(iter(target_networks))
isolated = inspect("network", isolated_name)
require(isolated.get("Internal") is True, "target network is not internal")
require(
    (isolated.get("Options") or {}).get(
        "com.docker.network.bridge.gateway_mode_ipv4"
    ) == "isolated",
    "target bridge is not in isolated gateway mode",
)
require(
    all(not item.get("Gateway") for item in isolated["IPAM"].get("Config") or []),
    "target network declares a gateway",
)
require(
    len(relay["NetworkSettings"]["Networks"]) in (1, 2),
    "relay topology is unexpected before start",
)
PY

"$compose" start target relay
PHP2SHELL_SYMFONY_HOST_PORT="$host_port" "$bundle_dir/scripts/symfony-verify.sh"

succeeded=1
trap - EXIT HUP INT TERM
printf 'Symfony lab is ready at http://127.0.0.1:%s/index.php\n' "$host_port"
