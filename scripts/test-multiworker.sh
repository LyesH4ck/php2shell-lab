#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
container=${PHP2SHELL_TARGET_CONTAINER:-php2shell-vulnerable-lab}
verify_script=${PHP2SHELL_VERIFY_SCRIPT:-scripts/verify.sh}
application_profile=${PHP2SHELL_APPLICATION_PROFILE:-minimal}
results_dir=${PHP2SHELL_RESULTS_DIR:-results}
command=${*:-id}

case "$verify_script" in
    /*) ;;
    *) verify_script="$bundle_dir/$verify_script" ;;
esac
case "$results_dir" in
    /*) ;;
    *) results_dir="$bundle_dir/$results_dir" ;;
esac
case "$application_profile" in
    minimal|wordpress-7.1.3) ;;
    *)
        echo "Invalid PHP2SHELL_APPLICATION_PROFILE: $application_profile" >&2
        exit 2
        ;;
esac

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

worker_count=$(
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" |
        awk -F= '
            $1 == "PHP2SHELL_APACHE_WORKERS" {
                value = substr($0, index($0, "=") + 1)
            }
            END { print value }
        '
)
worker_count=${worker_count:-1}
case "$worker_count" in
    *[!0-9]*|'')
        echo "Invalid PHP2SHELL_APACHE_WORKERS in $container: $worker_count" >&2
        exit 2
        ;;
esac
if [ "$worker_count" -lt 2 ] || [ "$worker_count" -gt 16 ]; then
    echo "Multiworker test requires PHP2SHELL_APACHE_WORKERS in 2..16, got $worker_count" >&2
    exit 2
fi

"$verify_script"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
output_dir="$results_dir/$stamp-$$"
mkdir -p "$results_dir"
mkdir "$output_dir"

exploit_log=$(mktemp "$results_dir/.multiworker-exploit-log.XXXXXX")
exploit_status_file=$(mktemp "$results_dir/.multiworker-exploit-status.XXXXXX")
cleanup() {
    rm -f "$exploit_log" "$exploit_status_file"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

: >"$exploit_status_file"
set +e
(
    python3 -B "$bundle_dir/exploit/exploit_off.py" \
        --url "http://127.0.0.1:${host_port}/index.php" \
        --host-header 127.0.0.1:8088 \
        --cmd "$command" \
        --workers "$worker_count" \
        --output-dir "$output_dir" \
        -vv
    status=$?
    printf '%s\n' "$status" >"$exploit_status_file"
) 2>&1 | tee "$exploit_log"
pipeline_status=$?
set -e
mv "$exploit_log" "$output_dir/exploit.log"
exploit_log=

if [ ! -s "$exploit_status_file" ]; then
    echo "exploit process did not publish its exit status" >&2
    exploit_status=125
else
    exploit_status=$(cat "$exploit_status_file")
    case "$exploit_status" in
        *[!0-9]*|'')
            echo "invalid exploit exit status: $exploit_status" >&2
            exploit_status=125
            ;;
    esac
fi

follow_url="http://127.0.0.1:${host_port}/index.php"
: >"$output_dir/follow-up.headers"
: >"$output_dir/follow-up.body"
: >"$output_dir/follow-up.curl.stderr"
set +e
follow_status=$(curl --noproxy '*' -sS \
    -H 'Host: 127.0.0.1:8088' \
    -D "$output_dir/follow-up.headers" \
    -o "$output_dir/follow-up.body" \
    -w '%{http_code}' \
    "$follow_url" 2>"$output_dir/follow-up.curl.stderr")
curl_status=$?
set -e

set +e
"$verify_script"
post_verify_status=$?

python3 -B - \
    "$output_dir" \
    "$application_profile" \
    "$worker_count" \
    "$command" \
    "$exploit_status" \
    "$pipeline_status" \
    "$curl_status" \
    "$follow_status" \
    "$follow_url" \
    "$post_verify_status" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys


(
    output_text,
    application_profile,
    worker_text,
    command,
    exploit_exit_text,
    pipeline_exit_text,
    curl_exit_text,
    http_status,
    follow_url,
    post_verify_exit_text,
) = sys.argv[1:]
output_dir = Path(output_text)
worker_count = int(worker_text)
exploit_exit = int(exploit_exit_text)
pipeline_exit = int(pipeline_exit_text)
curl_exit = int(curl_exit_text)
post_verify_exit = int(post_verify_exit_text)

expected_bodies = {
    "minimal": b"php2shell isolated lab\n",
    "wordpress-7.1.3": (
        b"php2shell wordpress lab\n"
        b"wordpress=7.1.3\n"
        b"database=1\n"
        b"sqlite=1\n"
    ),
}
errors: list[str] = []


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_bytes(name: str) -> bytes:
    path = output_dir / name
    try:
        return path.read_bytes()
    except OSError as error:
        errors.append(f"cannot read {name}: {error}")
        return b""


def load_object(name: str) -> dict[str, object]:
    try:
        value = json.loads((output_dir / name).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        errors.append(f"cannot load {name}: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{name} root is not an object")
        return {}
    return value


result = load_object("result.json")
parking = load_object("worker-parking.json")

command_output = read_bytes("command-output.bin")
headers = read_bytes("follow-up.headers")
body = read_bytes("follow-up.body")
expected_body = expected_bodies[application_profile]
output_hash = sha256(command_output)
body_hash = sha256(body)
expected_body_hash = sha256(expected_body)

if exploit_exit != 0:
    errors.append(f"exploit exited with status {exploit_exit}")
if pipeline_exit != 0:
    errors.append(f"exploit logging pipeline exited with status {pipeline_exit}")
if result.get("status") != "RCE_OUTPUT_OBSERVED":
    errors.append("result status is not RCE_OUTPUT_OBSERVED")
if result.get("terminal_http_status") != 200:
    errors.append("terminal HTTP status is not 200")
if result.get("http_body_complete") is not True:
    errors.append("terminal HTTP body is incomplete")
if result.get("command") != command:
    errors.append("result command does not match the requested command")
if type(result.get("command_output_bytes")) is not int:
    errors.append("command_output_bytes is not an integer")
elif result["command_output_bytes"] <= 0:
    errors.append("terminal command output is empty")
elif result["command_output_bytes"] != len(command_output):
    errors.append("command-output.bin length does not match result.json")
if result.get("command_output_sha256") != output_hash:
    errors.append("command-output.bin SHA-256 does not match result.json")
if type(result.get("apache_worker_count")) is not int:
    errors.append("apache_worker_count is not an integer")
elif result["apache_worker_count"] != worker_count:
    errors.append(
        "apache_worker_count does not match the configured worker count"
    )
if type(result.get("parked_worker_count")) is not int:
    errors.append("parked_worker_count is not an integer")
elif result["parked_worker_count"] != worker_count - 1:
    errors.append("parked_worker_count is not worker_count - 1")
if result.get("worker_affinity") != "prefork-keepalive-fencing":
    errors.append("worker_affinity is not prefork-keepalive-fencing")

if parking.get("protocol") != "php2shell-prefork-keepalive-fencing/v1":
    errors.append("worker-parking.json protocol is unexpected")
if parking.get("configured_worker_count") != worker_count:
    errors.append("parking configured_worker_count is unexpected")
if parking.get("target_parked_worker_count") != worker_count - 1:
    errors.append("parking target_parked_worker_count is unexpected")
if parking.get("opened_parking_connection_count") != worker_count - 1:
    errors.append("parking opened connection count is unexpected")
if parking.get("active_parking_connections") != 0:
    errors.append("parking connections remained active after close")
if parking.get("affinity") != "prefork-keepalive-fencing":
    errors.append("parking affinity is unexpected")
if parking.get("closed") is not True:
    errors.append("parking connections were not recorded as closed")
parking_events = parking.get("events")
if not isinstance(parking_events, list):
    errors.append("parking event transcript is missing")
else:
    if any(
        isinstance(event, dict) and event.get("event") == "heartbeat-failed"
        for event in parking_events
    ):
        errors.append("parking transcript contains a failed heartbeat")
    opened = sorted(
        event.get("connection")
        for event in parking_events
        if isinstance(event, dict)
        and event.get("event") == "open"
        and type(event.get("connection")) is int
    )
    if opened != list(range(1, worker_count)):
        errors.append("parking transcript does not contain every opened connection")
    heartbeat_connections = {
        event.get("connection")
        for event in parking_events
        if isinstance(event, dict)
        and event.get("event") == "heartbeat"
        and type(event.get("connection")) is int
    }
    if heartbeat_connections != set(range(1, worker_count)):
        errors.append("parking transcript lacks a heartbeat for every connection")
    close_events = [
        event
        for event in parking_events
        if isinstance(event, dict) and event.get("event") == "close-all"
    ]
    if len(close_events) != 1 or close_events[0].get(
        "connection_count"
    ) != worker_count - 1:
        errors.append("parking transcript close-all event is unexpected")

if curl_exit != 0:
    errors.append(f"follow-up curl exited with status {curl_exit}")
if http_status != "200":
    errors.append(f"follow-up HTTP status is {http_status!r}, not '200'")
if not re.search(br"(?m)^HTTP/[0-9.]+ 200(?: |\r?$)", headers):
    errors.append("follow-up headers do not contain an HTTP 200 status line")
if body != expected_body:
    errors.append("follow-up HTTP body does not exactly match the lab profile")
if post_verify_exit != 0:
    errors.append(f"post-exploit lab verification exited with status {post_verify_exit}")

verification = {
    "protocol": "php2shell-multiworker-receipt/v1",
    "verified": not errors,
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    ),
    "application_profile": application_profile,
    "follow_up_url": follow_url,
    "configured_worker_count": worker_count,
    "expected_parked_worker_count": worker_count - 1,
    "expected_worker_affinity": "prefork-keepalive-fencing",
    "exploit_exit": exploit_exit,
    "exploit_pipeline_exit": pipeline_exit,
    "curl_exit": curl_exit,
    "follow_up_http_status": http_status,
    "post_verify_exit": post_verify_exit,
    "command_output_bytes": len(command_output),
    "command_output_sha256": output_hash,
    "follow_up_body_bytes": len(body),
    "follow_up_body_sha256": body_hash,
    "expected_follow_up_body_sha256": expected_body_hash,
    "errors": errors,
}
verification_path = output_dir / "multiworker-verification.json"
temporary_path = verification_path.with_name(
    f".{verification_path.name}.{id(verification)}.tmp"
)
temporary_path.write_text(
    json.dumps(verification, indent=2) + "\n", encoding="utf-8"
)
temporary_path.replace(verification_path)

if errors:
    for error in errors:
        print(f"MULTIWORKER_VERIFY_ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("MULTIWORKER_RECEIPT_OK")
print(f"worker_count={worker_count}")
print(f"parked_worker_count={worker_count - 1}")
print("worker_affinity=prefork-keepalive-fencing")
print(f"command_output_sha256={output_hash}")
print(f"follow_up_body_sha256={body_hash}")
PY
receipt_status=$?
set -e

if [ "$receipt_status" -ne 0 ] || [ "$post_verify_status" -ne 0 ]; then
    echo "Multiworker proof failed; diagnostic receipt: $output_dir" >&2
    exit 1
fi

printf 'MULTIWORKER_RCE_OK\n'
printf 'worker_count=%s\n' "$worker_count"
printf 'parked_worker_count=%s\n' "$((worker_count - 1))"
printf 'affinity=prefork-keepalive-fencing\n'
printf 'receipt=%s\n' "$output_dir"
