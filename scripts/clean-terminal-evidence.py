#!/usr/bin/env python3
"""Capture and verify Docker clean-terminal evidence for the lab harness."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any, Sequence


ERROR_LOG = "/tmp/php2shell-apache-error.log"
EVIDENCE_PROTOCOL = "php2shell-clean-terminal-evidence/v1"
SYNC_PROTOCOL = "php2shell-clean-terminal-sync/v1"
APPLICATION_PROFILE_BODIES = {
    "minimal": b"php2shell isolated lab\n",
    "wordpress-7.1.3": (
        b"php2shell wordpress lab\n"
        b"wordpress=7.1.3\n"
        b"database=1\n"
        b"sqlite=1\n"
    ),
}
APPLICATION_PROFILE_BODY_SHA256 = {
    "minimal": (
        "58e8a225fa3a8f081dac2b6e3beca6d75eeeddbe1e3e86de2edd8c433737d56f"
    ),
    "wordpress-7.1.3": (
        "0cab4b9edc46a4c17ba60cf00ebfb234eaec0abffa89e5c00bfa10aaf401b123"
    ),
}


def utc_from_ns(value: int) -> str:
    return dt.datetime.fromtimestamp(
        value / 1_000_000_000, tz=dt.timezone.utc
    ).isoformat(timespec="microseconds").replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.{id(value)}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_command(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return subprocess.CompletedProcess(arguments, 127, "", str(error))


def command_error(label: str, result: subprocess.CompletedProcess[str]) -> str:
    detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
    return f"{label} failed with exit {result.returncode}: {detail}"


def capture_snapshot(container: str, label: str, output: Path) -> dict[str, Any]:
    started_unix_ns = time.time_ns()
    started_monotonic_ns = time.monotonic_ns()
    errors: list[str] = []

    container_state: dict[str, Any] = {
        "id": None,
        "started_at": None,
        "restart_count": None,
        "running": None,
        "init_pid": None,
    }
    inspected = run_command(["docker", "inspect", container])
    if inspected.returncode:
        errors.append(command_error("docker inspect", inspected))
    else:
        try:
            document = json.loads(inspected.stdout)[0]
            state = document["State"]
            container_state = {
                "id": document["Id"],
                "started_at": state["StartedAt"],
                "restart_count": document["RestartCount"],
                "running": state["Running"],
                "init_pid": state["Pid"],
            }
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as error:
            errors.append(f"cannot parse docker inspect output: {error}")

    docker_top_pids: list[int] = []
    topped = run_command(["docker", "top", container, "-eo", "pid,user,comm"])
    if topped.returncode:
        errors.append(command_error("docker top", topped))
    else:
        for line in topped.stdout.splitlines():
            fields = line.split(None, 2)
            if len(fields) != 3 or not fields[0].isdigit():
                continue
            pid_text, user, command = fields
            if user in {"www-data", "33"} and command == "apache2":
                docker_top_pids.append(int(pid_text, 10))
        if len(docker_top_pids) != 1:
            errors.append(
                "expected exactly one www-data Apache worker from docker top, "
                f"got {docker_top_pids!r}"
            )

    namespace_count: int | None = None
    namespace_pid: int | None = None
    namespace_start_time: int | None = None

    log_state: dict[str, Any] = {
        "source": "docker exec target; stat/wc/sha256sum",
        "path": ERROR_LOG,
        "present": None,
        "size": None,
        "sha256": None,
        "device": None,
        "inode": None,
        "snapshot_stable": None,
    }
    metadata_script = r'''
set -eu
worker_rows=$(
    for status in /proc/[0-9]*/status; do
        [ -r "$status" ] || continue
        pid=${status#/proc/}
        pid=${pid%/status}
        [ -r "/proc/$pid/comm" ] && [ -r "/proc/$pid/stat" ] || continue
        uid=$(awk '$1 == "Uid:" {print $2; exit}' "$status")
        comm=$(cat "/proc/$pid/comm")
        if [ "$uid" = 33 ] && [ "$comm" = apache2 ]; then
            starttime=$(awk '{print $22}' "/proc/$pid/stat")
            printf '%s %s\n' "$pid" "$starttime"
        fi
    done
)
worker_count=$(printf '%s\n' "$worker_rows" | awk 'NF {count++} END {print count+0}')
worker_pid=-
worker_starttime=-
if [ "$worker_count" = 1 ]; then
    set -- $worker_rows
    worker_pid=$1
    worker_starttime=$2
fi
printf 'worker\t%s\t%s\t%s\n' \
    "$worker_count" "$worker_pid" "$worker_starttime"

path=/tmp/php2shell-apache-error.log
if [ ! -f "$path" ]; then
    printf 'log\tfalse\t0\t-\t-\t-\ttrue\n'
    exit 0
fi
set -- $(stat -c '%d %i' "$path")
device_before=$1
inode_before=$2
size_before=$(wc -c < "$path")
hash_line=$(sha256sum "$path")
hash=${hash_line%% *}
size_after=$(wc -c < "$path")
set -- $(stat -c '%d %i' "$path")
device_after=$1
inode_after=$2
stable=true
if [ "$size_before" != "$size_after" ] || \
   [ "$device_before" != "$device_after" ] || \
   [ "$inode_before" != "$inode_after" ]; then
    stable=false
fi
printf 'log\ttrue\t%s\t%s\t%s\t%s\t%s\n' \
    "$size_after" "$hash" "$device_after" "$inode_after" "$stable"
'''
    metadata = run_command(
        ["docker", "exec", container, "sh", "-c", metadata_script]
    )
    if metadata.returncode:
        errors.append(command_error("container worker/error-log snapshot", metadata))
    else:
        lines = metadata.stdout.strip().splitlines()
        worker_fields = lines[0].split("\t") if lines else []
        log_fields = lines[1].split("\t") if len(lines) > 1 else []
        if len(worker_fields) != 4 or worker_fields[0] != "worker":
            errors.append(f"malformed namespace-worker snapshot: {metadata.stdout!r}")
        else:
            try:
                namespace_count = int(worker_fields[1], 10)
                namespace_pid = (
                    None if worker_fields[2] == "-" else int(worker_fields[2], 10)
                )
                namespace_start_time = (
                    None if worker_fields[3] == "-" else int(worker_fields[3], 10)
                )
            except ValueError as error:
                errors.append(f"malformed namespace-worker metadata: {error}")
            if namespace_count != 1:
                errors.append(
                    "expected exactly one UID 33 Apache worker in the container "
                    f"PID namespace, got {namespace_count!r}"
                )

        if len(log_fields) != 7 or log_fields[0] != "log":
            errors.append(f"malformed error-log snapshot: {metadata.stdout!r}")
        else:
            _, present, size, digest, device, inode, stable = log_fields
            try:
                log_state = {
                    "source": "docker exec target; stat/wc/sha256sum",
                    "path": ERROR_LOG,
                    "present": present == "true",
                    "size": int(size, 10),
                    "sha256": None if digest == "-" else digest,
                    "device": None if device == "-" else int(device, 10),
                    "inode": None if inode == "-" else int(inode, 10),
                    "snapshot_stable": stable == "true",
                }
            except ValueError as error:
                errors.append(f"malformed error-log metadata: {error}")
            if present not in {"true", "false"} or stable not in {"true", "false"}:
                errors.append("invalid error-log boolean metadata")
            if digest != "-" and not re.fullmatch(r"[0-9a-f]{64}", digest):
                errors.append(f"invalid error-log SHA-256: {digest!r}")

    if container_state["running"] is not True:
        errors.append("container is not running")
    if log_state["present"] is not True:
        errors.append(f"Apache error log is absent: {ERROR_LOG}")
    if log_state["snapshot_stable"] is not True:
        errors.append("Apache error log changed while its snapshot was taken")

    completed_unix_ns = time.time_ns()
    completed_monotonic_ns = time.monotonic_ns()
    snapshot = {
        "label": label,
        "capture_started_unix_ns": started_unix_ns,
        "capture_started_at": utc_from_ns(started_unix_ns),
        "capture_completed_unix_ns": completed_unix_ns,
        "capture_completed_at": utc_from_ns(completed_unix_ns),
        "capture_started_monotonic_ns": started_monotonic_ns,
        "capture_completed_monotonic_ns": completed_monotonic_ns,
        "container": container_state,
        "worker": {
            "source": {
                "docker_top_pid": "docker top -eo pid,user,comm",
                "namespace_identity": (
                    "docker exec target; UID 33 apache2; "
                    "/proc/PID/stat field 22"
                ),
            },
            "docker_top_count": len(docker_top_pids),
            "docker_top_pid": (
                docker_top_pids[0] if len(docker_top_pids) == 1 else None
            ),
            "all_docker_top_pids": docker_top_pids,
            "namespace_count": namespace_count,
            "namespace_pid": namespace_pid,
            "namespace_start_time_ticks": namespace_start_time,
        },
        "error_log": log_state,
        "capture_errors": errors,
    }
    atomic_json(output, snapshot)
    return snapshot


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"cannot load {path.name}: {error}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{path.name} does not contain a JSON object")
        return {}
    return value


def read_bytes(path: Path, errors: list[str]) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        errors.append(f"cannot read {path.name}: {error}")
        return b""


def nested(value: dict[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def verify_receipt(arguments: argparse.Namespace) -> int:
    receipt = arguments.receipt.resolve()
    errors: list[str] = []
    application_profile = arguments.application_profile
    expected_body = APPLICATION_PROFILE_BODIES[application_profile]
    expected_body_sha256 = APPLICATION_PROFILE_BODY_SHA256[application_profile]
    if sha256(expected_body) != expected_body_sha256:
        errors.append(
            f"internal expected-body hash mismatch for {application_profile!r}"
        )
    snapshots = {
        "before_rce_b": load_json(
            receipt / "clean-terminal-before-rce-b.json", errors
        ),
        "after_rce_b": load_json(
            receipt / "clean-terminal-after-rce-b.json", errors
        ),
        "after_get": load_json(receipt / "clean-terminal-after-get.json", errors),
    }
    sync = load_json(receipt / "terminal-sync.json", errors)
    result = load_json(receipt / "result.json", errors)
    command_output = read_bytes(receipt / "command-output.bin", errors)
    headers = read_bytes(receipt / "follow-up.headers", errors)
    body = read_bytes(receipt / "follow-up.body", errors)
    curl_stderr = read_bytes(receipt / "follow-up.curl.stderr", errors)

    expected_labels = {
        "before_rce_b": "before-rce-b",
        "after_rce_b": "after-rce-b",
        "after_get": "after-get",
    }
    for key, expected_label in expected_labels.items():
        snapshot = snapshots[key]
        if snapshot.get("label") != expected_label:
            errors.append(f"{key} label is not {expected_label!r}")
        capture_errors = snapshot.get("capture_errors")
        if capture_errors:
            errors.extend(f"{key}: {item}" for item in capture_errors)

    baseline = snapshots["before_rce_b"]
    for key in ("after_rce_b", "after_get"):
        observed = snapshots[key]
        for field in ("id", "started_at", "restart_count", "init_pid"):
            if nested(observed, "container", field) != nested(
                baseline, "container", field
            ):
                errors.append(f"container {field} changed at {key}")
        if nested(observed, "container", "running") is not True:
            errors.append(f"container was not running at {key}")
        for field in (
            "docker_top_pid",
            "namespace_pid",
            "namespace_start_time_ticks",
        ):
            if nested(observed, "worker", field) != nested(baseline, "worker", field):
                errors.append(f"Apache worker {field} changed at {key}")
        for field in ("device", "inode", "size", "sha256"):
            if nested(observed, "error_log", field) != nested(
                baseline, "error_log", field
            ):
                errors.append(f"Apache error-log {field} changed at {key}")

    if nested(baseline, "worker", "docker_top_count") != 1:
        errors.append("baseline did not contain exactly one docker-top Apache worker")
    if nested(baseline, "worker", "namespace_count") != 1:
        errors.append("baseline did not contain exactly one namespace Apache worker")
    if nested(baseline, "worker", "namespace_start_time_ticks") is None:
        errors.append("baseline namespace worker start time is missing")
    if nested(baseline, "error_log", "present") is not True:
        errors.append("baseline Apache error log is missing")
    if nested(baseline, "error_log", "sha256") is None:
        errors.append("baseline Apache error-log hash is missing")

    events = sync.get("events") if isinstance(sync.get("events"), list) else []
    if sync.get("protocol") != SYNC_PROTOCOL:
        errors.append("terminal sync protocol is missing or unsupported")
    if not isinstance(sync.get("session"), str) or not re.fullmatch(
        r"[0-9a-f]{32}", sync["session"]
    ):
        errors.append("terminal sync session token is missing or malformed")
    if [
        (event.get("sequence"), event.get("checkpoint"))
        for event in events
        if isinstance(event, dict)
    ] != [(1, "before-rce-b"), (2, "after-rce-b")]:
        errors.append("terminal sync checkpoint sequence is incomplete")
    event_by_name = {
        event.get("checkpoint"): event for event in events if isinstance(event, dict)
    }
    barrier_files: dict[str, dict[str, Any]] = {}
    for checkpoint, snapshot_key in (
        ("before-rce-b", "before_rce_b"),
        ("after-rce-b", "after_rce_b"),
    ):
        event = event_by_name.get(checkpoint, {})
        snapshot = snapshots[snapshot_key]
        ready_name = event.get("ready_file")
        ack_name = event.get("ack_file")
        sequence = event.get("sequence")
        expected_stem = (
            f"{sequence:02d}-{checkpoint}" if type(sequence) is int else None
        )
        ready_data = b""
        ack_data = b""
        if (
            not isinstance(ready_name, str)
            or Path(ready_name).name != ready_name
            or ready_name != f"{expected_stem}.ready"
        ):
            errors.append(f"invalid ready-marker name at {checkpoint}")
        else:
            ready_data = read_bytes(receipt / ready_name, errors)
        if (
            not isinstance(ack_name, str)
            or Path(ack_name).name != ack_name
            or ack_name != f"{expected_stem}.ack"
        ):
            errors.append(f"invalid acknowledgement name at {checkpoint}")
        else:
            ack_data = read_bytes(receipt / ack_name, errors)
        barrier_files[checkpoint] = {
            "ready_file": ready_name,
            "ready_sha256": sha256(ready_data),
            "ack_file": ack_name,
            "ack_sha256": sha256(ack_data),
            "byte_identical": bool(ready_data) and ready_data == ack_data,
        }
        if not ready_data or ready_data != ack_data:
            errors.append(f"marker/acknowledgement mismatch at {checkpoint}")
        else:
            try:
                token = ready_data.decode("ascii").strip()
            except UnicodeDecodeError:
                token = ""
            expected_token = re.fullmatch(
                rf"{re.escape(str(sync.get('session', '')))}:"
                rf"{sequence}:{re.escape(checkpoint)}:[0-9a-f]{{32}}",
                token,
            )
            if expected_token is None:
                errors.append(f"invalid barrier token at {checkpoint}")
        if event.get("state") != "acknowledged":
            errors.append(f"terminal checkpoint {checkpoint} was not acknowledged")
        ready = event.get("ready_unix_ns")
        acknowledged = event.get("ack_unix_ns")
        capture_start = snapshot.get("capture_started_unix_ns")
        capture_end = snapshot.get("capture_completed_unix_ns")
        if not all(isinstance(item, int) for item in (ready, acknowledged, capture_start, capture_end)):
            errors.append(f"terminal checkpoint timing is incomplete at {checkpoint}")
        elif not ready <= capture_start <= capture_end <= acknowledged:
            errors.append(
                f"snapshot at {checkpoint} was not enclosed by its sync barrier"
            )

    before_ack = nested(event_by_name.get("before-rce-b", {}), "ack_unix_ns")
    after_ready = nested(
        event_by_name.get("after-rce-b", {}), "ready_unix_ns"
    )
    if not isinstance(before_ack, int) or not isinstance(after_ready, int):
        errors.append("terminal checkpoint ordering metadata is incomplete")
    elif before_ack > after_ready:
        errors.append("after-rce-b checkpoint preceded the before-rce-b acknowledgement")

    if arguments.exploit_exit != 0:
        errors.append(f"exploit exited with status {arguments.exploit_exit}")
    if result.get("status") != "RCE_OUTPUT_OBSERVED":
        errors.append("result status is not RCE_OUTPUT_OBSERVED")
    if result.get("terminal_http_status") != 200:
        errors.append("terminal HTTP status is not 200")
    if result.get("http_body_complete") is not True:
        errors.append("terminal HTTP body is incomplete")
    if not isinstance(result.get("command_output_bytes"), int) or result.get(
        "command_output_bytes", 0
    ) <= 0:
        errors.append("terminal command output is empty")
    if result.get("command_output_bytes") != len(command_output):
        errors.append("command-output.bin length does not match result.json")
    if result.get("command_output_sha256") != sha256(command_output):
        errors.append("command-output.bin SHA-256 does not match result.json")

    if arguments.curl_exit != 0:
        errors.append(f"follow-up curl exited with status {arguments.curl_exit}")
    if arguments.http_status != "200":
        errors.append(f"follow-up HTTP status is {arguments.http_status!r}, not '200'")
    if arguments.get_started_unix_ns > arguments.get_completed_unix_ns:
        errors.append("follow-up GET completion time precedes its start time")
    after_ack = nested(event_by_name.get("after-rce-b", {}), "ack_unix_ns")
    if isinstance(after_ack, int) and after_ack > arguments.get_started_unix_ns:
        errors.append("follow-up GET started before after-rce-b was acknowledged")
    if body != expected_body:
        errors.append("follow-up HTTP body does not match the lab health response")
    after_get_start = snapshots["after_get"].get("capture_started_unix_ns")
    if not isinstance(after_get_start, int) or (
        after_get_start < arguments.get_completed_unix_ns
    ):
        errors.append("after-GET snapshot did not start after curl completed")

    snapshot_values = list(snapshots.values())
    same_container = nested(baseline, "container", "running") is True and all(
        nested(snapshot, "container", "running") is True
        and all(
            nested(snapshot, "container", field)
            == nested(baseline, "container", field)
            for field in ("id", "started_at", "restart_count", "init_pid")
        )
        for snapshot in snapshot_values
    )
    same_worker = (
        nested(baseline, "worker", "docker_top_count") == 1
        and nested(baseline, "worker", "namespace_count") == 1
        and nested(baseline, "worker", "docker_top_pid") is not None
        and nested(baseline, "worker", "namespace_pid") is not None
        and nested(baseline, "worker", "namespace_start_time_ticks") is not None
        and all(
            nested(snapshot, "worker", "docker_top_count") == 1
            and nested(snapshot, "worker", "namespace_count") == 1
            and nested(snapshot, "worker", "docker_top_pid")
            == nested(baseline, "worker", "docker_top_pid")
            and nested(snapshot, "worker", "namespace_pid")
            == nested(baseline, "worker", "namespace_pid")
            and nested(snapshot, "worker", "namespace_start_time_ticks")
            == nested(baseline, "worker", "namespace_start_time_ticks")
            for snapshot in snapshot_values
        )
    )
    same_error_log = (
        nested(baseline, "error_log", "present") is True
        and nested(baseline, "error_log", "sha256") is not None
        and all(
            nested(snapshot, "error_log", "present") is True
            and nested(snapshot, "error_log", "snapshot_stable") is True
            and all(
                nested(snapshot, "error_log", field)
                == nested(baseline, "error_log", field)
                for field in ("device", "inode", "size", "sha256")
            )
            for snapshot in snapshot_values
        )
    )
    barriers_valid = not any(
        "sync barrier" in item
        or "checkpoint timing" in item
        or "checkpoint sequence" in item
        or "checkpoint ordering" in item
        or "checkpoint preceded" in item
        or "session token" in item
        or "marker/acknowledgement" in item
        or "barrier token" in item
        or "marker name" in item
        or "acknowledgement name" in item
        or "was not acknowledged" in item
        or "started before after-rce-b" in item
        for item in errors
    )
    invariants = {
        "same_container": same_container,
        "same_worker_docker_top_pid_namespace_pid_and_start_time": same_worker,
        "same_error_log_identity_size_and_sha256": same_error_log,
        "snapshots_enclosed_by_barriers": barriers_valid,
        "follow_up_http_200": arguments.curl_exit == 0
        and arguments.http_status == "200"
        and body == expected_body,
    }
    for name, value in invariants.items():
        if not value:
            errors.append(f"invariant failed: {name}")
    follow_up = {
        "url": arguments.url,
        "host_header": arguments.host_header,
        "application_profile": application_profile,
        "expected_body_sha256": expected_body_sha256,
        "curl_exit": arguments.curl_exit,
        "http_status": arguments.http_status,
        "started_unix_ns": arguments.get_started_unix_ns,
        "started_at": utc_from_ns(arguments.get_started_unix_ns),
        "completed_unix_ns": arguments.get_completed_unix_ns,
        "completed_at": utc_from_ns(arguments.get_completed_unix_ns),
        "started_monotonic_ns": arguments.get_started_monotonic_ns,
        "completed_monotonic_ns": arguments.get_completed_monotonic_ns,
        "headers_bytes": len(headers),
        "headers_sha256": sha256(headers),
        "body_bytes": len(body),
        "body_sha256": sha256(body),
        "curl_stderr_bytes": len(curl_stderr),
        "curl_stderr_sha256": sha256(curl_stderr),
    }
    evidence = {
        "protocol": EVIDENCE_PROTOCOL,
        "cross_process_ordering_clock": "unix_ns (time.time_ns)",
        "status": "CLEAN_TERMINAL_OK" if not errors else "FAILED",
        "application_profile": application_profile,
        "expected_body_sha256": expected_body_sha256,
        "exploit_exit": arguments.exploit_exit,
        "terminal_sync": sync,
        "barrier_files": barrier_files,
        "snapshots": snapshots,
        "follow_up_get": follow_up,
        "result": result,
        "command_output_artifact": {
            "bytes": len(command_output),
            "sha256": sha256(command_output),
        },
        "invariants": invariants,
        "errors": errors,
    }
    atomic_json(receipt / "clean-terminal-evidence.json", evidence)

    transcript = [
        f"protocol={EVIDENCE_PROTOCOL}",
        "cross_process_ordering_clock=unix_ns (time.time_ns)",
        f"status={evidence['status']}",
        f"application_profile={application_profile}",
        f"expected_body_sha256={expected_body_sha256}",
        f"exploit_exit={arguments.exploit_exit}",
    ]
    for key in ("before_rce_b", "after_rce_b", "after_get"):
        snapshot = snapshots[key]
        transcript.extend(
            [
                f"{key}.capture_started_at={snapshot.get('capture_started_at')}",
                f"{key}.capture_completed_at={snapshot.get('capture_completed_at')}",
                f"{key}.worker_docker_top_pid={nested(snapshot, 'worker', 'docker_top_pid')}",
                f"{key}.worker_namespace_pid={nested(snapshot, 'worker', 'namespace_pid')}",
                f"{key}.worker_namespace_start_time_ticks={nested(snapshot, 'worker', 'namespace_start_time_ticks')}",
                f"{key}.error_log_size={nested(snapshot, 'error_log', 'size')}",
                f"{key}.error_log_sha256={nested(snapshot, 'error_log', 'sha256')}",
            ]
        )
    for checkpoint in ("before-rce-b", "after-rce-b"):
        barrier = barrier_files.get(checkpoint, {})
        transcript.extend(
            [
                f"{checkpoint}.ready_sha256={barrier.get('ready_sha256')}",
                f"{checkpoint}.ack_sha256={barrier.get('ack_sha256')}",
                f"{checkpoint}.marker_ack_identical={str(barrier.get('byte_identical')).lower()}",
            ]
        )
    transcript.extend(
        [
            f"follow_up_get.started_at={follow_up['started_at']}",
            f"follow_up_get.completed_at={follow_up['completed_at']}",
            f"follow_up_get.curl_exit={arguments.curl_exit}",
            f"follow_up_get.http_status={arguments.http_status}",
            f"follow_up_get.body_sha256={follow_up['body_sha256']}",
        ]
    )
    transcript.extend(f"invariant.{key}={str(value).lower()}" for key, value in invariants.items())
    transcript.extend(f"error={item}" for item in errors)
    (receipt / "clean-terminal-transcript.txt").write_text(
        "\n".join(transcript) + "\n", encoding="utf-8"
    )

    if errors:
        for error in errors:
            print(f"CLEAN_TERMINAL_ERROR: {error}", file=sys.stderr)
        return 1

    print("RCE_RESULT_OK")
    print(f"output_bytes={result['command_output_bytes']}")
    print(f"output_sha256={result['command_output_sha256']}")
    print("CLEAN_TERMINAL_OK")
    print(f"worker_docker_top_pid={nested(baseline, 'worker', 'docker_top_pid')}")
    print(f"worker_namespace_pid={nested(baseline, 'worker', 'namespace_pid')}")
    print(
        "worker_namespace_start_time_ticks="
        f"{nested(baseline, 'worker', 'namespace_start_time_ticks')}"
    )
    print(f"error_log_size={nested(baseline, 'error_log', 'size')}")
    print(f"error_log_sha256={nested(baseline, 'error_log', 'sha256')}")
    print(f"receipt={receipt}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="action", required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--container", required=True)
    snapshot.add_argument("--label", required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    snapshot.add_argument("--fail-on-capture-errors", action="store_true")

    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--exploit-exit", type=int, required=True)
    verify.add_argument("--curl-exit", type=int, required=True)
    verify.add_argument("--http-status", required=True)
    verify.add_argument("--url", required=True)
    verify.add_argument("--host-header", required=True)
    verify.add_argument(
        "--application-profile",
        choices=tuple(APPLICATION_PROFILE_BODIES),
        default="minimal",
    )
    verify.add_argument("--get-started-unix-ns", type=int, required=True)
    verify.add_argument("--get-completed-unix-ns", type=int, required=True)
    verify.add_argument("--get-started-monotonic-ns", type=int, required=True)
    verify.add_argument("--get-completed-monotonic-ns", type=int, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.action == "snapshot":
        snapshot = capture_snapshot(
            arguments.container, arguments.label, arguments.output.resolve()
        )
        if arguments.fail_on_capture_errors and snapshot["capture_errors"]:
            for error in snapshot["capture_errors"]:
                print(f"SNAPSHOT_ERROR: {error}", file=sys.stderr)
            return 1
        return 0
    return verify_receipt(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
