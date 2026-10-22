#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
container=${PHP2SHELL_TARGET_CONTAINER:-php2shell-vulnerable-lab}
verify_script=${PHP2SHELL_VERIFY_SCRIPT:-scripts/verify.sh}
application_profile=${PHP2SHELL_APPLICATION_PROFILE:-minimal}
results_dir=${PHP2SHELL_RESULTS_DIR:-results}
command=${*:-id}
sync_timeout=${PHP2SHELL_TERMINAL_SYNC_TIMEOUT:-120}
exploit_wait_timeout=${PHP2SHELL_EXPLOIT_WAIT_TIMEOUT:-900}

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

case "$sync_timeout" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_TERMINAL_SYNC_TIMEOUT: $sync_timeout" >&2; exit 2 ;;
esac
case "$exploit_wait_timeout" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_EXPLOIT_WAIT_TIMEOUT: $exploit_wait_timeout" >&2; exit 2 ;;
esac
[ "$sync_timeout" -gt 0 ] || { echo "Terminal sync timeout must be positive" >&2; exit 2; }
[ "$exploit_wait_timeout" -gt 0 ] || { echo "Exploit wait timeout must be positive" >&2; exit 2; }

if [ -z "${PHP2SHELL_HOST_PORT+x}" ] && [ -f "$bundle_dir/.env" ]; then
    PHP2SHELL_HOST_PORT=$(sed -n 's/^PHP2SHELL_HOST_PORT=//p' "$bundle_dir/.env" | tail -n 1)
fi
host_port=${PHP2SHELL_HOST_PORT:-9090}

"$verify_script"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
output_dir="$results_dir/$stamp-$$"
mkdir -p "$output_dir"

exploit_pid=
cleanup() {
    if [ -n "$exploit_pid" ] && kill -0 "$exploit_pid" 2>/dev/null; then
        kill "$exploit_pid" 2>/dev/null || true
        wait "$exploit_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

wait_for_checkpoint() {
    checkpoint=$1
    ready="$output_dir/$checkpoint.ready"
    deadline=$(($(date +%s) + exploit_wait_timeout))
    while [ ! -f "$ready" ]; do
        if ! kill -0 "$exploit_pid" 2>/dev/null; then
            set +e
            wait "$exploit_pid"
            early_status=$?
            set -e
            exploit_pid=
            echo "exploit exited before checkpoint $checkpoint (status $early_status)" >&2
            exit 1
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "timed out waiting for checkpoint $checkpoint" >&2
            exit 1
        fi
        sleep 0.05
    done
}

acknowledge_checkpoint() {
    checkpoint=$1
    ready="$output_dir/$checkpoint.ready"
    acknowledgement="$output_dir/$checkpoint.ack"
    acknowledgement_tmp="$output_dir/.$checkpoint.ack.$$"
    token=$(cat "$ready")
    [ -n "$token" ] || { echo "empty checkpoint token: $ready" >&2; exit 1; }
    printf '%s\n' "$token" >"$acknowledgement_tmp"
    mv "$acknowledgement_tmp" "$acknowledgement"
}

python3 -B "$bundle_dir/exploit/exploit_off.py" \
    --url "http://127.0.0.1:${host_port}/index.php" \
    --host-header 127.0.0.1:8088 \
    --cmd "$command" \
    --output-dir "$output_dir" \
    --terminal-sync-dir "$output_dir" \
    --terminal-sync-timeout "$sync_timeout" \
    -vv &
exploit_pid=$!

wait_for_checkpoint 01-before-rce-b
python3 -B "$bundle_dir/scripts/clean-terminal-evidence.py" snapshot \
    --container "$container" \
    --label before-rce-b \
    --output "$output_dir/clean-terminal-before-rce-b.json" \
    --fail-on-capture-errors
acknowledge_checkpoint 01-before-rce-b

wait_for_checkpoint 02-after-rce-b
python3 -B "$bundle_dir/scripts/clean-terminal-evidence.py" snapshot \
    --container "$container" \
    --label after-rce-b \
    --output "$output_dir/clean-terminal-after-rce-b.json"
acknowledge_checkpoint 02-after-rce-b

set +e
wait "$exploit_pid"
exploit_status=$?
set -e
exploit_pid=

follow_url="http://127.0.0.1:${host_port}/index.php"
set -- $(python3 -c 'import time; print(time.time_ns(), time.monotonic_ns())')
get_started_unix_ns=$1
get_started_monotonic_ns=$2
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
set -- $(python3 -c 'import time; print(time.time_ns(), time.monotonic_ns())')
get_completed_unix_ns=$1
get_completed_monotonic_ns=$2

python3 -B "$bundle_dir/scripts/clean-terminal-evidence.py" snapshot \
    --container "$container" \
    --label after-get \
    --output "$output_dir/clean-terminal-after-get.json"

python3 -B "$bundle_dir/scripts/clean-terminal-evidence.py" verify \
    --receipt "$output_dir" \
    --exploit-exit "$exploit_status" \
    --curl-exit "$curl_status" \
    --http-status "$follow_status" \
    --url "$follow_url" \
    --host-header 127.0.0.1:8088 \
    --application-profile "$application_profile" \
    --get-started-unix-ns "$get_started_unix_ns" \
    --get-completed-unix-ns "$get_completed_unix_ns" \
    --get-started-monotonic-ns "$get_started_monotonic_ns" \
    --get-completed-monotonic-ns "$get_completed_monotonic_ns"
