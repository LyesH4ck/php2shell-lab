#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
host_port=${PHP2SHELL_SYMFONY_HOST_PORT:-9093}

export PHP2SHELL_TARGET_CONTAINER=php2shell-symfony-lab
export PHP2SHELL_VERIFY_SCRIPT="$bundle_dir/scripts/symfony-verify.sh"
export PHP2SHELL_APPLICATION_PROFILE=symfony-7.4.21
export PHP2SHELL_RESULTS_DIR="$bundle_dir/results/symfony"
export PHP2SHELL_HOST_PORT="$host_port"
export PHP2SHELL_SYMFONY_HOST_PORT="$host_port"

exec "$bundle_dir/scripts/test.sh" "$@"
