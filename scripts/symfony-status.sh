#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
host_port=${PHP2SHELL_SYMFONY_HOST_PORT:-9093}
export PHP2SHELL_SYMFONY_HOST_PORT="$host_port"

"$bundle_dir/scripts/symfony-compose-command.sh" ps
"$bundle_dir/scripts/symfony-verify.sh"
