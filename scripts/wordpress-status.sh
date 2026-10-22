#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
host_port=${PHP2SHELL_WORDPRESS_HOST_PORT:-9091}
export PHP2SHELL_WORDPRESS_HOST_PORT="$host_port"

"$bundle_dir/scripts/wordpress-compose-command.sh" ps
"$bundle_dir/scripts/wordpress-verify.sh"
