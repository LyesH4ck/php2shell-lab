#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
host_port=${PHP2SHELL_WORDPRESS_HOST_PORT:-9091}

case "$host_port" in
    *[!0-9]*|'') echo "Invalid PHP2SHELL_WORDPRESS_HOST_PORT: $host_port" >&2; exit 2 ;;
esac

export PHP2SHELL_TARGET_CONTAINER=php2shell-wordpress-lab
export PHP2SHELL_VERIFY_SCRIPT="$bundle_dir/scripts/wordpress-verify.sh"
export PHP2SHELL_APPLICATION_PROFILE=wordpress-7.1.3
export PHP2SHELL_RESULTS_DIR="$bundle_dir/results/wordpress"
export PHP2SHELL_HOST_PORT="$host_port"
export PHP2SHELL_WORDPRESS_HOST_PORT="$host_port"

exec "$bundle_dir/scripts/test.sh" "$@"
