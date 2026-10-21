#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
"$bundle_dir/scripts/compose-command.sh" down
printf 'Lab stopped. Receipts remain in %s/results/.\n' "$bundle_dir"
