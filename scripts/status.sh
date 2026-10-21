#!/bin/sh
set -eu

bundle_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
"$bundle_dir/scripts/compose-command.sh" ps
"$bundle_dir/scripts/verify.sh"

