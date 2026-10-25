#!/bin/sh
set -eu
exec "$(dirname "$0")/compose-command.sh" down --remove-orphans
