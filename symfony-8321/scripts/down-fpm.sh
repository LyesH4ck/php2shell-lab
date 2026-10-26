#!/bin/sh
set -eu
exec "$(dirname "$0")/compose-fpm-command.sh" down --remove-orphans
