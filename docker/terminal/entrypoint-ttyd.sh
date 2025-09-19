#!/usr/bin/env bash
set -euo pipefail

# Default command to run inside ttyd - spawn a login shell
SHELL_CMD=${SHELL_CMD:-"/bin/bash"}
# Allow passing extra args to ttyd via environment. Include -w/--writable by default
# so the terminal accepts input (not readonly). Override TT_ARGS to customize.
TT_ARGS=${TT_ARGS:-"-p 7681 -W"}

# Ensure user environment is set
export LANG=en_US.UTF-8

# Start ttyd as the appuser user (already running as appuser)
exec ttyd $TT_ARGS $SHELL_CMD
