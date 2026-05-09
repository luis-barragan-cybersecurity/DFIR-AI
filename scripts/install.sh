#!/usr/bin/env bash
# Compat shim — delegates to install-sift.sh (Sub-Plan 05).
exec "$(dirname "$0")/install-sift.sh" --install "$@"
