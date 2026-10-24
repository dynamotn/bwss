#!/usr/bin/env bash
# @file stdin_closed.sh
# @brief A pinentry that closes its input before it greets.
# @description Whatever the client sends next cannot be delivered. The program then stays around until it is killed.
set -euo pipefail
exec <&-
echo "OK scripted pinentry"
exec sleep 30
