#!/usr/bin/env bash
# @file greeting_err.sh
# @brief A pinentry that refuses at the greeting.
# @description No display, say: the greeting is an ERR reply instead of OK.
set -euo pipefail
echo "ERR 83886360 no display"
