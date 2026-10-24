#!/usr/bin/env bash
# @file set_err.sh
# @brief A pinentry that refuses the first option it is given.
# @description It greets, reads one command and answers it with an ERR reply.
set -euo pipefail
echo "OK scripted pinentry"
IFS= read -r -t 20 _command
echo "ERR 83886360 option refused"
