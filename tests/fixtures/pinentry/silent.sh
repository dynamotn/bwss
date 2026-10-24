#!/usr/bin/env bash
# @file silent.sh
# @brief A pinentry that greets and then never answers.
# @description It stays around until it is killed.
set -euo pipefail
echo "OK scripted pinentry"
exec sleep 30
