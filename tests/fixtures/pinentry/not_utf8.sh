#!/usr/bin/env bash
# @file not_utf8.sh
# @brief A pinentry whose greeting is not text.
# @description It sends two bytes that are not UTF-8.
set -euo pipefail
printf '\377\376\n'
