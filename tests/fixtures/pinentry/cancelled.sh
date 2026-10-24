#!/usr/bin/env bash
# @file cancelled.sh
# @brief A pinentry whose user cancels the password dialog.
# @description GETPIN answers with the ERR code for cancelled.
set -euo pipefail
echo "OK scripted pinentry"
while IFS=' ' read -r -t 20 command _; do
  case "${command}" in
    GETPIN) echo "ERR 83886179 Operation cancelled" ;;
    BYE)
      echo "OK closing connection"
      exit 0
      ;;
    *) echo "OK" ;;
  esac
done
