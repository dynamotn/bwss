#!/usr/bin/env bash
# @file chunked_pin.sh
# @brief A pinentry whose PIN comes in two D lines.
# @description The second line ends in an escape. Status and comment lines come in between, which a client ignores.
set -euo pipefail
echo "OK scripted pinentry"
while IFS=' ' read -r -t 20 command _; do
  case "${command}" in
    GETPIN)
      echo "# thinking"
      echo "S PROGRESS pin"
      echo "D abc"
      echo "D 100%25"
      echo "OK"
      ;;
    BYE)
      echo "OK closing connection"
      exit 0
      ;;
    *) echo "OK" ;;
  esac
done
