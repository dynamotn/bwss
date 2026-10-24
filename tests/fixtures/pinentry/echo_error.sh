#!/usr/bin/env bash
# @file echo_error.sh
# @brief A pinentry that answers GETPIN with the text of SETERROR.
# @description A test can see by it what the client showed in the dialog.
set -euo pipefail
echo "OK scripted pinentry"
error=""
while IFS=' ' read -r -t 20 command arg; do
  case "${command}" in
    SETERROR)
      error="${arg}"
      echo "OK"
      ;;
    GETPIN)
      echo "D ${error}"
      echo "OK"
      ;;
    BYE)
      echo "OK closing connection"
      exit 0
      ;;
    *) echo "OK" ;;
  esac
done
