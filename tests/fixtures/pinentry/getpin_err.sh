#!/usr/bin/env bash
# @file getpin_err.sh
# @brief A pinentry that cannot ask.
# @description GETPIN fails with a code that is not the one for cancelled, as pinentry-curses does without a terminal.
set -euo pipefail
echo "OK scripted pinentry"
while IFS=' ' read -r -t 20 command _; do
  case "${command}" in
    GETPIN) echo "ERR 83918950 Inappropriate ioctl for device" ;;
    BYE)
      echo "OK closing connection"
      exit 0
      ;;
    *) echo "OK" ;;
  esac
done
