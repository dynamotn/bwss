#!/usr/bin/env bash
# @file coverage.sh
# @brief Line coverage of src/ over the unit and end-to-end tests combined.
# @description Runs inside the bwss-e2e image (tests/e2e/Dockerfile), with a
#   reachable Vaultwarden at BW_E2E_URL and the sources mounted at /src.
#   COVERAGE_MIN (default 100) is the line-coverage threshold. See README.
set -euo pipefail

ignore='(^|/)src/(perf|backend/tests)\.rs$'

# Instrument every build and point every process at one profile directory.
env_script="$(cargo llvm-cov show-env --sh --remap-path-prefix)"
# shellcheck source=/dev/null # the exports come from cargo llvm-cov at run time
. /dev/stdin <<< "${env_script}"
profile_dir="${CARGO_LLVM_COV_TARGET_DIR:?}"
mkdir -p "${profile_dir}"

# `cargo llvm-cov clean` refuses a target directory without CACHEDIR.TAG and
# would leave stale builds that skew the report, so create the tag first.
cachedir_tag="${profile_dir}/CACHEDIR.TAG"
if [[ ! -f "${cachedir_tag}" ]]; then
  printf '%s\n' \
    'Signature: 8a477f597d28d172789f06886806bc55' \
    '# This file is a cache directory tag created by scripts/coverage.sh.' \
    '# For information about cache directory tags see https://bford.info/cachedir/' \
    > "${cachedir_tag}"
fi
cargo llvm-cov clean --workspace

# The daemons that pytest starts run as `tester`, so it must be able to write
# their .profraw files (written at exit, hence SIGTERM in the fixtures).
chmod 1777 "${profile_dir}"

cargo build --locked
cargo test --locked

# bwss refuses uid 0, so the end-to-end tests run as an ordinary user.
BWSS_BIN="${profile_dir}/debug/bwss" \
  setpriv --reuid=tester --regid=tester --init-groups env HOME=/home/tester \
  dbus-run-session -- python3 -m pytest -q -rf -p no:cacheprovider tests/e2e

# The lcov data stays in the target volume; it is copied next to the sources
# only when they are mounted writable.
lcov="${profile_dir}/lcov.info"
cargo llvm-cov report --ignore-filename-regex "${ignore}" --lcov --output-path "${lcov}"
echo "lcov data: ${lcov}"
{ mkdir -p /src/target && cp "${lcov}" /src/target/lcov.info; } \
  || echo "note: /src is not writable, lcov.info was not copied"
cargo llvm-cov report --ignore-filename-regex "${ignore}" --show-missing-lines \
  --fail-under-lines "${COVERAGE_MIN:-100}"
