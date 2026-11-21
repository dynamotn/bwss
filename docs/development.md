# Developing bwss

## Quick checks

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets
cargo test --locked --workspace                       # unit tests, pam_bwss included
cargo test --locked --release perf -- --ignored --nocapture   # performance budgets
cargo test --features vectors vectors::               # dybw-core conformance vectors
```

A plain `cargo build` or `cargo test` covers bwss alone; pass `--workspace`
to include `pam_bwss`. The minimum supported Rust version is 1.89
(`rust-version` in `Cargo.toml`).

## End-to-end tests

The end-to-end suite (`tests/e2e`) runs in Docker on Linux, with a session
bus, `secret-tool` and python-secretstorage. The image installs a fake
pinentry in `/usr/local/bin` and runs the tests as a non-root user, since
bwss trusts no pinentry for root. Most tests need a throwaway Vaultwarden,
which the test container joins:

```sh
docker build -t bwss-e2e -f tests/e2e/Dockerfile .

# Recreate Vaultwarden for every run: a third run on one container hits HTTP 429.
docker rm -f bw-it
docker run -d --rm --name bw-it -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false \
  -e DISABLE_ICON_DOWNLOAD=true -e LOGIN_RATELIMIT_MAX_BURST=1000 \
  -e LOGIN_RATELIMIT_SECONDS=1 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
  vaultwarden/server:1.37.4

# The end-to-end suite
docker run --rm --network container:bw-it -e BW_E2E_URL=http://127.0.0.1:80 \
  -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry bwss-e2e

# Or: unit and end-to-end tests with line coverage, gated at 100%
docker run --rm --network container:bw-it -e BW_E2E_URL=http://127.0.0.1:80 \
  -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry \
  bwss-e2e scripts/coverage.sh
```

## pam_bwss

`pam_bwss` has its own suite (`tests/pam`), driven by `pamtester` and a
small libpam harness. It runs as root, adds a user and writes
`/etc/pam.d/bwss-test-*` inside the container. Docker's defaults block the
keyring syscalls and hide `/proc/keys`, so it needs two more options:

```sh
docker run --rm --security-opt seccomp=unconfined --security-opt systempaths=unconfined \
  -v "$PWD":/src -v bwss-target:/target -v bwss-cargo:/usr/local/cargo/registry bwss-e2e \
  sh -c 'cargo build --locked -p pam_bwss && PAM_BWSS_SO=/target/debug/libpam_bwss.so python3 -m pytest -q tests/pam'
```

The kernel keyring is not namespaced: the test user's keys (uid 4242) live
in the Docker host's kernel until they expire.

## Coverage

`scripts/coverage.sh` builds an instrumented debug build, runs both suites,
prints the uncovered lines of every file and fails below `COVERAGE_MIN`
(default 100; pass `-e COVERAGE_MIN=0` to only measure). With
`-e PAM_E2E=1` and the two options above it also measures `pam_bwss` over
its suite, as the GitHub gate does. It excludes only `src/perf.rs` and
`src/backend/tests.rs`. The lcov data is written to `/target/lcov.info` in
the `bwss-target` volume, and copied to `target/lcov.info` when `/src` is
writable.

## CI

CI runs the same checks on both forges:

- **GitHub** (`.github/workflows/`): fmt and clippy; unit tests on x86_64,
  aarch64 and macOS; `cargo audit`; an MSRV check against `rust-version`;
  the end-to-end suite against a Vaultwarden service container; and the
  100% coverage gate, `pam_bwss` included, which uploads `lcov.info`. It
  also builds static musl binaries for x86_64 and aarch64, and a `v*` tag
  creates a release with those binaries and their checksums. Actions are
  pinned to commit SHAs, and the release path uses no caches.
- **GitLab** (`.gitlab-ci.yml`): the same jobs except the MSRV check and
  the `pam_bwss` suite, which its Docker runners' seccomp profile blocks.
  Releases go to the Generic Package Registry and are linked from the
  release. aarch64 builds need an arm64 runner (`ARM64_RUNNER_TAG`, default
  `saas-linux-small-arm64`).

## Design

[design.md](design.md) covers the item model, collections, writing and
deletion, access control, locking, the offline queue, sessions and prompts,
configuration, the security model and the test matrix.
[m4-test-map.md](m4-test-map.md) maps the tests replaced when bwss moved
onto dybw-core.
