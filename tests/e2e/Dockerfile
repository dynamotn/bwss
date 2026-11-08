# Linux environment for the bwss end-to-end tests: a Rust toolchain, a D-Bus
# session bus, libsecret's secret-tool and python-secretstorage.
# Build from the repository root: docker build -t bwss-e2e -f tests/e2e/Dockerfile .
FROM rust:1-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      dbus dbus-daemon libsecret-tools \
      python3 python3-pytest python3-secretstorage python3-cryptography python3-jeepney \
 && rm -rf /var/lib/apt/lists/*

# bwss runs a pinentry only from a system directory the user cannot write
# (ADR 0008), so the fake one is installed like a real one, owned by root.
COPY --chmod=755 tests/e2e/fake_pinentry.py /usr/local/bin/fake-pinentry

# Coverage (scripts/coverage.sh) and the clippy the checks use on Linux.
RUN rustup component add llvm-tools-preview clippy \
 && cargo install cargo-llvm-cov --locked --version '^0.9'

# root can write anywhere, so bwss trusts no pinentry as root: the tests run
# as an ordinary user. The build stays root (CARGO_HOME, the /target volume).
RUN useradd --create-home --uid 1000 tester

# dybw-core is a private repository: the crates are fetched here, into the
# image's CARGO_HOME, so the test runs need no credentials. CI mounts a token
# as a BuildKit secret (docker build --secret id=dybw_core_token,env=...): it
# lives in this command's environment only, never in an ARG, ENV or layer.
# Without the secret nothing is fetched here. A secret is not part of the
# build cache: after a build without one, build again with --no-cache.
RUN --mount=type=secret,id=dybw_core_token --mount=type=secret,id=dybw_core_token_user \
    --mount=type=bind,target=/fetch \
    if [ -s /run/secrets/dybw_core_token ]; then \
      user="$(cat /run/secrets/dybw_core_token_user 2>/dev/null)"; \
      GIT_CONFIG_COUNT=1 \
      GIT_CONFIG_KEY_0="url.https://${user:-oauth2}:$(cat /run/secrets/dybw_core_token)@gitlab.com/dynamo-tools/dybw-core.insteadOf" \
      GIT_CONFIG_VALUE_0=https://gitlab.com/dynamo-tools/dybw-core \
      CARGO_NET_GIT_FETCH_WITH_CLI=true \
      cargo fetch --locked --manifest-path /fetch/Cargo.toml; \
    else \
      echo "no dybw_core_token secret: dybw-core is not prefetched" >&2; \
    fi

ENV CARGO_TARGET_DIR=/target BWSS_BIN=/target/release/bwss PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
CMD ["sh", "-c", "cargo build --release --locked && setpriv --reuid=tester --regid=tester --init-groups env HOME=/home/tester dbus-run-session -- python3 -m pytest -q -p no:cacheprovider tests/e2e"]
