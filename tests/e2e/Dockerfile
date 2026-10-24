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

# root can write anywhere, so bwss trusts no pinentry as root: the tests run
# as an ordinary user. The build stays root (CARGO_HOME, the /target volume).
RUN useradd --create-home --uid 1000 tester

ENV CARGO_TARGET_DIR=/target BWSS_BIN=/target/release/bwss PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
CMD ["sh", "-c", "cargo build --release --locked && setpriv --reuid=tester --regid=tester --init-groups env HOME=/home/tester dbus-run-session -- python3 -m pytest -q -p no:cacheprovider tests/e2e"]
