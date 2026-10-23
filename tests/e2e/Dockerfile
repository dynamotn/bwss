# Linux environment for the bwss end-to-end tests: a Rust toolchain, a D-Bus
# session bus, libsecret's secret-tool and python-secretstorage.
FROM rust:1-trixie

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      dbus dbus-daemon libsecret-tools \
      python3 python3-pytest python3-secretstorage python3-cryptography python3-jeepney \
 && rm -rf /var/lib/apt/lists/*

ENV CARGO_TARGET_DIR=/target BWSS_BIN=/target/release/bwss
WORKDIR /src
CMD ["sh", "-c", "cargo build --release --locked && dbus-run-session -- python3 -m pytest -q -p no:cacheprovider tests/e2e"]
