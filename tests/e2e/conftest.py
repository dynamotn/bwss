"""Fixtures: a bwss daemon on the (private) session bus of the test run.

Run under `dbus-run-session`, so the daemon owns org.freedesktop.secrets on a
bus that exists only for this test session.
"""

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import secretstorage

HERE = Path(__file__).parent
BWSS = os.environ.get("BWSS_BIN", str(HERE.parents[1] / "target" / "release" / "bwss"))
PINENTRY = str(HERE / "fake_pinentry.py")


class Daemon:
    def __init__(self, config: dict, home: Path | None = None):
        self.home = home or Path(tempfile.mkdtemp(prefix="bwss-e2e-"))
        self.ctl = self.home / "pinentry.json"
        self.log = self.home / "pinentry.log"
        self.env = dict(os.environ)
        self.env.update(
            XDG_CONFIG_HOME=str(self.home / "config"),
            XDG_CACHE_HOME=str(self.home / "cache"),
            XDG_STATE_HOME=str(self.home / "state"),
            FAKE_PINENTRY_CTL=str(self.ctl),
            FAKE_PINENTRY_LOG=str(self.log),
            BWSS_LOG="debug",
        )
        (self.home / "config" / "bwss").mkdir(parents=True, exist_ok=True)
        lines = [f'prompter = "{PINENTRY}"'] + [f"{k} = {json.dumps(v)}" for k, v in config.items()]
        (self.home / "config" / "bwss" / "config.toml").write_text("\n".join(lines) + "\n")
        self.pinentry(pins=[], confirm="deny")
        self.proc = None

    def pinentry(self, **ctl):
        self.ctl.write_text(json.dumps(ctl))

    def prompts(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def start(self):
        self.stderr = open(self.home / "daemon.log", "a")
        self.proc = subprocess.Popen([BWSS, "daemon", "--replace"], env=self.env, stderr=self.stderr)
        for _ in range(100):
            if self.cli("status", check=False).returncode == 0:
                return self
            time.sleep(0.1)
        raise RuntimeError("bwss did not start:\n" + (self.home / "daemon.log").read_text())

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait(10)
            self.proc = None

    def cli(self, *args, input=None, check=True):
        return subprocess.run([BWSS, *args], env=self.env, input=input, capture_output=True, text=True, check=check)

    def tool(self, *args, input=None, check=True):
        """secret-tool, run as a separate process (its own executable for the ACL)."""
        return subprocess.run(["secret-tool", *args], env=self.env, input=input, capture_output=True, text=True, check=check)


@pytest.fixture
def memory_daemon():
    d = Daemon({"backend": "memory", "memory_password": "open sesame", "acl": "prompt"}).start()
    yield d
    d.stop()


@pytest.fixture
def bus():
    conn = secretstorage.dbus_init()
    yield conn
    conn.close()
