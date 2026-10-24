"""Fixtures: a bwss daemon on the (private) session bus of the test run.

Run under `dbus-run-session`, so the daemon owns org.freedesktop.secrets on a
bus that exists only for this test session.
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import secretstorage
from jeepney.bus_messages import message_bus

HERE = Path(__file__).parent
BWSS = os.environ.get("BWSS_BIN", str(HERE.parents[1] / "target" / "release" / "bwss"))
# bwss only runs a pinentry from a system directory the user cannot write
# (ADR 0008), so the test image installs the fake one there.
PINENTRY = os.environ.get("BWSS_E2E_PINENTRY", "/usr/local/bin/fake-pinentry")
SQUATTER = str(HERE / "squatter.py")
PROFILE = "e2e"


def toml_lines(table: dict) -> list[str]:
    # JSON strings, numbers and booleans are valid TOML values.
    return [f"{k} = {json.dumps(v)}" for k, v in table.items()]


class Daemon:
    """A bwss home: the shared dybw config file, device state, and a daemon.

    `bwss` is the [bwss] section; `profile`, when given, becomes
    [profiles.e2e], the profile bwss serves; `top` adds top-level keys.
    `acl_off` writes the device state that `bwss acl off` would.
    """

    def __init__(self, bwss: dict, profile: dict | None = None, top: dict | None = None, acl_off: bool = False,
                 home: Path | None = None):
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
        self.config = self.home / "config" / "dybw" / "config.toml"
        self.state = self.home / "state" / "dybw"
        self.write_config(bwss, profile, top)
        if acl_off:
            (self.state / "tools" / "bwss").mkdir(parents=True, exist_ok=True)
            (self.state / "tools" / "bwss" / "acl-off").write_text("off\n")
        self.pinentry(pins=[], confirm="deny")
        self.proc = None

    def write_config(self, bwss: dict, profile: dict | None = None, top: dict | None = None):
        lines = toml_lines({"pinentry": PINENTRY, **(top or {})})
        if profile is not None:
            lines += ["", f"[profiles.{PROFILE}]"] + toml_lines(profile)
            bwss = {"profile": PROFILE, **bwss}
        lines += ["", "[bwss]"] + toml_lines(bwss)
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text("\n".join(lines) + "\n")

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

    def cli(self, *args, input=None, check=True, timeout=None):
        return subprocess.run([BWSS, *args], env=self.env, input=input, capture_output=True, text=True, check=check,
                              timeout=timeout)

    def tool(self, *args, input=None, check=True):
        """secret-tool, run as a separate process (its own executable for the ACL)."""
        return subprocess.run(["secret-tool", *args], env=self.env, input=input, capture_output=True, text=True, check=check)


class Squatter:
    """Another client on the bus asking for `name` (see squatter.py)."""

    # RequestName flags.
    REPLACE_EXISTING = 2
    DO_NOT_QUEUE = 4

    def __init__(self, name: str, flags: int = DO_NOT_QUEUE, exec_argv=(), env=None):
        self.name = name
        self.log = Path(tempfile.mkdtemp(prefix="bwss-squatter-")) / "calls.log"
        # Its own process group, so stop() also reaches a forked child.
        self.proc = subprocess.Popen([sys.executable, SQUATTER, name, str(flags), str(self.log), *exec_argv],
                                     stdout=subprocess.PIPE, text=True, env=env, start_new_session=True)
        self.reply = int(self.proc.stdout.readline())

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def stop(self):
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        self.proc.wait(10)
        if self.reply != 1:
            return
        # Wait until the name is free again for the next test.
        conn = secretstorage.dbus_init()
        try:
            for _ in range(100):
                if not conn.send_and_get_reply(message_bus.NameHasOwner(self.name)).body[0]:
                    return
                time.sleep(0.1)
            raise RuntimeError(f"{self.name} is still owned after the squatter stopped")
        finally:
            conn.close()


@pytest.fixture
def squatters():
    started = []

    def start(name, flags=Squatter.DO_NOT_QUEUE, **kw):
        started.append(Squatter(name, flags, **kw))
        return started[-1]

    yield start
    for s in started:
        s.stop()


@pytest.fixture
def memory_daemon():
    d = Daemon({"backend": "memory", "memory_password": "open sesame"}).start()
    yield d
    d.stop()


@pytest.fixture
def bus():
    conn = secretstorage.dbus_init()
    yield conn
    conn.close()
