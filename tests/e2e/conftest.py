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
PINENTRY = str(HERE / "fake_pinentry.py")
SQUATTER = str(HERE / "squatter.py")


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
    d = Daemon({"backend": "memory", "memory_password": "open sesame", "acl": "prompt"}).start()
    yield d
    d.stop()


@pytest.fixture
def bus():
    conn = secretstorage.dbus_init()
    yield conn
    conn.close()
