"""Locking on sleep and screen lock (TM-013), with a fake logind.

The daemon reads DBUS_SYSTEM_BUS_ADDRESS, so a private bus stands in for the
system bus and a small script plays systemd-logind on it.
"""

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from conftest import HERE, Daemon

FAKE_LOGIND = str(HERE / "fake_logind.py")
SESSION = "/org/freedesktop/login1/session/_32"
PASSWORD = "open sesame"


class SystemBus(str):
    """The bus address; `proc` is the dbus-daemon behind it."""

    proc = None


@pytest.fixture
def system_bus():
    """A private dbus-daemon, standing in for the system bus."""
    sock = Path(tempfile.mkdtemp(prefix="bwss-sysbus-")) / "bus"
    address = SystemBus(f"unix:path={sock}")
    proc = subprocess.Popen(["dbus-daemon", "--session", "--nofork", f"--address={address}"])
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("dbus-daemon did not start")
    address.proc = proc
    yield address
    if proc.poll() is None:
        proc.terminate()
    proc.wait(10)


class FakeLogind:
    def __init__(self, address):
        self.proc = subprocess.Popen([sys.executable, FAKE_LOGIND, address, SESSION], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True)
        assert self.proc.stdout.readline().strip() == "ready"

    def emit(self, what):
        self.proc.stdin.write(what + "\n")
        self.proc.stdin.flush()

    def stop(self):
        self.proc.stdin.close()
        self.proc.wait(10)


@pytest.fixture
def logind(system_bus):
    f = FakeLogind(system_bus)
    yield f
    f.stop()


def daemon_on(address=None, **top):
    d = Daemon({"backend": "memory", "memory_password": PASSWORD}, top=top)
    d.env.pop("DBUS_SYSTEM_BUS_ADDRESS", None)
    if address:
        d.env["DBUS_SYSTEM_BUS_ADDRESS"] = address
    return d


def unlocked(d):
    d.cli("unlock", "--password-stdin", input=PASSWORD + "\n")
    assert d.cli("status").stdout.startswith("unlocked")
    return d


def wait_locked(d):
    for _ in range(50):
        if d.cli("status").stdout.startswith("locked"):
            return True
        time.sleep(0.1)
    return False


def wait_log(d, text):
    for _ in range(50):
        if text in (d.home / "daemon.log").read_text():
            return True
        time.sleep(0.1)
    return False


@pytest.fixture
def started(system_bus, logind):
    d = daemon_on(system_bus).start()
    assert wait_log(d, "locking on sleep and screen lock"), (d.home / "daemon.log").read_text()
    yield d
    d.stop()


def test_the_session_lock_signal_locks_the_keyring(started, logind):
    unlocked(started)
    logind.emit("lock")
    assert wait_locked(started)


def test_sleep_locks_the_keyring(started, logind):
    unlocked(started)
    logind.emit("sleep")
    assert wait_locked(started)


def test_waking_up_and_unlocking_the_session_leave_it_unlocked(started, logind):
    unlocked(started)
    logind.emit("resume")
    logind.emit("unlock")
    # Then a real lock, so the earlier signals were certainly handled first.
    logind.emit("lock")
    assert wait_locked(started)
    log = (started.home / "daemon.log").read_text()
    assert "system is going to sleep" not in log, log
    assert log.count("session lock requested") == 1, "only Lock locks, not Unlock: " + log


def test_without_a_system_bus_the_daemon_warns_and_keeps_serving():
    d = daemon_on("unix:path=/nonexistent/system_bus_socket").start()
    try:
        assert wait_log(d, "no system bus"), (d.home / "daemon.log").read_text()
        unlocked(d)
        assert d.proc.poll() is None
        d.cli("lock")
        assert d.cli("status").stdout.startswith("locked")
    finally:
        d.stop()


def test_a_bus_without_logind_warns_and_keeps_serving(system_bus):
    d = daemon_on(system_bus).start()
    try:
        assert wait_log(d, "no logind session") or wait_log(d, "cannot listen to logind"), (
            d.home / "daemon.log"
        ).read_text()
        unlocked(d)
        assert d.proc.poll() is None
    finally:
        d.stop()


def test_logind_still_locks_when_idle_locking_is_off(system_bus, logind):
    d = daemon_on(system_bus, lock_timeout_minutes=0).start()
    try:
        assert wait_log(d, "locking on sleep and screen lock")
        unlocked(d)
        logind.emit("sleep")
        assert wait_locked(d)
    finally:
        d.stop()


def test_losing_the_system_bus_is_logged_and_the_daemon_keeps_serving(started, system_bus):
    unlocked(started)
    system_bus.proc.kill()
    system_bus.proc.wait(10)
    assert wait_log(started, "no longer lock the keyring"), (started.home / "daemon.log").read_text()
    assert started.proc.poll() is None
    assert started.cli("status").stdout.startswith("unlocked")
    started.cli("lock")
    assert started.cli("status").stdout.startswith("locked")
