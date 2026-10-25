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
SPOOF_LOCK = str(HERE / "spoof_lock.py")
SESSION = "/org/freedesktop/login1/session/_32"
PASSWORD = "open sesame"


class SystemBus(str):
    """The bus address; `proc` is the dbus-daemon behind it."""

    proc = None


def private_bus(match_rule_limit=None):
    """A private dbus-daemon, standing in for the system bus. With
    `match_rule_limit`, a connection may add that many match rules only."""
    sock = Path(tempfile.mkdtemp(prefix="bwss-sysbus-")) / "bus"
    address = SystemBus(f"unix:path={sock}")
    if match_rule_limit is None:
        command = ["dbus-daemon", "--session", "--nofork", f"--address={address}"]
    else:
        config = sock.parent / "bus.conf"
        config.write_text(
            "<busconfig><type>session</type>"
            f"<listen>{address}</listen>"
            '<policy context="default"><allow send_destination="*" eavesdrop="true"/>'
            '<allow eavesdrop="true"/><allow own="*"/></policy>'
            f'<limit name="max_match_rules_per_connection">{match_rule_limit}</limit>'
            "</busconfig>"
        )
        command = ["dbus-daemon", "--nofork", f"--config-file={config}"]
    proc = subprocess.Popen(command)
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("dbus-daemon did not start")
    address.proc = proc
    return address


def stop_bus(address):
    if address.proc.poll() is None:
        address.proc.terminate()
    address.proc.wait(10)


@pytest.fixture
def system_bus():
    address = private_bus()
    yield address
    stop_bus(address)


@pytest.fixture
def limited_bus():
    """A bus that refuses a client's first match rule beyond the limit."""
    address = private_bus(match_rule_limit=1)
    yield address
    stop_bus(address)


class FakeLogind:
    def __init__(self, address, *options):
        self.proc = subprocess.Popen([sys.executable, FAKE_LOGIND, address, SESSION, *options], stdin=subprocess.PIPE,
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


@pytest.fixture
def logind_without_pid_lookup(system_bus):
    f = FakeLogind(system_bus, "unknown-pid")
    yield f
    f.stop()


def test_the_session_of_the_environment_is_used_when_logind_does_not_know_the_process(
    system_bus, logind_without_pid_lookup
):
    d = daemon_on(system_bus)
    d.env["XDG_SESSION_ID"] = "32"
    d.start()
    try:
        assert wait_log(d, "locking on sleep and screen lock"), (d.home / "daemon.log").read_text()
        unlocked(d)
        logind_without_pid_lookup.emit("lock")
        assert wait_locked(d)
    finally:
        d.stop()


def test_without_a_session_of_its_own_the_lock_of_a_session_of_our_user_locks(system_bus, logind_without_pid_lookup):
    d = daemon_on(system_bus)
    d.env.pop("XDG_SESSION_ID", None)
    d.start()
    try:
        assert wait_log(d, "no logind session of our own"), (d.home / "daemon.log").read_text()
        assert wait_log(d, "(of any session of this user)"), (d.home / "daemon.log").read_text()
        unlocked(d)
        logind_without_pid_lookup.emit("lock")
        assert wait_locked(d)
    finally:
        d.stop()


def test_without_a_session_of_its_own_the_lock_of_another_users_session_does_not_lock(
    system_bus, logind_without_pid_lookup
):
    d = daemon_on(system_bus)
    d.env.pop("XDG_SESSION_ID", None)
    d.start()
    try:
        assert wait_log(d, "(of any session of this user)"), (d.home / "daemon.log").read_text()
        unlocked(d)
        logind_without_pid_lookup.emit("lock-other")
        # A lock of our own session after it, so the other one was certainly judged first.
        logind_without_pid_lookup.emit("lock")
        assert wait_locked(d)
        log = (d.home / "daemon.log").read_text()
        assert log.count("session lock requested") == 1, "only our user's session locks: " + log
    finally:
        d.stop()


def spoof_lock(address, *options):
    """A client that is not logind sends Session.Lock to every connection."""
    subprocess.run([sys.executable, SPOOF_LOCK, address, SESSION, *options], check=True, timeout=60)


def assert_only_the_genuine_lock_locked(d):
    """After a spoofed and then a genuine Lock: locked, by the genuine one only."""
    assert wait_locked(d)
    assert wait_log(d, "not sent by logind"), (d.home / "daemon.log").read_text()
    log = (d.home / "daemon.log").read_text()
    assert log.count("session lock requested") == 1, "only logind's Lock locks: " + log


def test_a_lock_signal_not_sent_by_logind_does_not_lock_a_known_session(started, logind, system_bus):
    unlocked(started)
    spoof_lock(system_bus)
    logind.emit("lock")
    assert_only_the_genuine_lock_locked(started)


def test_a_lock_signal_not_sent_by_logind_does_not_lock_without_a_session_of_our_own(
    system_bus, logind_without_pid_lookup
):
    d = daemon_on(system_bus)
    d.env.pop("XDG_SESSION_ID", None)
    d.start()
    try:
        assert wait_log(d, "(of any session of this user)"), (d.home / "daemon.log").read_text()
        unlocked(d)
        spoof_lock(system_bus)
        logind_without_pid_lookup.emit("lock")
        assert_only_the_genuine_lock_locked(d)
    finally:
        d.stop()


def assert_a_flood_leaves_logind_working(d, logind, address):
    """A flood of spoofed Locks, then a genuine sleep and a genuine Lock: both
    lock, and the whole flood costs one warning."""
    unlocked(d)
    spoof_lock(address, "--count", "1000")
    logind.emit("sleep")
    assert wait_locked(d), (d.home / "daemon.log").read_text()
    unlocked(d)
    # The genuine Lock comes after the whole flood on the same stream, so
    # once it locked, every spoofed one was judged.
    logind.emit("lock")
    assert wait_locked(d), (d.home / "daemon.log").read_text()
    log = (d.home / "daemon.log").read_text()
    assert log.count("system is going to sleep") == 1, log
    assert log.count("session lock requested") == 1, "only logind's Lock locks: " + log
    assert log.count("not sent by logind") == 1, "one warning for 1000 spoofed Locks: " + log


def test_a_flood_of_spoofed_locks_does_not_stall_the_listener(started, logind, system_bus):
    assert_a_flood_leaves_logind_working(started, logind, system_bus)


def test_a_flood_of_spoofed_locks_does_not_stall_the_listener_without_a_session_of_our_own(
    system_bus, logind_without_pid_lookup
):
    d = daemon_on(system_bus)
    d.env.pop("XDG_SESSION_ID", None)
    d.start()
    try:
        assert wait_log(d, "(of any session of this user)"), (d.home / "daemon.log").read_text()
        assert_a_flood_leaves_logind_working(d, logind_without_pid_lookup, system_bus)
    finally:
        d.stop()


def test_a_forged_owner_change_neither_hides_logind_nor_lets_the_forger_lock(started, logind, system_bus):
    unlocked(started)
    # NameOwnerChanged claiming logind's name, then a Lock, from the forger.
    spoof_lock(system_bus, "--claim-owner")
    logind.emit("sleep")
    assert wait_locked(started), (started.home / "daemon.log").read_text()
    unlocked(started)
    logind.emit("lock")
    assert wait_locked(started), (started.home / "daemon.log").read_text()
    log = (started.home / "daemon.log").read_text()
    assert log.count("system is going to sleep") == 1, log
    assert log.count("session lock requested") == 1, "only logind's Lock locks: " + log
    assert "logind has a new name on the bus" not in log, "only the bus tells who owns logind's name: " + log


def test_after_logind_restarts_only_its_new_name_locks(system_bus):
    old = FakeLogind(system_bus, "replaceable")
    d = daemon_on(system_bus).start()
    new = None
    try:
        assert wait_log(d, "locking on sleep and screen lock"), (d.home / "daemon.log").read_text()
        unlocked(d)
        new = FakeLogind(system_bus, "replace")
        assert wait_log(d, "logind has a new name on the bus"), (d.home / "daemon.log").read_text()
        # Unicast, as the bus no longer routes the old name's broadcasts as logind's.
        old.emit("lock-direct")
        assert wait_log(d, "not sent by logind"), (d.home / "daemon.log").read_text()
        assert d.cli("status").stdout.startswith("unlocked"), "the old name no longer speaks for logind"
        new.emit("lock")
        assert wait_locked(d), (d.home / "daemon.log").read_text()
        log = (d.home / "daemon.log").read_text()
        assert log.count("session lock requested") == 1, log
    finally:
        d.stop()
        old.stop()
        if new:
            new.stop()


def test_a_session_whose_user_cannot_be_read_still_locks_when_logind_says_so(system_bus):
    f = FakeLogind(system_bus, "unknown-pid", "no-user")
    d = daemon_on(system_bus)
    d.env.pop("XDG_SESSION_ID", None)
    d.start()
    try:
        assert wait_log(d, "(of any session of this user)"), (d.home / "daemon.log").read_text()
        unlocked(d)
        f.emit("lock")
        assert wait_locked(d)
        assert wait_log(d, "cannot read the user of session"), (d.home / "daemon.log").read_text()
        assert SESSION in (d.home / "daemon.log").read_text()
    finally:
        d.stop()
        f.stop()


def test_a_bus_that_refuses_the_subscription_is_logged_and_the_daemon_keeps_serving(limited_bus):
    d = daemon_on(limited_bus).start()
    try:
        assert wait_log(d, "cannot listen to logind"), (d.home / "daemon.log").read_text()
        unlocked(d)
        assert d.proc.poll() is None
    finally:
        d.stop()
