"""Bus-name ownership: who may hold bwss's names, and who gets the password."""

import subprocess

from jeepney.bus_messages import message_bus

from conftest import BWSS, Daemon, Squatter

PASSWORD = "open sesame"
CONTROL = "io.github.dynamotn.bwss"
SECRETS = "org.freedesktop.secrets"


def has_owner(bus, name):
    return bool(bus.send_and_get_reply(message_bus.NameHasOwner(name)).body[0])


def run_daemon(d):
    return subprocess.run([BWSS, "daemon", "--replace"], env=d.env, capture_output=True, text=True, timeout=30)


def memory_home():
    return Daemon({"backend": "memory", "memory_password": PASSWORD})


def test_daemon_refuses_a_squatted_control_name(squatters, bus):
    squatter = squatters(CONTROL)
    assert squatter.reply == 1
    r = run_daemon(memory_home())
    assert r.returncode != 0
    assert f"{CONTROL} is owned by /usr/bin/python3" in r.stderr, r.stderr
    assert not has_owner(bus, SECRETS)


def test_daemon_refuses_a_secrets_provider_it_cannot_replace(squatters, bus):
    squatter = squatters(SECRETS)
    assert squatter.reply == 1
    r = run_daemon(memory_home())
    assert r.returncode != 0
    assert f"{SECRETS} is owned by /usr/bin/python3" in r.stderr, r.stderr
    assert "does not allow replacement" in r.stderr
    assert not has_owner(bus, CONTROL)


def test_running_daemon_names_cannot_be_taken(memory_daemon, squatters):
    flags = Squatter.REPLACE_EXISTING | Squatter.DO_NOT_QUEUE
    for name in (SECRETS, CONTROL):
        assert squatters(name, flags).reply == 3, name  # 3 = EXISTS
    assert memory_daemon.cli("status").stdout.startswith("locked")


def test_password_stdin_goes_only_to_bwss(squatters):
    squatter = squatters(CONTROL)
    home = memory_home()
    r = home.cli("unlock", "--password-stdin", input=PASSWORD + "\n", check=False)
    assert r.returncode != 0
    assert "refusing to send the password" in r.stderr and "/usr/bin/python3" in r.stderr, r.stderr
    # Plain `unlock` sends no password, so it does reach the squatter; that
    # shows the squatter would have logged a password had one been sent.
    assert home.cli("unlock", check=False).returncode != 0
    calls = squatter.calls()
    assert any(c.startswith("UnlockInteractive ") for c in calls), calls
    assert not any("UnlockWithPassword" in c or PASSWORD in c for c in calls), calls


def test_password_stdin_without_a_daemon_says_so():
    r = memory_home().cli("unlock", "--password-stdin", input=PASSWORD + "\n", check=False)
    assert r.returncode != 0
    assert f"{CONTROL} is not on the bus" in r.stderr, r.stderr


def test_password_stdin_reaches_the_real_daemon(memory_daemon):
    d = memory_daemon
    assert d.cli("unlock", "--password-stdin", input=PASSWORD + "\n").stdout == "unlocked\n"
    assert d.cli("status").stdout.startswith("unlocked")


def test_plain_unlock_prompts_through_the_daemon(memory_daemon):
    d = memory_daemon
    d.pinentry(pins=[])
    cancelled = d.cli("unlock", check=False)
    assert cancelled.returncode != 0 and "unlock cancelled or failed" in cancelled.stderr
    assert d.cli("status").stdout.startswith("locked")

    d.pinentry(pins=["wrong", PASSWORD])
    assert d.cli("unlock").stdout == "unlocked\n"
    assert d.cli("status").stdout.startswith("unlocked")
    getpins = [p for p in d.prompts() if p.startswith("GETPIN")]
    assert len(getpins) == 3  # cancelled once, then wrong, then right
    assert any(p.startswith("SETERROR Wrong password") for p in d.prompts())
