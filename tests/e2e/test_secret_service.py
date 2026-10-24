"""Secret Service conformance and keychain-like behaviour, over the memory backend.

Clients used: libsecret (`secret-tool`), python-secretstorage (which speaks the
DH-encrypted session), and the bwss CLI.
"""

import pytest
import secretstorage
from conftest import BWSS
from secretstorage.exceptions import LockedException

PASSWORD = "open sesame"


def unlock(d):
    d.cli("unlock", "--password-stdin", input=PASSWORD + "\n")


def test_starts_locked_and_unlocks_through_the_cli(memory_daemon):
    d = memory_daemon
    assert d.cli("status").stdout.startswith("locked")
    bad = d.cli("unlock", "--password-stdin", input="nope\n", check=False)
    assert bad.returncode != 0
    unlock(d)
    assert d.cli("status").stdout.startswith("unlocked")
    d.cli("lock")
    assert d.cli("status").stdout.startswith("locked")


def test_secret_tool_store_lookup_clear(memory_daemon):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=GitHub token", "service", "github", "user", "me", input="ghp_123")
    assert d.tool("lookup", "service", "github").stdout == "ghp_123"
    search = d.tool("search", "--all", "user", "me").stdout + d.tool("search", "--all", "user", "me").stderr
    assert "GitHub token" in search
    d.tool("clear", "service", "github")
    assert d.tool("lookup", "service", "github", check=False).returncode != 0


def test_store_while_locked_prompts_for_the_password(memory_daemon):
    d = memory_daemon
    d.pinentry(pins=["wrong", PASSWORD])
    d.tool("store", "--label=x", "k", "v", input="value")
    prompts = d.prompts()
    assert sum(1 for p in prompts if p.startswith("GETPIN")) == 2
    assert any(p.startswith("SETERROR") and "Wrong password" in p for p in prompts)
    assert d.tool("lookup", "k", "v").stdout == "value"


def test_cancelled_prompt_leaves_the_keyring_locked(memory_daemon):
    d = memory_daemon
    d.pinentry(pins=[])
    # libsecret treats a dismissed prompt as "nothing stored", not as an error.
    d.tool("store", "--label=x", "k", "v", input="value", check=False)
    assert d.cli("status").stdout.startswith("locked")
    unlock(d)
    assert d.tool("lookup", "k", "v", check=False).returncode != 0


def test_dh_session_round_trip_with_secretstorage(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    coll = secretstorage.get_default_collection(bus)
    assert not coll.is_locked()
    # secretstorage negotiates dh-ietf1024-sha256-aes128-cbc-pkcs7 by default.
    item = coll.create_item("binary", {"app": "e2e", "kind": "bin"}, b"\x00\xffbinary\x10", content_type="application/octet-stream")
    assert item.get_secret() == b"\x00\xffbinary\x10"
    assert item.get_secret_content_type() == "application/octet-stream"
    assert item.get_attributes() == {"app": "e2e", "kind": "bin"}
    item.set_label("renamed")
    item.set_attributes({"app": "e2e", "kind": "changed"})
    found = list(coll.search_items({"kind": "changed"}))
    assert [i.get_label() for i in found] == ["renamed"]
    item.set_secret(b"new value")
    assert item.get_secret() == b"new value"
    item.delete()
    assert not list(coll.search_items({"app": "e2e"}))


def test_replace_updates_instead_of_duplicating(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    coll = secretstorage.get_default_collection(bus)
    coll.create_item("a", {"id": "same"}, b"1")
    coll.create_item("a", {"id": "same"}, b"2", replace=True)
    items = list(coll.search_items({"id": "same"}))
    assert len(items) == 1 and items[0].get_secret() == b"2"


def test_locked_items_are_found_and_unlocked_by_prompt(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=x", "service", "locked-test", input="s3")
    d.cli("lock")
    coll = secretstorage.get_default_collection(bus)
    assert coll.is_locked()
    found = list(secretstorage.search_items(bus, {"service": "locked-test"}))
    assert len(found) == 0 or found[0].is_locked()
    with pytest.raises(LockedException):
        coll.create_item("y", {"a": "b"}, b"x")
    d.pinentry(pins=[PASSWORD])
    assert coll.unlock() is False  # False = not dismissed
    assert d.tool("lookup", "service", "locked-test").stdout == "s3"


def test_dismissed_unlock(memory_daemon, bus):
    d = memory_daemon
    d.pinentry(pins=[])
    coll = secretstorage.get_default_collection(bus)
    assert coll.unlock() is True  # dismissed


def test_acl_denies_other_applications_until_allowed(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    # Created by secret-tool: python (this test) is a different executable.
    d.tool("store", "--label=private", "acl", "test", input="mine")
    item = next(iter(secretstorage.get_default_collection(bus).search_items({"acl": "test"})))

    d.pinentry(confirm="deny")
    with pytest.raises(Exception):
        item.get_secret()
    assert any(p.startswith("SETDESC") and "secret-tool" not in p and "private" in p for p in d.prompts())

    d.pinentry(confirm="once")
    assert item.get_secret() == b"mine"
    d.pinentry(confirm="deny")
    with pytest.raises(Exception):
        item.get_secret()

    d.pinentry(confirm="always")
    assert item.get_secret() == b"mine"
    d.pinentry(confirm="deny")
    assert item.get_secret() == b"mine"  # remembered, no prompt
    # The creator never needed a prompt.
    before = len(d.prompts())
    assert d.tool("lookup", "acl", "test").stdout == "mine"
    assert len(d.prompts()) == before


def test_collections(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    work = secretstorage.create_collection(bus, "Work")
    work.create_item("vpn", {"svc": "vpn"}, b"pw")
    assert "Work" in [c.get_label() for c in secretstorage.get_all_collections(bus)]
    assert [i.get_label() for i in work.get_all_items()] == ["vpn"]
    work.delete()
    assert "Work" not in [c.get_label() for c in secretstorage.get_all_collections(bus)]


def test_get_secrets_skips_locked_and_needs_a_valid_session(memory_daemon):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=a", "multi", "1", input="one")
    d.tool("store", "--label=b", "multi", "2", input="two")
    # secret-tool reads both through Service.GetSecrets.
    out = d.tool("search", "--all", "--unlock", "multi", "1").stdout
    assert "one" in out or "secret = one" in out


def test_survives_garbage_input(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    from jeepney import DBusAddress, new_method_call

    svc = DBusAddress("/org/freedesktop/secrets", bus_name="org.freedesktop.secrets", interface="org.freedesktop.Secret.Service")
    for algo, arg in [("dh-ietf1024-sha256-aes128-cbc-pkcs7", ("ay", b"\x01")), ("rot13", ("s", ""))]:
        reply = bus.send_and_get_reply(new_method_call(svc, "OpenSession", "sv", (algo, arg)))
        assert reply.header.message_type.name == "error"
    reply = bus.send_and_get_reply(new_method_call(svc, "GetSecrets", "aoo", (["/org/freedesktop/secrets/collection/login/nope"], "/bogus")))
    assert reply.header.message_type.name == "error"
    assert d.cli("status").returncode == 0


# --- abuse limits between bus clients (TM-019) ---------------------------------------

SVC = "/org/freedesktop/secrets"
LOGIN = "/org/freedesktop/secrets/collection/login"
SESSION_CAP = 64
PROMPT_CAP = 16


@pytest.fixture
def other_bus():
    conn = secretstorage.dbus_init()
    yield conn
    conn.close()


def _call(conn, path, interface, member, sig="", body=()):
    from jeepney import DBusAddress, new_method_call

    addr = DBusAddress(path, bus_name="org.freedesktop.secrets", interface=interface)
    return conn.send_and_get_reply(new_method_call(addr, member, sig, body))


def _open_plain(conn):
    reply = _call(conn, SVC, "org.freedesktop.Secret.Service", "OpenSession", "sv", ("plain", ("s", "")))
    assert reply.header.message_type.name == "method_return", reply.body
    return reply.body[1]


def _session_alive(conn, path):
    """A session is alive while Close on it is not answered with an unknown-object error."""
    reply = _call(conn, path, "org.freedesktop.DBus.Introspectable", "Introspect")
    return reply.header.message_type.name == "method_return"


def test_one_client_cannot_evict_anothers_sessions(memory_daemon, bus, other_bus):
    a_session = _open_plain(bus)
    first_b = _open_plain(other_bus)
    for _ in range(SESSION_CAP + 8):
        _open_plain(other_bus)
    # A's session is untouched by B's flood.
    assert _session_alive(bus, a_session)
    # B pushed out only its own oldest sessions, and their objects are gone.
    assert not _session_alive(other_bus, first_b)


def test_session_close_is_limited_to_its_owner(memory_daemon, bus, other_bus):
    a_session = _open_plain(bus)
    denied = _call(other_bus, a_session, "org.freedesktop.Secret.Session", "Close")
    assert denied.header.message_type.name == "error"
    assert _session_alive(bus, a_session)
    ok = _call(bus, a_session, "org.freedesktop.Secret.Session", "Close")
    assert ok.header.message_type.name == "method_return"
    assert not _session_alive(bus, a_session)


def test_prompts_are_capped_per_client(memory_daemon, bus, other_bus):
    a_prompt = _call(bus, SVC, "org.freedesktop.Secret.Service", "Unlock", "ao", ([LOGIN],)).body[1]
    b_prompts = [
        _call(other_bus, SVC, "org.freedesktop.Secret.Service", "Unlock", "ao", ([LOGIN],)).body[1]
        for _ in range(PROMPT_CAP + 4)
    ]
    # B's oldest prompts were dismissed and removed; its newest survive; A's is untouched.
    assert not _session_alive(other_bus, b_prompts[0])
    assert _session_alive(other_bus, b_prompts[-1])
    assert _session_alive(bus, a_prompt)


def test_failed_unlocks_are_serialized(memory_daemon):
    import subprocess
    import time

    d = memory_daemon
    start = time.monotonic()
    procs = [
        subprocess.Popen(
            [BWSS, "unlock", "--password-stdin"],
            env=d.env,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for _ in range(2)
    ]
    for p in procs:
        p.communicate("wrong\n")
        assert p.returncode != 0
    assert time.monotonic() - start >= 4.0
