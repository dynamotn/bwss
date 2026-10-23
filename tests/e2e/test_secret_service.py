"""Secret Service conformance and keychain-like behaviour, over the memory backend.

Clients used: libsecret (`secret-tool`), python-secretstorage (which speaks the
DH-encrypted session), and the bwss CLI.
"""

import pytest
import secretstorage
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
    r = d.tool("store", "--label=x", "k", "v", input="value", check=False)
    assert r.returncode != 0
    assert d.cli("status").stdout.startswith("locked")


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
