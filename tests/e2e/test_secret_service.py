"""Secret Service conformance and keychain-like behaviour, over the memory backend.

Clients used: libsecret (`secret-tool`), python-secretstorage (which speaks the
DH-encrypted session), and the bwss CLI.
"""

import shutil
import subprocess
import sys
import time

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
    # python is an interpreter: it is asked every time, even for its own items.
    d.pinentry(confirm="once")
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
    d.pinentry(confirm="once")
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


def other_tool(d):
    """A copy of secret-tool: a different executable, and not an interpreter."""
    path = d.home / "other-tool"
    shutil.copy(shutil.which("secret-tool"), path)
    return lambda *args, check=True: subprocess.run([str(path), *args], env=d.env, capture_output=True, text=True,
                                                   check=check)


def confirms(d):
    return sum(1 for p in d.prompts() if p.startswith("CONFIRM"))


def test_acl_denies_other_applications_until_allowed(memory_daemon):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=private", "acl", "test", input="mine")
    other = other_tool(d)

    d.pinentry(confirm="deny")
    assert other("lookup", "acl", "test", check=False).stdout == ""
    assert any(p.startswith("SETDESC") and "other-tool" in p and "private" in p for p in d.prompts())

    d.pinentry(confirm="once")
    assert other("lookup", "acl", "test").stdout == "mine"
    d.pinentry(confirm="deny")
    assert other("lookup", "acl", "test", check=False).stdout == ""

    d.pinentry(confirm="always")
    assert other("lookup", "acl", "test").stdout == "mine"
    assert "SETOK Always allow" in d.prompts()
    d.pinentry(confirm="deny")
    before = confirms(d)
    assert other("lookup", "acl", "test").stdout == "mine"  # remembered, no prompt
    # The creator never needed a prompt.
    assert d.tool("lookup", "acl", "test").stdout == "mine"
    assert confirms(d) == before


def test_interpreters_are_never_offered_always_allow(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=scripted", "acl", "interp", input="s3cret")
    item = next(iter(secretstorage.get_default_collection(bus).search_items({"acl": "interp"})))

    # The pinentry would answer "Always allow" if it were asked.
    d.pinentry(confirm="always")
    assert item.get_secret() == b"s3cret"
    assert confirms(d) == 1, d.prompts()
    assert not any("Always allow" in p for p in d.prompts()), d.prompts()
    assert any(p.startswith("SETDESC") and "runs scripts" in p for p in d.prompts())

    # Nothing was remembered: the next read is asked again.
    d.pinentry(confirm="deny")
    with pytest.raises(Exception):
        item.get_secret()
    assert confirms(d) == 2


SCRIPT = """
import sys
import secretstorage

bus = secretstorage.dbus_init()
coll = secretstorage.get_default_collection(bus)
if sys.argv[-1] == "store":
    coll.create_item("by script", {"script": "e2e"}, b"from-script")
else:
    item = next(iter(coll.search_items({"script": "e2e"})))
    sys.stdout.write(item.get_secret().decode())
"""


def test_a_script_file_is_an_application_of_its_own(memory_daemon):
    d = memory_daemon
    unlock(d)
    script = d.home / "keyring_script.py"
    script.write_text(SCRIPT)
    run = lambda *argv: subprocess.run([sys.executable, *argv], env=d.env, capture_output=True, text=True)

    # The script creates the item, so it is the creator: later runs read it freely.
    assert run(str(script), "store").returncode == 0
    d.pinentry(confirm="deny")
    read = run(str(script), "read")
    assert read.returncode == 0 and read.stdout == "from-script", read.stderr
    assert confirms(d) == 0, d.prompts()

    # The same code from `python -c` is no script file: asked, and never "Always allow".
    inline = run("-c", SCRIPT, "read")
    assert inline.returncode != 0
    assert confirms(d) == 1, d.prompts()
    assert any(p.startswith("SETDESC") and "runs scripts" in p for p in d.prompts())
    assert not any("Always allow" in p for p in d.prompts())


def test_unlock_with_password_only_from_the_bwss_cli(memory_daemon, bus):
    from jeepney import DBusAddress, new_method_call

    d = memory_daemon
    ctl = DBusAddress("/io/github/dynamotn/bwss", bus_name="io.github.dynamotn.bwss",
                      interface="io.github.dynamotn.bwss.Control1")
    reply = bus.send_and_get_reply(new_method_call(ctl, "UnlockWithPassword", "s", (PASSWORD,)))
    assert reply.header.message_type.name == "error"
    assert "only the bwss CLI" in reply.body[0], reply.body
    assert d.cli("status").stdout.startswith("locked")
    # The CLI is bwss's own executable, so it still may.
    unlock(d)
    assert d.cli("status").stdout.startswith("unlocked")


def test_collections(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.pinentry(confirm="once")
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


def _object_exists(conn, path):
    """True while the daemon still serves an object at `path` (Introspect succeeds)."""
    reply = _call(conn, path, "org.freedesktop.DBus.Introspectable", "Introspect")
    return reply.header.message_type.name == "method_return"


def test_one_client_cannot_evict_anothers_sessions(memory_daemon, bus, other_bus):
    a_session = _open_plain(bus)
    first_b = _open_plain(other_bus)
    for _ in range(SESSION_CAP + 8):
        newest_b = _open_plain(other_bus)
    # A's session is untouched by B's flood.
    assert _object_exists(bus, a_session)
    # B pushed out only its own oldest sessions, and their objects are gone.
    assert not _object_exists(other_bus, first_b)
    assert _object_exists(other_bus, newest_b)


def test_session_close_is_limited_to_its_owner(memory_daemon, bus, other_bus):
    a_session = _open_plain(bus)
    denied = _call(other_bus, a_session, "org.freedesktop.Secret.Session", "Close")
    assert denied.header.message_type.name == "error"
    assert _object_exists(bus, a_session)
    ok = _call(bus, a_session, "org.freedesktop.Secret.Session", "Close")
    assert ok.header.message_type.name == "method_return"
    assert not _object_exists(bus, a_session)


def test_prompts_are_capped_per_client(memory_daemon, bus, other_bus):
    a_prompt = _call(bus, SVC, "org.freedesktop.Secret.Service", "Unlock", "ao", ([LOGIN],)).body[1]
    b_prompts = [
        _call(other_bus, SVC, "org.freedesktop.Secret.Service", "Unlock", "ao", ([LOGIN],)).body[1]
        for _ in range(PROMPT_CAP + 4)
    ]
    # B's oldest prompts were dismissed and removed; its newest survive; A's is untouched.
    assert not _object_exists(other_bus, b_prompts[0])
    assert _object_exists(other_bus, b_prompts[-1])
    assert _object_exists(bus, a_prompt)


def test_sessions_and_prompts_of_a_departed_client_are_freed(memory_daemon, bus):
    import secretstorage as ss

    gone = ss.dbus_init()
    session = _open_plain(gone)
    prompt = _call(gone, SVC, "org.freedesktop.Secret.Service", "Unlock", "ao", ([LOGIN],)).body[1]
    assert _object_exists(bus, session) and _object_exists(bus, prompt)
    gone.close()
    for _ in range(50):
        if not _object_exists(bus, session) and not _object_exists(bus, prompt):
            break
        time.sleep(0.1)
    assert not _object_exists(bus, session)
    assert not _object_exists(bus, prompt)


# --- prompts belong to the client that asked (R7) -------------------------------------

PROMPT_IFACE = "org.freedesktop.Secret.Prompt"


def _error_name(reply):
    from jeepney import HeaderFields

    return reply.header.fields.get(HeaderFields.error_name)


def _wait_until(check, tries=100):
    for _ in range(tries):
        if check():
            return True
        time.sleep(0.1)
    return False


def test_only_the_client_that_asked_may_start_its_prompt(memory_daemon, bus, other_bus):
    d = memory_daemon
    d.pinentry(pins=[PASSWORD], delay=1)
    prompt = _call(bus, SVC, "org.freedesktop.Secret.Service", "Unlock", "ao", ([LOGIN],)).body[1]
    for member in ("Prompt", "Dismiss"):
        sig, body = ("s", ("",)) if member == "Prompt" else ("", ())
        stolen = _call(other_bus, prompt, PROMPT_IFACE, member, sig, body)
        assert stolen.header.message_type.name == "error", member
        assert _error_name(stolen) == "org.freedesktop.Secret.Error.AccessDenied", stolen.body
    assert not [p for p in d.prompts() if p.startswith("GETPIN")], "nothing was asked"
    assert _object_exists(bus, prompt)
    # The client that asked still can, once.
    own = _call(bus, prompt, PROMPT_IFACE, "Prompt", "s", ("",))
    assert own.header.message_type.name == "method_return", own.body
    again = _call(bus, prompt, PROMPT_IFACE, "Prompt", "s", ("",))
    assert again.header.message_type.name == "error" and "already used" in again.body[0], again.body
    assert _wait_until(lambda: d.cli("status").stdout.startswith("unlocked"))


def test_a_started_prompt_is_cancelled_when_its_client_leaves(memory_daemon, bus):
    import secretstorage as ss

    d = memory_daemon
    # The user answers only after the client has gone.
    d.pinentry(pins=[PASSWORD], delay=2)
    gone = ss.dbus_init()
    session = _open_plain(gone)
    props = {
        "org.freedesktop.Secret.Item.Label": ("s", "left behind"),
        "org.freedesktop.Secret.Item.Attributes": ("a{ss}", {"cancel": "me"}),
    }
    created = _call(gone, LOGIN, "org.freedesktop.Secret.Collection", "CreateItem", "a{sv}(oayays)b",
                    (props, (session, b"", b"pending", "text/plain"), False))
    item, prompt = created.body
    assert item == "/" and prompt != "/", created.body
    started = _call(gone, prompt, PROMPT_IFACE, "Prompt", "s", ("",))
    assert started.header.message_type.name == "method_return", started.body
    gone.close()
    # The password still unlocks the keyring, but the departed client's item
    # is never written.
    assert _wait_until(lambda: d.cli("status").stdout.startswith("unlocked"))
    time.sleep(0.5)
    assert not list(secretstorage.search_items(bus, {"cancel": "me"}))
    assert not _object_exists(bus, prompt)


def test_a_password_for_an_unlocked_keyring_is_not_tried(memory_daemon):
    d = memory_daemon
    unlock(d)
    start = time.monotonic()
    r = d.cli("unlock", "--password-stdin", input="wrong\n", check=False)
    assert r.returncode == 0 and "unlocked" in r.stdout, r.stderr
    assert time.monotonic() - start < 2, "no penalty"
    assert d.cli("status").stdout.startswith("unlocked")
