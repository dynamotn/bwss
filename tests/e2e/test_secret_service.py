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


def _logged_departure(d, name):
    """Whether the daemon log shows that `name` left and was dropped."""
    import re

    text = re.sub(r"\x1b\[[0-9;]*m", "", (d.home / "daemon.log").read_text())
    owner = re.compile(rf"owner={re.escape(name)}(\s|$)")
    return any("a client left the bus" in line and owner.search(line) for line in text.splitlines())


def test_only_the_client_that_asked_may_start_its_prompt(memory_daemon, bus, other_bus):
    d = memory_daemon
    release = d.home / "release-pinentry"
    d.pinentry(pins=[PASSWORD], release=str(release))
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
    release.touch()
    assert _wait_until(lambda: d.cli("status").stdout.startswith("unlocked"))


def test_a_started_prompt_is_cancelled_when_its_client_leaves(memory_daemon, bus):
    import secretstorage as ss

    d = memory_daemon
    # The user answers only after the daemon saw the client go.
    release = d.home / "release-pinentry"
    d.pinentry(pins=[PASSWORD], release=str(release))
    gone = ss.dbus_init()
    name = gone.unique_name
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
    assert _wait_until(lambda: any(p.startswith("GETPIN") for p in d.prompts())), "the dialog is up"
    gone.close()
    assert _wait_until(lambda: _logged_departure(d, name)), "the daemon dropped the client"
    release.touch()
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


# --- every Secret Service method, over raw D-Bus --------------------------------------

SERVICE = "org.freedesktop.Secret.Service"
COLLECTION = "org.freedesktop.Secret.Collection"
ITEM = "org.freedesktop.Secret.Item"
SESSION_COLL = "/org/freedesktop/secrets/collection/session"
LABEL = "org.freedesktop.Secret.Collection.Label"
ITEM_LABEL = "org.freedesktop.Secret.Item.Label"
ITEM_ATTRS = "org.freedesktop.Secret.Item.Attributes"


def _ok(reply):
    assert reply.header.message_type.name == "method_return", (_error_name(reply), reply.body)
    return reply.body


def _refused(reply, name, message=None):
    """Asserts that `reply` is the error org.freedesktop.Secret.Error.<name> (or a full error name)."""
    assert reply.header.message_type.name == "error", reply.body
    full = name if "." in name else f"org.freedesktop.Secret.Error.{name}"
    assert _error_name(reply) == full, (_error_name(reply), reply.body)
    if message is not None:
        assert reply.body[0] == message, reply.body
    return reply.body[0]


def _get(conn, path, interface, prop):
    return _ok(_call(conn, path, "org.freedesktop.DBus.Properties", "Get", "ss", (interface, prop)))[0][1]


def _set(conn, path, interface, prop, sig, value):
    return _call(conn, path, "org.freedesktop.DBus.Properties", "Set", "ssv", (interface, prop, (sig, value)))


def _status(d):
    """"locked" or "unlocked", from the first word of `bwss status`."""
    return d.cli("status").stdout.split()[0].rstrip(",")


def _run_prompt(conn, prompt, during=None):
    """Starts `prompt` and returns its Completed signal's (dismissed, (signature, result)).

    `during(conn)` runs after the prompt was started, before the signal is awaited.
    """
    from jeepney import MatchRule
    from jeepney.bus_messages import message_bus as bus_driver

    rule = MatchRule(type="signal", interface=PROMPT_IFACE, member="Completed", path=prompt)
    _ok(conn.send_and_get_reply(bus_driver.AddMatch(rule)))
    with conn.filter(rule) as queue:
        _ok(_call(conn, prompt, PROMPT_IFACE, "Prompt", "s", ("",)))
        if during:
            during(conn)
        return conn.recv_until_filtered(queue, timeout=60).body


def _item_of(conn, attributes):
    unlocked, locked = _ok(_call(conn, SVC, SERVICE, "SearchItems", "a{ss}", (attributes,)))
    return (unlocked + locked)[0]


def _create_item(conn, collection, session, attributes, value, replace=False, label="e2e"):
    props = {ITEM_LABEL: ("s", label), ITEM_ATTRS: ("a{ss}", attributes)}
    return _call(conn, collection, COLLECTION, "CreateItem", "a{sv}(oayays)b",
                 (props, (session, b"", value, "text/plain"), replace))


def test_aliases_name_the_built_in_collections(memory_daemon, bus):
    unlock(memory_daemon)
    for name, path in [("default", LOGIN), ("login", LOGIN), ("session", SESSION_COLL), ("nope", "/")]:
        assert _ok(_call(bus, SVC, SERVICE, "ReadAlias", "s", (name,))) == (path,), name
    # Creating the "default" collection gives the existing login collection.
    created = _ok(_call(bus, SVC, SERVICE, "CreateCollection", "a{sv}s", ({LABEL: ("s", "Other")}, "default")))
    assert created == (LOGIN, "/")
    assert sorted(_get(bus, SVC, SERVICE, "Collections")) == sorted([LOGIN, SESSION_COLL])
    # Re-asserting default -> login is accepted; nothing else is.
    assert _ok(_call(bus, SVC, SERVICE, "SetAlias", "so", ("default", LOGIN))) == ()
    for name, path in [("default", SESSION_COLL), ("work", LOGIN)]:
        _refused(_call(bus, SVC, SERVICE, "SetAlias", "so", (name, path)), "NotSupported",
                 "aliases other than default → login are not supported")
    assert _ok(_call(bus, SVC, SERVICE, "ReadAlias", "s", ("work",))) == ("/",)


def test_a_collection_asked_for_while_locked_is_created_once_the_prompt_unlocks(memory_daemon, bus):
    d = memory_daemon
    d.pinentry(pins=[PASSWORD])
    coll, prompt = _ok(_call(bus, SVC, SERVICE, "CreateCollection", "a{sv}s", ({LABEL: ("s", "Work")}, "")))
    assert coll == "/" and prompt.startswith("/org/freedesktop/secrets/prompt/"), (coll, prompt)
    work = "/org/freedesktop/secrets/collection/work"
    assert _run_prompt(bus, prompt) == (False, ("o", work))
    assert _status(d) == "unlocked"
    assert _ok(_call(bus, SVC, SERVICE, "ReadAlias", "s", ("work",))) == (work,)
    assert work in _get(bus, SVC, SERVICE, "Collections")
    assert _get(bus, work, COLLECTION, "Label") == "Work"
    created, modified = _get(bus, work, COLLECTION, "Created"), _get(bus, work, COLLECTION, "Modified")
    assert created > 1_600_000_000 and modified >= created
    assert _ok(_set(bus, work, COLLECTION, "Label", "s", "Renamed")) == ()
    assert _get(bus, work, COLLECTION, "Label") == "Renamed"
    assert _get(bus, work, COLLECTION, "Modified") >= modified
    assert _get(bus, work, COLLECTION, "Locked") is False
    assert _get(bus, LOGIN, COLLECTION, "Created") > 0 and _get(bus, LOGIN, COLLECTION, "Modified") > 0


def test_lock_and_unlock_leave_the_session_collection_alone(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    assert _ok(_call(bus, SVC, SERVICE, "Lock", "ao", ([SESSION_COLL],))) == ([], "/")
    assert _status(d) == "unlocked", "the session collection never locks"
    assert _ok(_call(bus, SVC, SERVICE, "Lock", "ao", ([LOGIN, SESSION_COLL],))) == ([LOGIN], "/")
    assert _status(d) == "locked"
    # The session collection is always open: unlocking it needs no prompt.
    assert _ok(_call(bus, SVC, SERVICE, "Unlock", "ao", ([SESSION_COLL],))) == ([SESSION_COLL], "/")
    assert _status(d) == "locked"
    unlock(d)
    assert _ok(_call(bus, SVC, SERVICE, "LockService")) == ()
    assert _status(d) == "locked"
    _refused(_call(bus, SVC, SERVICE, "ChangeLock", "o", (LOGIN,)), "NotSupported",
             "the keyring password is the Bitwarden master password; change it in Bitwarden")


def test_get_secrets_returns_only_the_items_it_can_read(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=a", "multi", "known", input="one")
    item = _item_of(bus, {"multi": "known"})
    session = _open_plain(bus)
    d.pinentry(confirm="once")
    secrets = _ok(_call(bus, SVC, SERVICE, "GetSecrets", "aoo", ([LOGIN + "/nope", item], session)))[0]
    assert secrets == {item: (session, b"", b"one", "text/plain")}


def test_a_session_serves_only_the_client_that_opened_it(memory_daemon, bus, other_bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=a", "owned", "session", input="mine")
    item = _item_of(bus, {"owned": "session"})
    theirs = _open_plain(other_bus)
    _refused(_call(bus, item, ITEM, "GetSecret", "o", (theirs,)), "NoSession", "the session belongs to another client")
    _refused(_create_item(bus, LOGIN, theirs, {"owned": "other"}, b"x"), "NoSession",
             "the session belongs to another client")
    assert not _ok(_call(bus, SVC, SERVICE, "SearchItems", "a{ss}", ({"owned": "other"},)))[0]


def test_a_secret_that_does_not_decrypt_is_refused(memory_daemon, bus):
    from secretstorage.util import open_session

    unlock(memory_daemon)
    session = open_session(bus)
    assert session.encrypted
    props = {ITEM_LABEL: ("s", "bad"), ITEM_ATTRS: ("a{ss}", {"cipher": "bad"})}
    reply = _call(bus, LOGIN, COLLECTION, "CreateItem", "a{sv}(oayays)b",
                  (props, (session.object_path, b"short iv", b"0123456789abcdef", "text/plain"), False))
    _refused(reply, "Failed", "invalid encrypted secret")
    assert not _ok(_call(bus, SVC, SERVICE, "SearchItems", "a{ss}", ({"cipher": "bad"},)))[0]


def test_a_property_change_without_access_fails(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=private", "prop", "acl", input="mine")
    item = _item_of(bus, {"prop": "acl"})
    d.pinentry(confirm="deny")
    for prop, sig, value in [("Label", "s", "stolen"), ("Attributes", "a{ss}", {"prop": "stolen"})]:
        message = _refused(_set(bus, item, ITEM, prop, sig, value), "org.freedesktop.DBus.Error.Failed")
        assert message.startswith("AccessDenied(") and "was denied access to" in message, message
    assert _get(bus, item, ITEM, "Label") == "private"
    assert _get(bus, item, ITEM, "Attributes") == {"prop": "acl"}


def test_a_prompt_whose_action_fails_completes_as_dismissed(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=mine", "replace", "denied", input="mine")
    attributes = _get(bus, _item_of(bus, {"replace": "denied"}), ITEM, "Attributes")
    d.cli("lock")
    session = _open_plain(bus)
    # The password unlocks the keyring, then replacing secret-tool's item is denied.
    d.pinentry(pins=[PASSWORD], confirm="deny")
    item, prompt = _ok(_create_item(bus, LOGIN, session, attributes, b"other", replace=True))
    assert item == "/"
    assert _run_prompt(bus, prompt) == (True, ("o", "/"))
    assert _status(d) == "unlocked"
    assert d.tool("lookup", "replace", "denied").stdout == "mine"
    assert "prompt action failed" in (d.home / "daemon.log").read_text()
    assert not _object_exists(bus, prompt)


def test_a_dismissed_prompt_completes_once_and_goes(memory_daemon, bus):
    from jeepney import MatchRule
    from jeepney.bus_messages import message_bus as bus_driver

    prompt = _ok(_call(bus, SVC, SERVICE, "Unlock", "ao", ([LOGIN],)))[1]
    rule = MatchRule(type="signal", interface=PROMPT_IFACE, member="Completed", path=prompt)
    _ok(bus.send_and_get_reply(bus_driver.AddMatch(rule)))
    with bus.filter(rule) as queue:
        assert _ok(_call(bus, prompt, PROMPT_IFACE, "Dismiss")) == ()
        assert bus.recv_until_filtered(queue, timeout=30).body == (True, ("ao", []))
    assert _wait_until(lambda: not _object_exists(bus, prompt))
    _refused(_call(bus, prompt, PROMPT_IFACE, "Dismiss"), "org.freedesktop.DBus.Error.UnknownObject")
    assert _status(memory_daemon) == "locked"


def test_a_prompt_whose_action_already_runs_is_not_dismissed(memory_daemon, bus):
    d = memory_daemon
    unlock(d)
    d.tool("store", "--label=mine", "replace", "running", input="mine")
    mine = _item_of(bus, {"replace": "running"})
    attributes = _get(bus, mine, ITEM, "Attributes")
    d.cli("lock")
    session = _open_plain(bus)
    release = d.home / "release-confirm"
    d.pinentry(pins=[PASSWORD], confirm="once", confirm_release=str(release))
    item, prompt = _ok(_create_item(bus, LOGIN, session, attributes, b"replaced", replace=True))

    def dismiss_while_asking(conn):
        # Unlocked; the action runs and asks whether python may replace the item.
        assert _wait_until(lambda: any(p.startswith("CONFIRM") for p in d.prompts()))
        assert _ok(_call(conn, prompt, PROMPT_IFACE, "Dismiss")) == ()
        release.touch()

    assert _run_prompt(bus, prompt, during=dismiss_while_asking) == (False, ("o", mine)), "the item was replaced"
    assert d.tool("lookup", "replace", "running").stdout == "replaced"


def _confirms_asked(d):
    return sum(1 for p in d.prompts() if p.startswith("CONFIRM"))


def test_an_item_deleted_during_its_access_prompt_is_not_read(memory_daemon, bus):
    import threading

    d = memory_daemon
    unlock(d)
    session = _open_plain(bus)
    replies = {}
    for name in ("GetSecret", "GetSecrets"):
        d.tool("store", f"--label={name}", "deleted", name, input="gone")
        item = _item_of(bus, {"deleted": name})
        if name == "GetSecret":
            call = (item, ITEM, name, "o", (session,))
        else:
            call = (SVC, SERVICE, name, "aoo", ([item], session))
        release = d.home / f"release-{name}"
        d.pinentry(confirm="once", confirm_release=str(release))
        before = _confirms_asked(d)
        reader = threading.Thread(target=lambda c=call, n=name: replies.update({n: _call(bus, *c)}))
        reader.start()
        # python is asked about; meanwhile secret-tool, which created the
        # item, deletes it without being asked.
        assert _wait_until(lambda: _confirms_asked(d) > before)
        d.tool("clear", "deleted", name)
        release.touch()
        reader.join(60)
    _refused(replies["GetSecret"], "IsLocked", "the item is locked")
    assert _ok(replies["GetSecrets"]) == ({},)
