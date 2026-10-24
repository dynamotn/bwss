"""bwss over a real Vaultwarden, cross-checked with an independent client.

Needs BW_E2E_URL (e.g. http://127.0.0.1:80 when the test container shares
the Vaultwarden container's network namespace).
"""

import base64
import json
import os
import shutil
import socket
import threading
import time
import urllib.parse

import pytest
import secretstorage

from bwclient import Account
from conftest import Daemon

URL = os.environ.get("BW_E2E_URL")
pytestmark = pytest.mark.skipif(not URL, reason="BW_E2E_URL not set")
FOLDER = "secret-service"


@pytest.fixture(scope="module")
def account():
    return Account(URL)


def bitwarden_daemon(account, server=None, acl="off"):
    d = Daemon({"backend": "bitwarden", "folder": FOLDER}, profile={"server_url": server or URL, "email": account.email},
               acl_off=acl == "off")
    # `bwss login` stores the profile's API key, bound to its server.
    d.cli("login", "--client-id", account.client_id, "--client-secret-stdin", input=account.client_secret + "\n")
    return d


def unlock(d, account):
    d.cli("unlock", "--password-stdin", input=account.password + "\n")


def test_secret_tool_writes_land_in_bitwarden(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        d.tool("store", "--label=GitHub token", "service", "github", "user", "me", input="ghp_e2e")
        it = account.items(FOLDER)["GitHub token"]
        # A secure note: no login, the secret in the hidden bwss:password field.
        assert it["type"] == 2
        assert it["password"] is None
        assert not it["notes"]
        assert it["fields"]["bwss:password"] == "ghp_e2e"
        assert it["fields"]["bwss:attr:service"] == "github"
        assert it["fields"]["bwss:attr:user"] == "me"
        assert it["fields"]["bwss:id"]

        d.tool("store", "--label=GitHub token", "service", "github", "user", "me", input="ghp_rotated")
        it = account.items(FOLDER)["GitHub token"]
        assert it["fields"]["bwss:password"] == "ghp_rotated"
        assert it["history"] == []
    finally:
        d.stop()


def test_items_from_other_clients_and_remote_edits(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(FOLDER, "Bank", "hunter2", {"bwss:id": "bank", "bwss:attr:service": "bank"})
        d.cli("sync")
        assert d.tool("lookup", "service", "bank").stdout == "hunter2"
        account.set_password(c["id"], "hunter3")
        d.cli("sync")
        assert d.tool("lookup", "service", "bank").stdout == "hunter3"
        # The login's own password is foreign content: deleting only strips the bwss fields.
        d.tool("clear", "service", "bank")
        it = account.item(c["id"])
        assert not it["deleted"]
        assert it["password"] == "hunter3"
        assert not [n for n in it["fields"] if n.startswith("bwss:")]
    finally:
        d.stop()


def test_restart_finds_locked_items_and_unlocks_on_demand(account):
    d = bitwarden_daemon(account).start()
    unlock(d, account)
    d.tool("store", "--label=restart", "restart", "yes", input="persisted")
    d.stop()
    d.start()
    try:
        assert d.cli("status").stdout.startswith("locked")
        # libsecret sees the locked item through the locked index and unlocks it via the prompt.
        d.pinentry(pins=[account.password])
        assert d.tool("lookup", "restart", "yes").stdout == "persisted"
        assert any(p.startswith("GETPIN") for p in d.prompts())
    finally:
        d.stop()


class Relay:
    """A TCP relay to Vaultwarden that can be cut: the server goes offline
    while its URL, and so the origin the API key is bound to, stays the same."""

    def __init__(self, target_url):
        u = urllib.parse.urlsplit(target_url)
        self.target = (u.hostname, u.port or 80)
        self.up = True
        self.conns = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.url = f"http://127.0.0.1:{self.sock.getsockname()[1]}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            if not self.up:
                client.close()
                continue
            server = socket.create_connection(self.target)
            self.conns += [client, server]
            for a, b in ((client, server), (server, client)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    @staticmethod
    def _pipe(a, b):
        try:
            while data := a.recv(65536):
                b.sendall(data)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def cut(self):
        self.up = False
        for s in self.conns:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.conns = []

    def restore(self):
        self.up = True

    def close(self):
        self.cut()
        self.sock.close()


def test_offline_unlock_reads_and_queues_writes(account):
    relay = Relay(URL)
    online = bitwarden_daemon(account, server=relay.url).start()
    try:
        unlock(online, account)
        online.tool("store", "--label=offline-read", "off", "read", input="cached")
        online.stop()

        # Same home, unreachable server: unlock from the cache, write into the queue.
        relay.cut()
        online.start()
        try:
            unlock(online, account)
            assert online.tool("lookup", "off", "read").stdout == "cached"
            online.tool("store", "--label=offline-write", "off", "write", input="queued")
            assert "1 queued" in online.cli("status").stdout
            assert "offline-write" not in account.items(FOLDER)
        finally:
            online.stop()

        relay.restore()
        online.start()
        unlock(online, account)
        deadline = time.time() + 10
        while "offline-write" not in account.items(FOLDER) and time.time() < deadline:
            time.sleep(0.5)
        assert account.items(FOLDER)["offline-write"]["fields"]["bwss:password"] == "queued"
        assert "0 queued" in online.cli("status").stdout
    finally:
        online.stop()
        relay.close()


def test_collections_come_from_the_field(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        bus = secretstorage.dbus_init()
        try:
            work = secretstorage.create_collection(bus, "Work")
            work.create_item("vpn", {"svc": "vpn"}, b"pw")
        finally:
            bus.close()
        vpn = account.items(FOLDER)["vpn"]
        assert vpn["fields"]["bwss:collection"] == "work"
        assert vpn["fields"]["bwss:password"] == "pw"
        assert vpn["folder"] == account.folder_id(FOLDER)
        registry = [i for i in account.items(FOLDER).values() if i["fields"].get("bwss:id") == "_collections"]
        assert len(registry) == 1
        assert registry[0]["fields"]["bwss:kind"] == "collections"
        assert json.loads(registry[0]["notes"])["work"]["label"] == "Work"
    finally:
        d.stop()


def sync_lookup(d, *attrs):
    d.cli("sync")
    return d.tool("lookup", *attrs, check=False)


def test_marked_login_is_found_and_written_back(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(None, "GitHub", "gh-old", {"bwss:id": "gh"}, username="octocat", uri="https://github.com")
        assert account.item(c["id"])["folder"] is None
        d.cli("sync")
        assert d.tool("lookup", "bwss:name", "GitHub").stdout == "gh-old"
        assert d.tool("lookup", "bwss:id", "gh").stdout == "gh-old"
        assert d.tool("lookup", "bwss:username", "octocat").stdout == "gh-old"
        assert d.tool("lookup", "bwss:uri", "https://github.com").stdout == "gh-old"

        d.tool("store", "--label=GitHub", "bwss:name", "GitHub", input="gh-new")
        it = account.item(c["id"])
        assert it["password"] == "gh-new"
        assert it["history"][0] == "gh-old"
        assert it["fields"]["bwss:id"] == "gh"
        assert it["username"] == "octocat"
        assert len(account.fields(c["id"])) == 1
    finally:
        d.stop()


def test_bwss_password_field_keeps_login_password(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(FOLDER, "Deploy", "web-login", {
            "bwss:id": "deploy", "bwss:password": "app-token", "bwss:attr:app": "deploy"})
        d.cli("sync")
        assert d.tool("lookup", "app", "deploy").stdout == "app-token"
        d.tool("store", "--label=Deploy", "app", "deploy", input="app-token-2")
        it = account.item(c["id"])
        assert it["fields"]["bwss:password"] == "app-token-2"
        assert it["password"] == "web-login"
        assert it["history"] == []
    finally:
        d.stop()


def test_binary_secret_on_marked_login_goes_to_new_field(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(FOLDER, "Binary host", "web-pw", {"bwss:id": "bin1", "bwss:attr:bin": "1"})
        before = account.item(c["id"])
        d.cli("sync")
        raw = b"\xff\x00\x01"
        bus = secretstorage.dbus_init()
        try:
            coll = secretstorage.get_default_collection(bus)
            coll.create_item("Binary host", {"bin": "1"}, raw, replace=True, content_type="application/octet-stream")
            found = list(coll.search_items({"bin": "1"}))
            assert len(found) == 1
            assert found[0].get_secret() == raw
        finally:
            bus.close()
        it = account.item(c["id"])
        assert it["fields"]["bwss:password"] == base64.b64encode(raw).decode()
        assert it["field_types"]["bwss:password"] == 1
        assert it["fields"]["bwss:encoding"] == "base64"
        assert it["password"] == "web-pw"
        assert it["history"] == before["history"]
    finally:
        d.stop()


def test_delete_strips_hand_marked_and_trashes_own(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        hand = account.add_login(FOLDER, "Hand marked", "keep-me", {"bwss:id": "hand", "bwss:attr:k": "hand"})
        d.cli("sync")
        d.tool("clear", "k", "hand")
        it = account.item(hand["id"])
        assert not it["deleted"] and it["password"] == "keep-me"
        assert not [n for n in it["fields"] if n.startswith("bwss:")]
        assert d.tool("lookup", "k", "hand", check=False).stdout == ""

        d.tool("store", "--label=Own item", "k", "own", input="temp")
        own = account.items(FOLDER)["Own item"]["id"]
        d.tool("clear", "k", "own")
        assert account.item(own)["deleted"]
    finally:
        d.stop()


def test_item_shared_with_obsidian_is_never_trashed(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        d.tool("store", "--label=Shared note", "k", "shared", input="temp")
        cid = account.items(FOLDER)["Shared note"]["id"]
        account.set_fields(cid, account.fields(cid) + [("obsidian:id", "vault-1")])
        d.cli("sync")
        d.tool("clear", "k", "shared")
        it = account.item(cid)
        assert not it["deleted"]
        assert it["fields"] == {"obsidian:id": "vault-1"}
        assert d.tool("lookup", "k", "shared", check=False).stdout == ""
    finally:
        d.stop()


def test_unmarking_removes_from_keyring(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(FOLDER, "Unmarked later", "pw-um", {"bwss:id": "um"})
        assert sync_lookup(d, "bwss:id", "um").stdout == "pw-um"
        account.remove_field(c["id"], "bwss:id")
        assert sync_lookup(d, "bwss:id", "um").stdout == ""
        it = account.item(c["id"])
        assert not it["deleted"] and it["password"] == "pw-um"
    finally:
        d.stop()


def test_clone_does_not_change_what_apps_see(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(FOLDER, "Original", "orig-pw", {"bwss:id": "cl"})
        assert sync_lookup(d, "bwss:id", "cl").stdout == "orig-pw"
        time.sleep(1.1)  # the clone must have a later creationDate
        clone = account.clone(c["id"])
        account.set_password(clone, "clone-pw")
        assert sync_lookup(d, "bwss:id", "cl").stdout == "orig-pw"
        # The loser stays untouched by writes.
        d.tool("store", "--label=Original", "bwss:id", "cl", input="orig-2")
        assert account.item(c["id"])["password"] == "orig-2"
        assert account.item(clone)["password"] == "clone-pw"
    finally:
        d.stop()


def test_unmarked_items_never_reach_the_bus(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        account.add_login(FOLDER, "Plain Unmarked Login", "plain-pw", username="plainuser", uri="https://plain.example")
        account.add_login(None, "Obsidian Only Login", "obs-pw", {"obsidian:id": "o1"})
        account.add_note(FOLDER, "Unmarked Journal", "dear diary", {"other:thing": "x"})
        account.add_login(None, "Marked Visible", "vis-pw", {"bwss:id": "vis"})
        d.cli("sync")
        bus = secretstorage.dbus_init()
        try:
            seen = []
            for coll in secretstorage.get_all_collections(bus):
                seen.append(coll.get_label())
                for item in coll.get_all_items():
                    seen.append(item.get_label())
                    seen.append(repr(item.get_attributes()))
        finally:
            bus.close()
        blob = "\n".join(seen)
        assert "Marked Visible" in blob
        for hidden in ("Plain Unmarked Login", "plainuser", "plain.example", "Obsidian Only Login", "Unmarked Journal", "_collections"):
            assert hidden not in blob, hidden
    finally:
        d.stop()


def test_wrong_password_is_reported(account):
    d = bitwarden_daemon(account).start()
    try:
        r = d.cli("unlock", "--password-stdin", input="not it\n", check=False)
        assert r.returncode != 0 and "wrong master password" in (r.stderr + r.stdout).lower()
    finally:
        d.stop()


def confirms(d):
    return sum(1 for p in d.prompts() if p.startswith("CONFIRM"))


def test_a_synced_acl_line_is_confirmed_once_on_this_device(account):
    d = bitwarden_daemon(account, acl="prompt").start()
    try:
        unlock(d, account)
        # Another client granted secret-tool: the line syncs in, unconfirmed here.
        tool = os.path.realpath(shutil.which("secret-tool"))
        account.add_login(FOLDER, "Synced grant", "syn-pw", {"bwss:id": "syn-7f3a", "bwss:attr:syn": "1", "bwss:acl": tool})
        d.cli("sync")
        d.pinentry(confirm="always")
        assert d.tool("lookup", "syn", "1").stdout == "syn-pw"
        assert confirms(d) == 1, d.prompts()
        assert any(p.startswith("SETDESC") and "granted on another device" in p for p in d.prompts()), d.prompts()
        assert not any("Always allow" in p for p in d.prompts()), d.prompts()

        d.pinentry(confirm="deny")
        assert d.tool("lookup", "syn", "1").stdout == "syn-pw"
        assert confirms(d) == 1, "confirmed once on this device"

        state = d.home / "state" / "dybw" / "tools" / "bwss" / "acl-confirmed"
        sealed = json.loads(state.read_text())
        assert sealed["format"] == 2 and sealed["set"].startswith("2.")
        assert "secret-tool" not in state.read_text() and "syn-7f3a" not in state.read_text()
        assert (state.stat().st_mode & 0o777) == 0o600
    finally:
        d.stop()


def test_a_denied_synced_acl_line_is_denied_without_asking_again(account):
    d = bitwarden_daemon(account, acl="prompt").start()
    try:
        unlock(d, account)
        tool = os.path.realpath(shutil.which("secret-tool"))
        account.add_login(FOLDER, "Denied grant", "den-pw", {"bwss:id": "den", "bwss:attr:den": "1", "bwss:acl": tool})
        d.cli("sync")
        d.pinentry(confirm="deny")
        assert d.tool("lookup", "den", "1", check=False).stdout == ""
        assert confirms(d) == 1

        # Even a pinentry that would allow is not asked: the denial is remembered.
        d.pinentry(confirm="always")
        assert d.tool("lookup", "den", "1", check=False).stdout == ""
        assert confirms(d) == 1, d.prompts()
        # And it survives a restart of the daemon.
        d.stop()
        d.start()
        unlock(d, account)
        assert d.tool("lookup", "den", "1", check=False).stdout == ""
        assert confirms(d) == 1, d.prompts()
    finally:
        d.stop()


def test_always_allow_here_needs_no_confirmation_after_a_restart(account):
    d = bitwarden_daemon(account, acl="prompt").start()
    try:
        unlock(d, account)
        account.add_login(FOLDER, "Local grant", "loc-pw", {"bwss:id": "loc", "bwss:attr:loc": "1"})
        d.cli("sync")
        d.pinentry(confirm="always")
        assert d.tool("lookup", "loc", "1").stdout == "loc-pw"
        assert "SETOK Always allow" in d.prompts()
        tool = os.path.realpath(shutil.which("secret-tool"))
        cid = next(i for i in account.items(FOLDER).values() if i["fields"].get("bwss:id") == "loc")["id"]
        assert account.item(cid)["fields"]["bwss:acl"] == tool
        d.stop()
        d.start()
        unlock(d, account)
        d.pinentry(confirm="deny")
        before = confirms(d)
        assert d.tool("lookup", "loc", "1").stdout == "loc-pw"
        assert confirms(d) == before, "granted on this device, so no confirmation"
    finally:
        d.stop()
