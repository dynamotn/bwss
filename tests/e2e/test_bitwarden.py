"""bwss over a real Vaultwarden, cross-checked with an independent client.

Needs BW_E2E_URL (e.g. http://127.0.0.1:80 when the test container shares
the Vaultwarden container's network namespace).
"""

import os
import time

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


def bitwarden_daemon(account, server=None):
    d = Daemon({"backend": "bitwarden", "folder": FOLDER, "acl": "off"})
    # `bwss login` keeps the other settings and stores the API key with mode 0600.
    d.cli("login", "--email", account.email, "--server", server or URL, "--client-id", account.client_id,
          "--client-secret-stdin", input=account.client_secret + "\n")
    return d


def unlock(d, account):
    d.cli("unlock", "--password-stdin", input=account.password + "\n")


def test_secret_tool_writes_land_in_bitwarden(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        d.tool("store", "--label=GitHub token", "service", "github", "user", "me", input="ghp_e2e")
        items = account.items(FOLDER)
        it = items["GitHub token"]
        assert it["password"] == "ghp_e2e"
        assert it["fields"]["bwss:attr:service"] == "github"
        assert it["fields"]["bwss:attr:user"] == "me"
        assert it["fields"]["bwss:id"]

        d.tool("store", "--label=GitHub token", "service", "github", "user", "me", input="ghp_rotated")
        it = account.items(FOLDER)["GitHub token"]
        assert it["password"] == "ghp_rotated"
        assert "ghp_e2e" in it["history"]
    finally:
        d.stop()


def test_items_from_other_clients_and_remote_edits(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        c = account.add_login(FOLDER, "Bank", "hunter2", {"bwss:attr:service": "bank"})
        d.cli("sync")
        assert d.tool("lookup", "service", "bank").stdout == "hunter2"
        account.set_password(c["id"], "hunter3")
        d.cli("sync")
        assert d.tool("lookup", "service", "bank").stdout == "hunter3"
        # Deleting through the Secret Service trashes the Bitwarden item.
        d.tool("clear", "service", "bank")
        assert "Bank" not in account.items(FOLDER)
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


def test_offline_unlock_reads_and_queues_writes(account):
    online = bitwarden_daemon(account).start()
    unlock(online, account)
    online.tool("store", "--label=offline-read", "off", "read", input="cached")
    online.stop()

    # Same home, unreachable server: unlock from the cache, write into the queue.
    cfg = online.home / "config" / "bwss" / "config.toml"
    original = cfg.read_text()
    assert f'server_url = "{URL}"' in original
    cfg.write_text(original.replace(f'server_url = "{URL}"', 'server_url = "http://127.0.0.1:9"'))
    online.start()
    try:
        unlock(online, account)
        assert online.tool("lookup", "off", "read").stdout == "cached"
        online.tool("store", "--label=offline-write", "off", "write", input="queued")
        assert "1 queued" in online.cli("status").stdout
        assert "offline-write" not in account.items(FOLDER)
    finally:
        online.stop()

    cfg.write_text(original)
    online.start()
    try:
        unlock(online, account)
        deadline = time.time() + 10
        while "offline-write" not in account.items(FOLDER) and time.time() < deadline:
            time.sleep(0.5)
        assert account.items(FOLDER)["offline-write"]["password"] == "queued"
        assert "0 queued" in online.cli("status").stdout
    finally:
        online.stop()


def test_collections_are_subfolders(account):
    d = bitwarden_daemon(account).start()
    try:
        unlock(d, account)
        bus = secretstorage.dbus_init()
        work = secretstorage.create_collection(bus, "Work")
        work.create_item("vpn", {"svc": "vpn"}, b"pw")
        assert account.items(f"{FOLDER}/Work")["vpn"]["password"] == "pw"
        bus.close()
    finally:
        d.stop()


def test_wrong_password_is_reported(account):
    d = bitwarden_daemon(account).start()
    try:
        r = d.cli("unlock", "--password-stdin", input="not it\n", check=False)
        assert r.returncode != 0 and "wrong master password" in (r.stderr + r.stdout).lower()
    finally:
        d.stop()
