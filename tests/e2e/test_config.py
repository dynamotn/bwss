"""The shared dybw config file (ADR 0008): login, migration and device state.

None of these talk to a server: `bwss login` and the daemon's start are
offline, so the account points at a port nobody listens on.
"""

import os
import pty
import select
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path

from conftest import BWSS, PINENTRY, PROFILE, Daemon

SERVER = "http://127.0.0.1:9"
EMAIL = "me@example.org"
PASSWORD = "open sesame"


def run_daemon(d):
    """A daemon expected to refuse to start."""
    return subprocess.run([BWSS, "daemon"], env=d.env, capture_output=True, text=True, timeout=30)


def bitwarden_home(server=SERVER):
    return Daemon({"backend": "bitwarden"}, profile={"server_url": server, "email": EMAIL})


def login(d, secret="csecret"):
    return d.cli("login", "--client-id", "user.cid", "--client-secret-stdin", input=secret + "\n")


def on_terminal(d, *args, answer):
    """Runs the CLI with a terminal as stdin and stderr, answers its question,
    and returns (exit code, stdout, what the terminal showed)."""
    master, slave = pty.openpty()
    proc = subprocess.Popen([BWSS, *args], env=d.env, stdin=slave, stdout=subprocess.PIPE, stderr=slave)
    os.close(slave)
    shown = b""
    try:
        while b"Type" not in shown:
            ready, _, _ = select.select([master], [], [], 10)
            assert ready, f"no question on the terminal: {shown!r}"
            shown += os.read(master, 1024)
        os.write(master, answer.encode() + b"\n")
        out, _ = proc.communicate(timeout=10)
    finally:
        os.close(master)
    return proc.returncode, out.decode(), shown.decode()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_login_saves_the_profiles_key_bound_to_its_origin():
    d = bitwarden_home()
    creds = d.state / "profiles" / PROFILE / "credentials"
    assert str(creds) in login(d).stdout
    assert (mode(creds), mode(creds.parent)) == (0o600, 0o700)
    assert tomllib.loads(creds.read_text()) == {
        "identity_origin": SERVER,
        "client_id": "user.cid",
        "client_secret": "csecret",
    }
    # The daemon starts from the shared file with that key, and keeps its
    # own device id under the profile.
    d.start()
    try:
        assert d.cli("status").stdout.startswith("locked")
    finally:
        d.stop()
    log = (d.home / "daemon.log").read_text()
    assert f"pinentry {PINENTRY} accepted: not writable by this user" in log, log
    device = d.state / "profiles" / PROFILE / "devices" / "bwss"
    assert mode(device) == 0o600 and device.read_text().strip()
    for private in (d.home / "cache" / "bwss", d.home / "state" / "bwss", device.parent):
        assert mode(private) == 0o700, private


def test_the_key_is_refused_for_another_server_until_login_again():
    d = bitwarden_home()
    login(d)
    creds = d.state / "profiles" / PROFILE / "credentials"
    saved = creds.read_text()

    d.write_config({"backend": "bitwarden"}, profile={"server_url": "http://127.0.0.1:10", "email": EMAIL})
    r = run_daemon(d)
    assert r.returncode != 0
    assert SERVER in r.stderr and "http://127.0.0.1:10" in r.stderr and "bwss login" in r.stderr, r.stderr
    assert creds.read_text() == saved, "refused, not cleared"

    login(d)
    assert tomllib.loads(creds.read_text())["identity_origin"] == "http://127.0.0.1:10"
    d.start()
    d.stop()


def test_a_broken_credentials_file_never_shows_the_secret():
    d = bitwarden_home()
    login(d)
    creds = d.state / "profiles" / PROFILE / "credentials"
    creds.write_text(creds.read_text().replace('client_secret = "csecret"', 'client_secret = "s3cr3t-leak'))
    r = run_daemon(d)
    assert r.returncode != 0 and str(creds) in r.stderr and "line 3" in r.stderr, r.stderr
    assert "s3cr3t" not in r.stderr


def test_an_unreadable_credentials_file_stops_the_daemon_naming_it():
    d = bitwarden_home()
    login(d)
    creds = d.state / "profiles" / PROFILE / "credentials"
    creds.chmod(0o000)
    try:
        r = run_daemon(d)
    finally:
        creds.chmod(0o600)
    assert r.returncode != 0 and str(creds) in r.stderr and "Permission denied" in r.stderr, r.stderr
    assert "csecret" not in r.stderr


def test_login_needs_a_profile():
    d = Daemon({"backend": "memory"})
    r = d.cli("login", "--client-id", "x", "--client-secret-stdin", input="s\n", check=False)
    assert r.returncode != 0 and "no profile" in r.stderr, r.stderr


def test_the_file_cannot_turn_the_acl_off():
    d = Daemon({"backend": "memory", "acl": "off"})
    r = run_daemon(d)
    assert r.returncode != 0
    assert "`acl` in [bwss]" in r.stderr and "bwss acl off" in r.stderr, r.stderr
    # Another tool's table is its own business.
    d.write_config({"backend": "memory"})
    with d.config.open("a") as f:
        f.write('\n[obsidian]\nacl = "off"\n')
    d.start()
    d.stop()


def test_the_file_cannot_put_derived_attributes_in_the_locked_index():
    d = Daemon({"backend": "memory", "index_derived_attributes": True})
    r = run_daemon(d)
    assert r.returncode != 0
    assert "`index_derived_attributes` in [bwss]" in r.stderr and "bwss index derived on" in r.stderr, r.stderr


def test_derived_attributes_in_the_index_need_a_confirmation_on_a_terminal():
    d = Daemon({"backend": "memory"})
    flag = d.state / "tools" / "bwss" / "index-derived"
    r = d.cli("index", "derived", "on", input="yes\n", check=False)
    assert r.returncode != 0 and "terminal" in r.stderr, r.stderr
    assert not flag.exists()

    code, _, shown = on_terminal(d, "index", "derived", "on", answer="no")
    assert code != 0 and "usernames and URIs" in shown and "guessable offline from ~/.cache" in shown, shown
    assert str(d.home / "cache" / "bwss" / "locked-index.json") in shown.replace("\r\n", "\n").replace("\n", "")
    assert not flag.exists()

    code, out, _ = on_terminal(d, "index", "derived", "on", answer="yes")
    assert code == 0 and "in the locked index on this device" in out, out
    assert flag.exists() and mode(flag) == 0o600

    # Off needs no question.
    assert "out of the locked index" in d.cli("index", "derived", "off").stdout
    assert not flag.exists()


def test_unknown_keys_stop_the_daemon():
    d = Daemon({"backend": "memory"}, top={"idle_lock_minutes": 5})
    r = run_daemon(d)
    assert r.returncode != 0 and "unknown key `idle_lock_minutes`" in r.stderr, r.stderr


def user_pinentry(d):
    """A copy of the fake pinentry that the user owns, so could replace."""
    bin_dir = d.home / "bin"
    bin_dir.mkdir(exist_ok=True)
    shutil.copy(PINENTRY, bin_dir / "pinentry")
    return bin_dir / "pinentry"


def test_a_pinentry_the_user_could_replace_is_refused():
    d = Daemon({"backend": "memory"})
    mine = user_pinentry(d)
    d.write_config({"backend": "memory"}, top={"pinentry": str(mine)})
    r = run_daemon(d)
    assert r.returncode != 0 and f"pinentry {mine.resolve()}" in r.stderr and "writable" in r.stderr, r.stderr

    # Found through PATH, or reached through a link: still refused.
    d.write_config({"backend": "memory"}, top={"pinentry": "pinentry"})
    d.env["PATH"] = f"{mine.parent}:{d.env['PATH']}"
    r = run_daemon(d)
    assert r.returncode != 0 and str(mine.resolve()) in r.stderr, r.stderr
    link = d.home / "link"
    link.symlink_to(mine)
    d.write_config({"backend": "memory"}, top={"pinentry": str(link)})
    r = run_daemon(d)
    assert r.returncode != 0 and str(mine.resolve()) in r.stderr, r.stderr


def other_tool(d):
    """A copy of secret-tool: another application for the ACL."""
    path = d.home / "other-tool"
    shutil.copy(shutil.which("secret-tool"), path)
    return lambda *args: subprocess.run([str(path), *args], env=d.env, capture_output=True, text=True)


def test_acl_off_needs_a_confirmation_on_a_terminal():
    d = Daemon({"backend": "memory", "memory_password": PASSWORD})
    off = d.state / "tools" / "bwss" / "acl-off"
    r = d.cli("acl", "off", input="yes\n", check=False)
    assert r.returncode != 0 and "terminal" in r.stderr, r.stderr
    assert not off.exists()

    code, _, shown = on_terminal(d, "acl", "off", answer="no")
    assert code != 0 and "Turn off per-application access control" in shown
    assert not off.exists()

    code, out, _ = on_terminal(d, "acl", "off", answer="yes")
    assert code == 0 and "off on this device" in out
    assert off.exists() and mode(off) == 0o600

    # Off: another application reads the item without a question.
    d.start()
    try:
        d.cli("unlock", "--password-stdin", input=PASSWORD + "\n")
        d.tool("store", "--label=open", "acl", "off", input="shared")
        other = other_tool(d)
        assert other("lookup", "acl", "off").stdout == "shared"
        assert not [p for p in d.prompts() if p.startswith("CONFIRM")]
    finally:
        d.stop()

    # Back on, without a question, and after a restart the ACL asks again.
    assert "on on this device" in d.cli("acl", "on").stdout
    assert not off.exists()
    d.start()
    try:
        d.cli("unlock", "--password-stdin", input=PASSWORD + "\n")
        d.tool("store", "--label=closed", "acl", "on", input="mine")
        d.pinentry(confirm="deny")
        assert other_tool(d)("lookup", "acl", "on").stdout == ""
        assert [p for p in d.prompts() if p.startswith("CONFIRM")]
    finally:
        d.stop()


def legacy_home(acl="off"):
    d = Daemon({"backend": "memory"})
    d.config.unlink()
    old = d.home / "config" / "bwss"
    old.mkdir(parents=True)
    (old / "config.toml").write_text(
        f'server_url = "{SERVER}"\nemail = "{EMAIL}"\nfolder = "keyring"\nprompter = "{PINENTRY}"\n'
        f'acl = "{acl}"\nidle_lock_minutes = 10\n'
    )
    (old / "credentials.toml").write_text('client_id = "user.cid"\nclient_secret = "csecret"\n')
    (old / "credentials.toml").chmod(0o600)
    (d.home / "state" / "bwss").mkdir(parents=True)
    (d.home / "state" / "bwss" / "device-id").write_text("dev-e2e\n")
    return d, old


def test_an_old_config_is_migrated():
    d, old = legacy_home()
    r = run_daemon(d)
    assert r.returncode != 0 and "bwss config migrate" in r.stderr, r.stderr

    # Without a terminal, `acl = "off"` is not confirmed: the ACL stays on.
    out = d.cli("config", "migrate").stdout
    assert "bwss acl off" in out, out
    assert not (d.state / "tools" / "bwss" / "acl-off").exists()

    cfg = tomllib.loads(d.config.read_text())
    assert cfg["bwss"] == {"profile": "bwss", "folder": "keyring", "backend": "bitwarden"}
    assert cfg["profiles"]["bwss"] == {
        "server_url": SERVER,
        "email": EMAIL,
        "lock_timeout_minutes": 10,
        "pinentry": PINENTRY,
    }
    profile = d.state / "profiles" / "bwss"
    assert tomllib.loads((profile / "credentials").read_text()) == {
        "identity_origin": SERVER,
        "client_id": "user.cid",
        "client_secret": "csecret",
    }
    assert (profile / "devices" / "bwss").read_text() == "dev-e2e"
    for name in ("config.toml", "credentials.toml"):
        assert not (old / name).exists() and (old / f"{name}.migrated").exists()
    assert (d.home / "state" / "bwss" / "device-id.migrated").exists()

    d.start()
    try:
        assert d.cli("status").stdout.startswith("locked")
    finally:
        d.stop()


def test_migrating_acl_off_asks_on_the_terminal():
    d, _ = legacy_home()
    code, out, shown = on_terminal(d, "config", "migrate", answer="yes")
    assert code == 0 and "Turn off per-application access control" in shown
    assert "access control is off" in out, out
    assert (d.state / "tools" / "bwss" / "acl-off").exists()
    assert "acl" not in d.config.read_text()


def test_a_migration_with_an_untrusted_prompter_changes_nothing():
    d, old = legacy_home(acl="prompt")
    text = (old / "config.toml").read_text().replace(PINENTRY, str(user_pinentry(d)))
    (old / "config.toml").write_text(text)
    r = d.cli("config", "migrate", check=False)
    assert r.returncode != 0 and "`prompter`" in r.stderr, r.stderr
    assert not d.config.exists()
    assert (old / "config.toml").read_text() == text
