"""pam_bwss end to end: pamtester drives real PAM stacks that load the module.

Runs as root in the bwss-e2e image only, started with
`--security-opt seccomp=unconfined` (Docker's default profile blocks the
keyring syscalls) and `--security-opt systempaths=unconfined` (it masks
/proc/keys, the only place that shows a key's expiry). It adds a user and writes /etc/pam.d/bwss-test-*, so it
refuses to run unless PAM_BWSS_SO names the built module (see README).
"""

import os
import secrets
import subprocess
import time
from pathlib import Path

import pytest

SO = os.environ.get("PAM_BWSS_SO", "")
USER, UID = "pamtest", 4242

pytestmark = pytest.mark.skipif(not SO or os.geteuid() != 0, reason="needs root and PAM_BWSS_SO (container only)")

WITH_PASSWORD = """\
auth     required pam_unix.so
auth     optional {so}
account  required pam_permit.so
password required pam_unix.so
password optional {so}
session  required pam_permit.so
session  optional {so}
"""
# A login without a password: PAM_AUTHTOK stays empty.
WITHOUT_PASSWORD = """\
auth     required pam_permit.so
auth     optional {so}
session  required pam_permit.so
session  optional {so}
"""


def as_user(*cmd):
    return ["setpriv", f"--reuid={UID}", f"--regid={UID}", "--clear-groups", *cmd]


def run(cmd, stdin=""):
    return subprocess.run(cmd, input=stdin.encode(), capture_output=True, timeout=30)


def pamtester(service, *ops, user=USER, stdin="", runner=lambda c: c):
    return run(runner(["pamtester", "-v", service, user, *ops]), stdin)


def entry(description, runner=as_user):
    """The entry as the consumer sees it: payload, seconds left, perm, uid, type."""
    found = run(runner("keyctl", "search", "@u", "user", description))
    if found.returncode:
        return None
    key = int(found.stdout)
    payload = run(runner("keyctl", "pipe", str(key))).stdout
    kind, uid, _, perm, _ = run(runner("keyctl", "rdescribe", str(key))).stdout.decode().split(";", 4)
    # Only /proc/keys shows the expiry; Docker masks it unless systempaths=unconfined.
    row = next(r.split() for r in run(runner("cat", "/proc/keys")).stdout.decode().splitlines()
               if int(r.split()[0], 16) == key)
    return {"payload": payload, "timeout": row[3], "perm": perm, "uid": int(uid), "type": kind}


def take(description):
    """What a consumer does once it has read the entry."""
    found = run(as_user("keyctl", "search", "@u", "user", description))
    if not found.returncode:
        assert not run(as_user("keyctl", "invalidate", found.stdout.decode().strip())).returncode


def set_password(password):
    subprocess.run(["chpasswd"], input=f"{USER}:{password}".encode(), check=True)


@pytest.fixture(scope="module", autouse=True)
def stacks():
    if run(["id", USER]).returncode:
        subprocess.run(["useradd", "--uid", str(UID), "--user-group", "--no-create-home", USER], check=True)
    for name, text in {"bwss-test": WITH_PASSWORD, "bwss-test-nopw": WITHOUT_PASSWORD}.items():
        Path(f"/etc/pam.d/{name}").write_text(text.format(so=SO))


@pytest.fixture(autouse=True)
def clean_keyring():
    for description in ("dybw:login", "dybw:login-old", "dybw:lock"):
        take(description)
    # The key system drops invalidated keys lazily; let it settle.
    time.sleep(0.2)


def test_a_password_login_leaves_the_token_for_a_minute_readable_by_the_user_alone():
    password = secrets.token_urlsafe(12)
    set_password(password)
    result = pamtester("bwss-test", "authenticate", "open_session", stdin=password + "\n")
    assert result.returncode == 0, result.stderr
    time.sleep(1.5)  # /proc/keys shows a full minute as "1m"; past it, seconds
    key = entry("dybw:login")
    assert key is not None
    assert key["payload"] == password.encode(), "the payload is the token's bytes, no terminator"
    assert key["type"] == "user" and key["uid"] == UID
    assert key["perm"] == "0b0b0000", "view, read, search for possessor and user; nothing else"
    assert key["timeout"].endswith("s") and 50 < int(key["timeout"][:-1]) < 60
    assert entry("dybw:login", runner=lambda *c: list(c)) is None, "root's own keyring stays empty"
    take("dybw:login")
    assert entry("dybw:login") is None, "search permission is enough to invalidate it"


def test_a_second_login_replaces_the_entry():
    for password in (secrets.token_urlsafe(12), secrets.token_urlsafe(12)):
        set_password(password)
        assert pamtester("bwss-test", "authenticate", "open_session", stdin=password + "\n").returncode == 0
    assert entry("dybw:login")["payload"] == password.encode()


def test_a_login_without_a_password_leaves_nothing():
    assert pamtester("bwss-test-nopw", "authenticate", "open_session").returncode == 0
    assert entry("dybw:login") is None


def test_a_session_open_without_authentication_leaves_nothing():
    assert pamtester("bwss-test-nopw", "open_session").returncode == 0
    assert entry("dybw:login") is None


def test_closing_a_session_asks_to_lock_without_a_secret():
    assert pamtester("bwss-test-nopw", "open_session", "close_session").returncode == 0
    time.sleep(1.5)
    lock = entry("dybw:lock")
    assert lock is not None and lock["payload"] == b"-" and lock["perm"] == "0b0b0000"
    assert lock["timeout"].endswith("s") and 50 < int(lock["timeout"][:-1]) < 60


def test_setcred_and_an_unknown_user_change_nothing():
    result = pamtester("bwss-test-nopw", "authenticate", "setcred", "open_session", "close_session", user="nosuchuser")
    assert result.returncode == 0, result.stderr


def test_a_module_run_by_another_user_never_writes_for_root():
    # pamtester runs as pamtest for the user root: the child cannot become root.
    result = pamtester("bwss-test-nopw", "close_session", user="root", runner=lambda c: as_user(*c))
    assert result.returncode == 0, result.stderr
    assert entry("dybw:lock", runner=lambda *c: list(c)) is None


def test_a_password_change_gives_the_old_and_the_new_token():
    old, new = secrets.token_urlsafe(12), secrets.token_urlsafe(12)
    set_password(old)
    # As the user, pam_unix asks for the old password, then the new one twice.
    pamtester("bwss-test", "chauthtok", runner=lambda c: as_user(*c), stdin=f"{old}\n{new}\n{new}\n")
    assert entry("dybw:login-old")["payload"] == old.encode()
    assert entry("dybw:login")["payload"] == new.encode()


def test_a_reset_by_root_gives_the_new_token_only():
    new = secrets.token_urlsafe(12)
    set_password("before")
    result = pamtester("bwss-test", "chauthtok", stdin=f"{new}\n{new}\n")
    assert result.returncode == 0, result.stderr
    assert entry("dybw:login-old") is None
    assert entry("dybw:login")["payload"] == new.encode()


def test_no_token_reaches_a_file_or_the_output(tmp_path):
    password = secrets.token_urlsafe(12)
    set_password(password)
    marker = tmp_path / "marker"
    marker.write_text("")
    time.sleep(1.1)
    result = pamtester("bwss-test", "authenticate", "open_session", "close_session", stdin=password + "\n")
    assert result.returncode == 0, result.stderr
    assert password.encode() not in result.stdout + result.stderr
    changed = run(["find", "/", "-xdev", "-type", "f", "-newer", str(marker)]).stdout.decode().split()
    leaks = [f for f in changed if password.encode() in Path(f).read_bytes()]
    assert leaks == []
