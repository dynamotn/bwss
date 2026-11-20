"""pam_bwss end to end: pamtester drives real PAM stacks that load the module.

Runs as root in the bwss-e2e image only, started with
`--security-opt seccomp=unconfined` (Docker's default profile blocks the
keyring syscalls) and `--security-opt systempaths=unconfined` (it masks
/proc/keys, the only place that shows a key's expiry). It adds two users and
writes /etc/pam.d/bwss-test-*, so it refuses to run unless PAM_BWSS_SO names
the built module (see README).
"""

import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import pytest

SO = os.environ.get("PAM_BWSS_SO", "")
USER, UID = "pamtest", 4242
OTHER, OTHER_UID = "pamother", 4243
HARNESS = str(Path(__file__).parent / "pam_harness.py")

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


def as_user(*cmd, uid=UID):
    return ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups", *cmd]


def as_other(*cmd):
    return as_user(*cmd, uid=OTHER_UID)


def as_root(*cmd):
    return list(cmd)


def harness(*ops, password="", service="bwss-test"):
    return run([sys.executable, HARNESS, service, USER, password, *ops])


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


def take(description, runner=as_user):
    """What a consumer does once it has read the entry."""
    found = run(runner("keyctl", "search", "@u", "user", description))
    if not found.returncode:
        assert not run(runner("keyctl", "invalidate", found.stdout.decode().strip())).returncode


def set_password(password):
    subprocess.run(["chpasswd"], input=f"{USER}:{password}".encode(), check=True)


@pytest.fixture(scope="module", autouse=True)
def stacks():
    for name, uid in ((USER, UID), (OTHER, OTHER_UID)):
        if run(["id", name]).returncode:
            subprocess.run(["useradd", "--uid", str(uid), "--user-group", "--no-create-home", name], check=True)
    # `passwd` (setuid root) is how a user changes their password; it reads /etc/pam.d/passwd.
    stacks = {"bwss-test": WITH_PASSWORD, "bwss-test-nopw": WITHOUT_PASSWORD, "passwd": WITH_PASSWORD}
    for name, text in stacks.items():
        Path(f"/etc/pam.d/{name}").write_text(text.format(so=SO))


@pytest.fixture(autouse=True)
def clean_keyring():
    for description in ("dybw:login", "dybw:login-old", "dybw:lock"):
        for runner in (as_user, as_other):
            take(description, runner)
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
    assert entry("dybw:login", runner=as_root) is None, "root's own keyring stays empty"
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
    assert entry("dybw:lock", runner=as_root) is None


def test_a_password_change_gives_the_old_and_the_new_token():
    old, new = secrets.token_urlsafe(12), secrets.token_urlsafe(12)
    set_password(old)
    # passwd run by the user: pam_unix asks for the old password, then the new one twice.
    result = run(as_user("passwd"), stdin=f"{old}\n{new}\n{new}\n")
    assert result.returncode == 0, result.stderr
    assert entry("dybw:login-old")["payload"] == old.encode()
    assert entry("dybw:login")["payload"] == new.encode()


def test_a_change_that_pam_unix_fails_to_write_is_still_handed_over():
    # The README's warning: pamtester run by the user cannot write /etc/shadow, yet
    # the update phase ran, so the consumer must keep its old wrap until a login verifies.
    old, new = secrets.token_urlsafe(12), secrets.token_urlsafe(12)
    set_password(old)
    result = pamtester("bwss-test", "chauthtok", runner=lambda c: as_user(*c), stdin=f"{old}\n{new}\n{new}\n")
    assert result.returncode != 0
    assert entry("dybw:login")["payload"] == new.encode()


def test_a_password_change_refused_at_the_preliminary_check_gives_nothing():
    set_password("right")
    # A wrong old password fails pam_unix's PAM_PRELIM_CHECK: the update phase never runs.
    result = pamtester("bwss-test", "chauthtok", runner=lambda c: as_user(*c), stdin="wrong\nnew-one\nnew-one\n")
    assert result.returncode != 0
    assert entry("dybw:login-old") is None and entry("dybw:login") is None


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


def test_the_harness_hands_over_a_login_like_pamtester():
    password = secrets.token_urlsafe(12)
    set_password(password)
    result = harness("authenticate", "open_session", password=password)
    assert result.returncode == 0, result.stdout
    assert entry("dybw:login")["payload"] == password.encode()


def test_a_token_never_goes_to_a_user_set_after_authentication():
    # sudo -u, su: auth runs for one user, PAM_USER is then changed to another.
    password = secrets.token_urlsafe(12)
    set_password(password)
    result = harness("authenticate", f"user={OTHER}", "open_session", "setcred=refresh", password=password)
    assert result.returncode == 0, result.stdout
    assert entry("dybw:login", runner=as_other) is None, "the other user never gets it"
    assert entry("dybw:login") is None, "and the copy is dropped, not kept for later"


@pytest.mark.parametrize("flag", ["refresh", "reinitialize"])
def test_a_screen_locker_refresh_hands_the_token_over(flag):
    password = secrets.token_urlsafe(12)
    set_password(password)
    result = harness("authenticate", f"setcred={flag}", password=password)
    assert result.returncode == 0, result.stdout
    time.sleep(1.5)
    key = entry("dybw:login")
    assert key["payload"] == password.encode() and key["perm"] == "0b0b0000" and key["uid"] == UID
    assert key["timeout"].endswith("s") and 50 < int(key["timeout"][:-1]) < 60


@pytest.mark.parametrize("flag", ["establish", "delete"])
def test_a_login_setcred_leaves_the_token_to_session_open(flag):
    password = secrets.token_urlsafe(12)
    set_password(password)
    assert harness("authenticate", f"setcred={flag}", password=password).returncode == 0
    assert entry("dybw:login") is None
    assert harness("authenticate", f"setcred={flag}", "open_session", password=password).returncode == 0
    assert entry("dybw:login")["payload"] == password.encode()
