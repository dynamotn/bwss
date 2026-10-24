"""Process hardening at daemon start (TM-013), Linux only."""

from pathlib import Path


def limits(pid):
    rows = {}
    for line in Path(f"/proc/{pid}/limits").read_text().splitlines()[1:]:
        name, _, rest = line.partition("  ")
        rows[name.strip()] = rest.split()
    return rows


def test_the_daemon_writes_no_core_dump(memory_daemon):
    soft, hard = limits(memory_daemon.proc.pid)["Max core file size"][:2]
    assert (soft, hard) == ("0", "0")


def test_the_daemon_is_not_dumpable(memory_daemon):
    # A process that is not dumpable owns its /proc entries as root.
    assert Path(f"/proc/{memory_daemon.proc.pid}/environ").stat().st_uid == 0
