#!/usr/bin/env python3
"""Scripted pinentry for the end-to-end tests.

Behaviour comes from the JSON file named by $FAKE_PINENTRY_CTL, re-read on
every run so tests can change it between prompts:

    {"pins": ["wrong", "right"], "confirm": "once" | "always" | "deny" | "cancel"}

"pins" is consumed one entry per GETPIN (the file is rewritten); an empty
list cancels. Every command received is appended to $FAKE_PINENTRY_LOG.
"""

import json
import os
import sys
import urllib.parse

ctl_path = os.environ["FAKE_PINENTRY_CTL"]
log_path = os.environ.get("FAKE_PINENTRY_LOG")


def load():
    with open(ctl_path) as f:
        return json.load(f)


def save(ctl):
    with open(ctl_path, "w") as f:
        json.dump(ctl, f)


def log(line):
    if log_path:
        with open(log_path, "a") as f:
            f.write(line + "\n")


def out(line):
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


out("OK fake pinentry")
for raw in sys.stdin:
    line = raw.rstrip("\n")
    cmd, _, arg = line.partition(" ")
    # One log line per command, even when the text has line breaks.
    log(f"{cmd} {urllib.parse.unquote(arg)}".rstrip().replace("\n", " "))
    if cmd == "GETPIN":
        ctl = load()
        pins = ctl.get("pins", [])
        if not pins:
            out("ERR 83886179 Operation cancelled")
            continue
        pin = pins.pop(0)
        save(ctl)
        out("D " + pin.replace("%", "%25").replace("\n", "%0A"))
        out("OK")
    elif cmd == "CONFIRM":
        answer = load().get("confirm", "deny")
        if answer == "once":
            out("OK")
        elif answer == "always":
            out("ERR 83886194 Not confirmed")
        else:
            out("ERR 83886179 Operation cancelled")
    elif cmd == "BYE":
        out("OK closing connection")
        break
    else:
        out("OK")
