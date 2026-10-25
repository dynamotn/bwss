#!/usr/bin/env python3
"""A stand-in for systemd-logind on a private bus.

    fake_logind.py ADDRESS SESSION_PATH [unknown-pid] [no-user] [replaceable | replace]

Owns org.freedesktop.login1 on ADDRESS and answers Manager.GetSessionByPID and
Manager.GetSession with SESSION_PATH. With "unknown-pid", GetSessionByPID
fails instead, as for a process that belongs to no session; GetSession still
answers. Both SESSION_PATH and a second session, OTHER_SESSION, answer
Properties.Get("User") with a (uid, user path) struct: SESSION_PATH for the
uid this script runs as, OTHER_SESSION for the next one. Prints "ready" once
it owns the name. With "no-user", Properties.Get fails instead, as for a
session that is gone. With "replaceable", another client may take the name
over; with "replace", it takes the name over from such a one, as a restarted
logind would. Then reads commands from stdin, one per line:

    sleep   emit Manager.PrepareForSleep(true)
    resume  emit Manager.PrepareForSleep(false)
    lock    emit Session.Lock on SESSION_PATH
    unlock  emit Session.Unlock on SESSION_PATH
    lock-other  emit Session.Lock on OTHER_SESSION
    lock-direct  send Session.Lock on SESSION_PATH to every other connection,
                 as unicast signals, which the bus delivers whoever owns the name
"""

import os
import select
import sys

from jeepney import DBusAddress, MessageType, new_error, new_method_call, new_method_return, new_signal
from jeepney.bus_messages import DBus, message_bus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

NAME = "org.freedesktop.login1"
MANAGER = DBusAddress("/org/freedesktop/login1", bus_name=NAME, interface="org.freedesktop.login1.Manager")

address, session_path = sys.argv[1], sys.argv[2]
unknown_pid = "unknown-pid" in sys.argv[3:]
no_user = "no-user" in sys.argv[3:]
# DO_NOT_QUEUE, plus ALLOW_REPLACEMENT or REPLACE_EXISTING.
FLAGS = 4 | (1 if "replaceable" in sys.argv[3:] else 0) | (2 if "replace" in sys.argv[3:] else 0)
OTHER_SESSION = "/org/freedesktop/login1/session/_99"
USERS = {session_path: os.getuid(), OTHER_SESSION: os.getuid() + 1}
session = DBusAddress(session_path, bus_name=NAME, interface="org.freedesktop.login1.Session")
SIGNALS = {
    "sleep": lambda: new_signal(MANAGER, "PrepareForSleep", "b", (True,)),
    "resume": lambda: new_signal(MANAGER, "PrepareForSleep", "b", (False,)),
    "lock": lambda: new_signal(session, "Lock"),
    "unlock": lambda: new_signal(session, "Unlock"),
    "lock-other": lambda: new_signal(DBusAddress(OTHER_SESSION, bus_name=NAME, interface=session.interface), "Lock"),
}


def lock_direct():
    names = conn.send_and_get_reply(new_method_call(DBus(), "ListNames")).body[0]
    for name in names:
        if name.startswith(":") and name != conn.unique_name:
            signal = new_signal(session, "Lock")
            signal.header.fields[HeaderFields.destination] = name
            conn.send(signal)


conn = open_dbus_connection(bus=address)
if conn.send_and_get_reply(message_bus.RequestName(NAME, FLAGS)).body[0] != 1:
    sys.exit("cannot own " + NAME)
print("ready", flush=True)
while True:
    if select.select([0], [], [], 0)[0]:
        chunk = os.read(0, 4096)  # unbuffered, so select sees what is left
        if not chunk:
            break
        for command in chunk.decode().split():
            if command == "lock-direct":
                lock_direct()
            else:
                conn.send(SIGNALS[command]())
    try:
        msg = conn.receive(timeout=0.1)
    except TimeoutError:
        continue
    if msg.header.message_type == MessageType.method_call:
        member = msg.header.fields.get(HeaderFields.member)
        if member == "GetSessionByPID" and unknown_pid:
            conn.send(new_error(msg, "org.freedesktop.login1.NoSessionForPID", "s", ("no session for the pid",)))
        elif member == "Get" and no_user:
            conn.send(new_error(msg, "org.freedesktop.DBus.Error.UnknownObject", "s", ("no such session",)))
        elif member == "Get" and msg.header.fields.get(HeaderFields.path) in USERS:
            uid = USERS[msg.header.fields[HeaderFields.path]]
            conn.send(new_method_return(msg, "v", ((("(uo)"), (uid, "/org/freedesktop/login1/user/_%d" % uid)),)))
        elif member in ("GetSessionByPID", "GetSession"):
            conn.send(new_method_return(msg, "o", (session_path,)))
