#!/usr/bin/env python3
"""A stand-in for systemd-logind on a private bus.

    fake_logind.py ADDRESS SESSION_PATH [unknown-pid] [no-user]

Owns org.freedesktop.login1 on ADDRESS and answers Manager.GetSessionByPID and
Manager.GetSession with SESSION_PATH. With "unknown-pid", GetSessionByPID
fails instead, as for a process that belongs to no session; GetSession still
answers. Both SESSION_PATH and a second session, OTHER_SESSION, answer
Properties.Get("User") with a (uid, user path) struct: SESSION_PATH for the
uid this script runs as, OTHER_SESSION for the next one. Prints "ready" once
it owns the name. With "no-user", Properties.Get fails instead, as for a
session that is gone. Then reads commands from stdin, one per line:

    sleep   emit Manager.PrepareForSleep(true)
    resume  emit Manager.PrepareForSleep(false)
    lock    emit Session.Lock on SESSION_PATH
    unlock  emit Session.Unlock on SESSION_PATH
    lock-other  emit Session.Lock on OTHER_SESSION
"""

import os
import select
import sys

from jeepney import DBusAddress, MessageType, new_error, new_method_return, new_signal
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

NAME = "org.freedesktop.login1"
MANAGER = DBusAddress("/org/freedesktop/login1", bus_name=NAME, interface="org.freedesktop.login1.Manager")

address, session_path = sys.argv[1], sys.argv[2]
unknown_pid = "unknown-pid" in sys.argv[3:]
no_user = "no-user" in sys.argv[3:]
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

conn = open_dbus_connection(bus=address)
if conn.send_and_get_reply(message_bus.RequestName(NAME, 4)).body[0] != 1:
    sys.exit("cannot own " + NAME)
print("ready", flush=True)
while True:
    if select.select([0], [], [], 0)[0]:
        chunk = os.read(0, 4096)  # unbuffered, so select sees what is left
        if not chunk:
            break
        for command in chunk.decode().split():
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
