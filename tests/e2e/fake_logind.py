#!/usr/bin/env python3
"""A stand-in for systemd-logind on a private bus.

    fake_logind.py ADDRESS SESSION_PATH

Owns org.freedesktop.login1 on ADDRESS and answers Manager.GetSessionByPID and
Manager.GetSession with SESSION_PATH. Prints "ready" once it owns the name;
then reads commands from stdin, one per line:

    sleep   emit Manager.PrepareForSleep(true)
    resume  emit Manager.PrepareForSleep(false)
    lock    emit Session.Lock on SESSION_PATH
    unlock  emit Session.Unlock on SESSION_PATH
"""

import os
import select
import sys

from jeepney import DBusAddress, MessageType, new_method_return, new_signal
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

NAME = "org.freedesktop.login1"
MANAGER = DBusAddress("/org/freedesktop/login1", bus_name=NAME, interface="org.freedesktop.login1.Manager")

address, session_path = sys.argv[1], sys.argv[2]
session = DBusAddress(session_path, bus_name=NAME, interface="org.freedesktop.login1.Session")
SIGNALS = {
    "sleep": lambda: new_signal(MANAGER, "PrepareForSleep", "b", (True,)),
    "resume": lambda: new_signal(MANAGER, "PrepareForSleep", "b", (False,)),
    "lock": lambda: new_signal(session, "Lock"),
    "unlock": lambda: new_signal(session, "Unlock"),
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
        if msg.header.fields.get(HeaderFields.member) in ("GetSessionByPID", "GetSession"):
            conn.send(new_method_return(msg, "o", (session_path,)))
