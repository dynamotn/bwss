#!/usr/bin/env python3
"""Requests a bus name and logs every method call sent to it.

    squatter.py NAME FLAGS LOG

Prints the RequestName reply code (1 = primary owner). As the owner it
stays on the bus, appends "<member> <body>" for each method call to LOG and
answers with an error; otherwise it exits.
"""

import sys

from jeepney import MessageType, new_error
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

name, flags, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
conn = open_dbus_connection(bus="SESSION")
code = conn.send_and_get_reply(message_bus.RequestName(name, flags)).body[0]
print(code, flush=True)
if code != 1:
    sys.exit(0)
while True:
    msg = conn.receive()
    if msg.header.message_type != MessageType.method_call:
        continue
    with open(log_path, "a") as f:
        f.write(f"{msg.header.fields.get(HeaderFields.member)} {msg.body!r}\n")
    conn.send(new_error(msg, "org.freedesktop.DBus.Error.Failed", "s", ("squatter",)))
