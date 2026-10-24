#!/usr/bin/env python3
"""Requests a bus name and logs every method call sent to it.

    squatter.py NAME FLAGS LOG [EXEC...]

Prints the RequestName reply code (1 = primary owner). As the owner it
stays on the bus, appends "<member> <body>" for each method call to LOG and
answers with an error; otherwise it exits.

With SQUATTER_UNDUMPABLE set, it first makes itself not dumpable, so that
nobody can read its /proc/<pid>/exe (as with bwss itself).

With EXEC, it forks once it owns the name: the child keeps the bus
connection (and so the name) and answers nothing, while the parent, whose
pid is the one the bus reports for the name, execs EXEC (e.g. the real
`bwss unlock`). The child leaves when the parent is gone.
"""

import os
import sys

from jeepney import MessageType, new_error
from jeepney.bus_messages import message_bus
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields

if os.environ.get("SQUATTER_UNDUMPABLE"):
    import ctypes

    PR_SET_DUMPABLE = 4
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        sys.exit("cannot make the squatter not dumpable")

name, flags, log_path, exec_argv = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4:]
conn = open_dbus_connection(bus="SESSION")
code = conn.send_and_get_reply(message_bus.RequestName(name, flags)).body[0]
print(code, flush=True)
if code != 1:
    sys.exit(0)
parent = os.getpid()
if exec_argv and os.fork() != 0:
    # The bus socket is close-on-exec, so only the child holds the connection.
    os.execv(exec_argv[0], exec_argv)
while True:
    try:
        msg = conn.receive(timeout=0.5)
    except TimeoutError:
        if exec_argv and os.getppid() != parent:
            sys.exit(0)
        continue
    if msg.header.message_type != MessageType.method_call:
        continue
    with open(log_path, "a") as f:
        f.write(f"{msg.header.fields.get(HeaderFields.member)} {msg.body!r}\n")
    if not exec_argv:
        conn.send(new_error(msg, "org.freedesktop.DBus.Error.Failed", "s", ("squatter",)))
