"""Drives one PAM handle through libpam with ctypes, for what pamtester cannot do.

Usage: pam_harness.py SERVICE USER PASSWORD OP...
OP: authenticate | open_session | close_session | setcred=establish|refresh|reinitialize|delete | user=NAME
Prints each operation's return code; exits 1 when one is not PAM_SUCCESS.
"""

import ctypes
import sys
from ctypes import CFUNCTYPE, POINTER, Structure, c_char_p, c_int, c_size_t, c_void_p

libpam = ctypes.CDLL("libpam.so.0")
libc = ctypes.CDLL("libc.so.6")
libc.calloc.restype = c_void_p
libc.calloc.argtypes = [c_size_t, c_size_t]
libc.strdup.restype = c_void_p
libc.strdup.argtypes = [c_char_p]

PAM_USER = 2
CRED = {"establish": 0x2, "delete": 0x4, "reinitialize": 0x8, "refresh": 0x10}


class Message(Structure):
    _fields_ = [("msg_style", c_int), ("msg", c_char_p)]


class Response(Structure):
    _fields_ = [("resp", c_void_p), ("resp_retcode", c_int)]


CONV = CFUNCTYPE(c_int, c_int, POINTER(POINTER(Message)), POINTER(POINTER(Response)), c_void_p)


class Conv(Structure):
    _fields_ = [("conv", CONV), ("appdata_ptr", c_void_p)]


def main(service, user, password, *ops):
    def answer(n, messages, responses, _):
        # libpam frees the answers, so they come from malloc.
        out = ctypes.cast(libc.calloc(n, ctypes.sizeof(Response)), POINTER(Response))
        for i in range(n):
            if messages[i].contents.msg_style in (1, 2):  # PAM_PROMPT_ECHO_OFF, _ON
                out[i].resp = libc.strdup(password.encode())
        responses[0] = out
        return 0

    conv = Conv(CONV(answer), None)
    handle = c_void_p()
    assert libpam.pam_start(service.encode(), user.encode(), ctypes.byref(conv), ctypes.byref(handle)) == 0
    failed = False
    for op in ops:
        name, _, arg = op.partition("=")
        if name == "user":
            rc = libpam.pam_set_item(handle, PAM_USER, c_char_p(arg.encode()))
        elif name == "setcred":
            rc = libpam.pam_setcred(handle, CRED[arg])
        else:
            rc = getattr(libpam, f"pam_{name}")(handle, 0)
        print(op, rc)
        failed |= rc != 0
    libpam.pam_end(handle, 0)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
