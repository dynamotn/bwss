# Independent reference implementation of Bitwarden key derivation and
# EncString encryption, used to produce known-answer vectors for the TS code.
import base64, hashlib, hmac, json, os
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from argon2.low_level import hash_secret_raw, Type

b64 = lambda b: base64.b64encode(b).decode()

def stretch(mk):
    enc = HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mk)
    mac = HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mk)
    return enc + mac

def enc_string(plain, key, iv):
    p = padding.PKCS7(128).padder(); data = p.update(plain) + p.finalize()
    e = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(data) + e.finalize()
    mac = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"

email, password = " User@Example.COM ", "correct horse battery staple ✓"
salt = email.strip().lower().encode()
out = {"email": email, "password": password}

mk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, 32)
out["pbkdf2"] = {"iterations": 600000, "masterKey": b64(mk), "stretched": b64(stretch(mk)),
                 "masterPasswordHash": b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1, 32))}

amk = hash_secret_raw(password.encode(), hashlib.sha256(salt).digest(), time_cost=3,
                      memory_cost=64 * 1024, parallelism=4, hash_len=32, type=Type.ID)
out["argon2id"] = {"iterations": 3, "memory": 64, "parallelism": 4, "masterKey": b64(amk), "stretched": b64(stretch(amk))}

user_key = bytes(range(64))
iv = bytes(range(100, 116))
out["userKey"] = b64(user_key)
out["protectedUserKey"] = enc_string(user_key, stretch(mk), iv)
out["encStrings"] = [{"plain": t, "enc": enc_string(t.encode(), user_key, iv)}
                     for t in ["", "a", "sixteen bytes!!!", "Tiếng Việt có dấu 🔐", "x" * 1000]]
print(json.dumps(out, indent=2, ensure_ascii=False))
