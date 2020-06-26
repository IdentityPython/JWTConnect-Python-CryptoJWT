import os
import struct
from math import ceil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.hashes import SHA512

from ..utils import b64e

LENMET = {32: (16, SHA256), 48: (24, SHA384), 64: (32, SHA512)}


def get_keys_seclen_dgst(key, iv):
    # Validate input
    if len(iv) != 16:
        raise Exception("IV for AES-CBC must be 16 octets long")

    # Select the digest to use based on key length
    try:
        seclen, hash_method = LENMET[len(key)]
    except KeyError:
        raise Exception("Invalid CBC+HMAC key length: %s bytes" % len(key))

    # Split the key
    ka = key[:seclen]
    ke = key[seclen:]

    return ka, ke, seclen, hash_method


# def int2big_endian(n):
#     return [ord(c) for c in struct.pack('>I', n)]


# def party_value(pv):
#     if pv:
#         s = b64e(pv)
#         r = int2big_endian(len(s))
#         r.extend(s)
#         return r
#     else:
#         return [0, 0, 0, 0]


# def _hash_input(cmk, enc, label, rond=1, length=128, hashsize=256,
#                 epu="", epv=""):
#     r = [0, 0, 0, rond]
#     r.extend(cmk)
#     r.extend([0, 0, 0, length])
#     r.extend([ord(c) for c in enc])
#     r.extend(party_value(epu))
#     r.extend(party_value(epv))
#     r.extend(label)
#     return r
#
#
# def keysize(spec):
#     if spec.startswith("HS"):
#         return int(spec[2:])
#     elif spec.startswith("CS"):
#         return int(spec[2:])
#     elif spec.startswith("A"):
#         return int(spec[1:4])
#     return 0


def alg2keytype(alg):
    if alg.startswith("RSA"):
        return "RSA"
    elif alg.startswith("A"):
        return "oct"
    elif alg.startswith("ECDH"):
        return "EC"
    else:
        return None


def split_ctx_and_tag(ctext):
    tag_length = 16
    tag = ctext[-tag_length:]
    ciphertext = ctext[:-tag_length]
    return ciphertext, tag


def get_random_bytes(len):
    return os.urandom(len)


def concat_sha256(secret, dk_len, other_info):
    """
    The Concat KDF, using SHA256 as the hash function.

    Note: Does not validate that otherInfo meets the requirements of
    SP800-56A.

    :param secret: The shared secret value
    :param dk_len: Length of key to be derived, in bits
    :param other_info: Other info to be incorporated (see SP800-56A)
    :return: The derived key
    """
    dkm = b""
    dk_bytes = int(ceil(dk_len / 8.0))
    counter = 0
    while len(dkm) < dk_bytes:
        counter += 1
        counter_bytes = struct.pack("!I", counter)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(counter_bytes)
        digest.update(secret)
        digest.update(other_info)
        dkm += digest.finalize()
    return dkm[:dk_bytes]
