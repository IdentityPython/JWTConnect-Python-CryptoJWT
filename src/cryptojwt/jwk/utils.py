import hashlib

from ..utils import as_bytes


def sha256_digest(msg):
    return hashlib.sha256(as_bytes(msg)).digest()


def sha384_digest(msg):
    return hashlib.sha384(as_bytes(msg)).digest()


def sha512_digest(msg):
    return hashlib.sha512(as_bytes(msg)).digest()


DIGEST_HASH = {
    'SHA-256': sha256_digest,
    'SHA-384': sha384_digest,
    'SHA-512': sha512_digest
}
