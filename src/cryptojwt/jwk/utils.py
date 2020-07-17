import hashlib

from ..utils import as_bytes


def sha256_digest(msg):
    """
    Produce a SHA256 digest of a message

    :param msg: The message
    :return: A SHA256 digest
    """
    return hashlib.sha256(as_bytes(msg)).digest()


def sha384_digest(msg):
    """
    Produce a SHA384 digest of a message

    :param msg: The message
    :return: A SHA384 digest
    """
    return hashlib.sha384(as_bytes(msg)).digest()


def sha512_digest(msg):
    """
    Produce a SHA512 digest of a message

    :param msg: The message
    :return: A SHA512 digest
    """
    return hashlib.sha512(as_bytes(msg)).digest()


DIGEST_HASH = {
    "SHA-256": sha256_digest,
    "SHA-384": sha384_digest,
    "SHA-512": sha512_digest,
}
