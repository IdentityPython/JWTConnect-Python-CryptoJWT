# import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..exception import UnsupportedAlgorithm
from ..jwk.hmac import sha256_digest
from ..jwk.hmac import sha384_digest
from ..jwk.hmac import sha512_digest
from ..utils import as_unicode
from ..utils import b64e


def left_hash(msg, func="HS256"):
    """Calculate left hash as described in
    https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
    for at_hash and in
    for c_hash

    :param msg: The message over which the hash should be calculated
    :param func: Which hash function that was used for the ID token
    """
    if func == "HS256":
        return as_unicode(b64e(sha256_digest(msg)[:16]))
    elif func == "HS384":
        return as_unicode(b64e(sha384_digest(msg)[:24]))
    elif func == "HS512":
        return as_unicode(b64e(sha512_digest(msg)[:32]))


# def mpint(b):
#     b += b"\x00"
#     return struct.pack(">L", len(b)) + b
#


def alg2keytype(alg):
    """
    Go from algorithm name to key type.

    :param alg: The algorithm name
    :return: The key type
    """
    if not alg or alg.lower() == "none":
        return "none"
    elif alg.startswith("RS") or alg.startswith("PS"):
        return "RSA"
    elif alg.startswith("HS") or alg.startswith("A"):
        return "oct"
    elif alg.startswith("ES") or alg.startswith("ECDH-ES"):
        return "EC"
    else:
        return None


def parse_rsa_algorithm(algorithm):
    """
    Parses a RSA algorithm and returns tuple (hash, padding).

    :param algorithm: string, RSA algorithm as defined at
        https://tools.ietf.org/html/rfc7518#section-3.1.
    :raises: UnsupportedAlgorithm: if the algorithm is not supported.
    :returns: (hash, padding) tuple.
    """

    if algorithm == "RS256":
        return hashes.SHA256(), padding.PKCS1v15()
    elif algorithm == "RS384":
        return hashes.SHA384(), padding.PKCS1v15()
    elif algorithm == "RS512":
        return hashes.SHA512(), padding.PKCS1v15()
    elif algorithm == "PS256":
        return (
            hashes.SHA256(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        )
    elif algorithm == "PS384":
        return (
            hashes.SHA384(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH),
        )
    elif algorithm == "PS512":
        return (
            hashes.SHA512(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=padding.PSS.MAX_LENGTH),
        )
    else:
        raise UnsupportedAlgorithm("Unknown algorithm: {}".format(algorithm))
