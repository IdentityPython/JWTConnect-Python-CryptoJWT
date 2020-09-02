import copy
import json
import os

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_dmp1
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_dmq1
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_iqmp

from ..exception import MissingValue
from ..exception import UnknownKeyType
from ..exception import UnsupportedAlgorithm
from ..exception import WrongKeyType
from ..utils import base64url_to_long
from .ec import NIST2SEC
from .ec import ECKey
from .hmac import SYMKey
from .rsa import RSAKey

EC_PUBLIC_REQUIRED = frozenset(["crv", "x", "y"])
EC_PUBLIC = EC_PUBLIC_REQUIRED
EC_PRIVATE_REQUIRED = frozenset(["d"])
EC_PRIVATE_OPTIONAL = frozenset()
EC_PRIVATE = EC_PRIVATE_REQUIRED | EC_PRIVATE_OPTIONAL

RSA_PUBLIC_REQUIRED = frozenset(["e", "n"])
RSA_PUBLIC = RSA_PUBLIC_REQUIRED
RSA_PRIVATE_REQUIRED = frozenset(["p", "q", "d"])
RSA_PRIVATE_OPTIONAL = frozenset(["qi", "dp", "dq"])
RSA_PRIVATE = RSA_PRIVATE_REQUIRED | RSA_PRIVATE_OPTIONAL


def ensure_ec_params(jwk_dict, private):
    """Ensure all required EC parameters are present in dictionary"""
    provided = frozenset(jwk_dict.keys())
    if private is not None and private:
        required = EC_PUBLIC_REQUIRED | EC_PRIVATE_REQUIRED
    else:
        required = EC_PUBLIC_REQUIRED
    return ensure_params("EC", provided, required)


def ensure_rsa_params(jwk_dict, private):
    """Ensure all required RSA parameters are present in dictionary"""
    provided = frozenset(jwk_dict.keys())
    if private is not None and private:
        required = RSA_PUBLIC_REQUIRED | RSA_PRIVATE_REQUIRED
    else:
        required = RSA_PUBLIC_REQUIRED
    return ensure_params("RSA", provided, required)


def ensure_params(kty, provided, required):
    """Ensure all required parameters are present in dictionary"""
    if not required <= provided:
        missing = required - provided
        raise MissingValue("Missing properties for kty={}, {}".format(kty, str(list(missing))))


def key_from_jwk_dict(jwk_dict, private=None):
    """Load JWK from dictionary

    :param jwk_dict: Dictionary representing a JWK
    """

    # uncouple from the original item
    _jwk_dict = copy.deepcopy(jwk_dict)

    if "kty" not in _jwk_dict:
        raise MissingValue("kty missing")

    if _jwk_dict["kty"] == "EC":
        ensure_ec_params(_jwk_dict, private)

        if private is not None and not private:
            # remove private components
            for v in EC_PRIVATE:
                _jwk_dict.pop(v, None)

        if _jwk_dict["crv"] in NIST2SEC:
            curve = NIST2SEC[_jwk_dict["crv"]]()
        else:
            raise UnsupportedAlgorithm("Unknown curve: %s" % (_jwk_dict["crv"]))

        if _jwk_dict.get("d", None) is not None:
            # Ecdsa private key.
            _jwk_dict["priv_key"] = ec.derive_private_key(
                base64url_to_long(_jwk_dict["d"]), curve, backends.default_backend()
            )
            _jwk_dict["pub_key"] = _jwk_dict["priv_key"].public_key()
        else:
            # Ecdsa public key.
            ec_pub_numbers = ec.EllipticCurvePublicNumbers(
                base64url_to_long(_jwk_dict["x"]),
                base64url_to_long(_jwk_dict["y"]),
                curve,
            )
            _jwk_dict["pub_key"] = ec_pub_numbers.public_key(backends.default_backend())
        return ECKey(**_jwk_dict)
    elif _jwk_dict["kty"] == "RSA":
        ensure_rsa_params(_jwk_dict, private)

        if private is not None and not private:
            # remove private components
            for v in RSA_PRIVATE:
                _jwk_dict.pop(v, None)

        rsa_pub_numbers = rsa.RSAPublicNumbers(
            base64url_to_long(_jwk_dict["e"]), base64url_to_long(_jwk_dict["n"])
        )
        if _jwk_dict.get("p", None) is not None:
            # Rsa private key. These MUST be present
            p_long = base64url_to_long(_jwk_dict["p"])
            q_long = base64url_to_long(_jwk_dict["q"])
            d_long = base64url_to_long(_jwk_dict["d"])
            # If not present these can be calculated from the others
            if "dp" not in _jwk_dict:
                dp_long = rsa_crt_dmp1(d_long, p_long)
            else:
                dp_long = base64url_to_long(_jwk_dict["dp"])
            if "dq" not in _jwk_dict:
                dq_long = rsa_crt_dmq1(d_long, q_long)
            else:
                dq_long = base64url_to_long(_jwk_dict["dq"])
            if "qi" not in _jwk_dict:
                qi_long = rsa_crt_iqmp(p_long, q_long)
            else:
                qi_long = base64url_to_long(_jwk_dict["qi"])

            rsa_priv_numbers = rsa.RSAPrivateNumbers(
                p_long, q_long, d_long, dp_long, dq_long, qi_long, rsa_pub_numbers
            )
            _jwk_dict["priv_key"] = rsa_priv_numbers.private_key(backends.default_backend())
            _jwk_dict["pub_key"] = _jwk_dict["priv_key"].public_key()
        else:
            _jwk_dict["pub_key"] = rsa_pub_numbers.public_key(backends.default_backend())

        if _jwk_dict["kty"] != "RSA":
            raise WrongKeyType('"{}" should have been "RSA"'.format(_jwk_dict["kty"]))
        return RSAKey(**_jwk_dict)
    elif _jwk_dict["kty"] == "oct":
        if "key" not in _jwk_dict and "k" not in _jwk_dict:
            raise MissingValue('There has to be one of "k" or "key" in a symmetric key')

        return SYMKey(**_jwk_dict)
    else:
        raise UnknownKeyType


def jwk_wrap(key, use="", kid=""):
    """
    Instantiate a Key instance with the given key

    :param key: The keys to wrap
    :param use: What the key are expected to be use for
    :param kid: A key id
    :return: The Key instance
    """
    if isinstance(key, rsa.RSAPublicKey) or isinstance(key, rsa.RSAPrivateKey):
        kspec = RSAKey(use=use, kid=kid).load_key(key)
    elif isinstance(key, str):
        kspec = SYMKey(key=key, use=use, kid=kid)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        kspec = ECKey(use=use, kid=kid).load_key(key)
    else:
        raise Exception("Unknown key type:key=" + str(type(key)))

    if not kspec.kid:
        kspec.add_kid()

    kspec.serialize()
    return kspec


def dump_jwk(filename, key):
    """Writes a RSAKey, ECKey or SYMKey instance as a JWK to a file."""
    head, tail = os.path.split(filename)
    if head and not os.path.isdir(head):
        os.makedirs(head)

    with open(filename, "w") as fp:
        fp.write(json.dumps(key.to_dict()))


def import_jwk(filename):
    """Reads a JWK from a file and converts it into the appropriate key class instance."""
    if os.path.isfile(filename):
        with open(filename) as jwk_file:
            jwk_dict = json.loads(jwk_file.read())
            return key_from_jwk_dict(jwk_dict)
    return None
