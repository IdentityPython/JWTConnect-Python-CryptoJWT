import copy

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

from ..exception import WrongKeyType
from ..exception import UnknownKeyType
from ..exception import UnsupportedAlgorithm
from ..utils import base64url_to_long, b64d, as_bytes

from .ec import ECKey
from .rsa import RSAKey
from .hmac import SYMKey


def key_from_jwk_dict(jwk_dict):
    """Load JWK from dictionary

    :param jwk_dict: Dictionary representing a JWK
    """

    # uncouple from the original item
    _jwk_dict = copy.copy(jwk_dict)

    if _jwk_dict['kty'] == 'EC':
        if _jwk_dict["crv"] == "P-256":
            curve = ec.SECP256R1()
        elif _jwk_dict["crv"] == "P-384":
            curve = ec.SECP384R1()
        elif _jwk_dict["crv"] == "P-521":
            curve = ec.SECP521R1()
        else:
            raise UnsupportedAlgorithm(
                "Unknown curve: %s" % (_jwk_dict["crv"]))
        if _jwk_dict.get("d", None) is not None:
            # Ecdsa private key.
            _jwk_dict['priv_key'] = ec.derive_private_key(
                base64url_to_long(_jwk_dict["d"]), curve,
                backends.default_backend())
            _jwk_dict['pub_key'] = _jwk_dict['priv_key'].public_key()
        else:
            # Ecdsa public key.
            ec_pub_numbers = ec.EllipticCurvePublicNumbers(
                base64url_to_long(_jwk_dict["x"]),
                base64url_to_long(_jwk_dict["y"]), curve)
            _jwk_dict['pub_key'] = ec_pub_numbers.public_key(
                backends.default_backend())
        return ECKey(**_jwk_dict)
    elif _jwk_dict['kty'] == 'RSA':
        rsa_pub_numbers = rsa.RSAPublicNumbers(
            base64url_to_long(_jwk_dict["e"]),
            base64url_to_long(_jwk_dict["n"]))
        if _jwk_dict.get("p", None) is not None:
            # Rsa private key.
            rsa_priv_numbers = rsa.RSAPrivateNumbers(
                base64url_to_long(_jwk_dict["p"]),
                base64url_to_long(_jwk_dict["q"]),
                base64url_to_long(_jwk_dict["d"]),
                base64url_to_long(_jwk_dict["dp"]),
                base64url_to_long(_jwk_dict["dq"]),
                base64url_to_long(_jwk_dict["qi"]), rsa_pub_numbers)
            _jwk_dict['priv_key'] = rsa_priv_numbers.private_key(
                backends.default_backend())
            _jwk_dict['pub_key'] = _jwk_dict['priv_key'].public_key()
        else:
            _jwk_dict['pub_key'] = rsa_pub_numbers.public_key(
                backends.default_backend())
            
        if _jwk_dict['kty'] != "RSA":
            raise WrongKeyType('"{}" should have been "RSA"'.format(_jwk_dict[
                                                                        'kty']))
        return RSAKey(**_jwk_dict)
    elif _jwk_dict['kty'] == 'oct':
        if isinstance(_jwk_dict['k'], bytes):
            _jwk_dict['key'] = b64d(_jwk_dict["k"])
        else:
            _jwk_dict['key'] = b64d(as_bytes(_jwk_dict["k"]))
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

    kspec.serialize()
    return kspec

