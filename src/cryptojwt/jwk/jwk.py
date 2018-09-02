from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

from ..exception import WrongKeyType
from ..exception import UnknownKeyType
from ..exception import UnsupportedAlgorithm
from ..utils import base64url_to_long, b64d

from . import JWK

from .ec import ECKey
from .rsa import RSAKey
from .hmac import SYMKey


def key_from_jwk_dict(jwk_dict):
    """Load JWK from dictionary
    :param jwk_dict: Dictionary representing a JWK
    """
    if jwk_dict['kty'] == 'EC':
        if jwk_dict["crv"] == "P-256":
            curve = ec.SECP256R1()
        elif jwk_dict["crv"] == "P-384":
            curve = ec.SECP384R1()
        elif jwk_dict["crv"] == "P-521":
            curve = ec.SECP521R1()
        else:
            raise UnsupportedAlgorithm(
                "Unknown curve: %s" % (jwk_dict["crv"]))
        if jwk_dict.get("d", None) is not None:
            # Ecdsa private key.
            jwk_dict['priv_key'] = ec.derive_private_key(
                base64url_to_long(jwk_dict["d"]), curve,
                backends.default_backend())
            jwk_dict['pub_key'] = jwk_dict['priv_key'].public_key()
        else:
            # Ecdsa public key.
            ec_pub_numbers = ec.EllipticCurvePublicNumbers(
                base64url_to_long(jwk_dict["x"]),
                base64url_to_long(jwk_dict["y"]), curve)
            jwk_dict['pub_key'] = ec_pub_numbers.public_key(
                backends.default_backend())
        return ECKey(**jwk_dict)
    elif jwk_dict['kty'] == 'RSA':
        rsa_pub_numbers = rsa.RSAPublicNumbers(
            base64url_to_long(jwk_dict["e"]),
            base64url_to_long(jwk_dict["n"]))
        if jwk_dict.get("p", None) is not None:
            # Rsa private key.
            rsa_priv_numbers = rsa.RSAPrivateNumbers(
                base64url_to_long(jwk_dict["p"]),
                base64url_to_long(jwk_dict["q"]),
                base64url_to_long(jwk_dict["d"]),
                base64url_to_long(jwk_dict["dp"]),
                base64url_to_long(jwk_dict["dq"]),
                base64url_to_long(jwk_dict["qi"]), rsa_pub_numbers)
            jwk_dict['priv_key'] = rsa_priv_numbers.private_key(
                backends.default_backend())
            jwk_dict['pub_key'] = jwk_dict['priv_key'].public_key()
        else:
            jwk_dict['pub_key'] = rsa_pub_numbers.public_key(
                backends.default_backend())
            
        if jwk_dict['kty'] != "RSA":
            raise WrongKeyType('"{}" should have been "RSA"'.format(jwk_dict[
                                                                        'kty']))
        return RSAKey(**jwk_dict)
    elif jwk_dict['kty'] == 'oct':
        jwk_dict['key'] = b64d(jwk_dict["k"])
        return SYMKey(**jwk_dict)
    else:
        raise UnknownKeyType


def keyrep(kspec, enc="utf-8"):
    """
    Instantiate a Key given a set of key/word arguments

    :param kspec: Key specification, arguments to the Key initialization
    :param enc: The encoding of the strings. If it's JSON which is the default
     the encoding is utf-8.
    :return: Key instance
    """
    if enc:
        _kwargs = {}
        for key, val in kspec.items():
            if isinstance(val, str):
                _kwargs[key] = val.encode(enc)
            else:
                _kwargs[key] = val
    else:
        _kwargs = kspec

    if kspec["kty"] == "RSA":
        item = RSAKey(**_kwargs)
    elif kspec["kty"] == "oct":
        item = SYMKey(**_kwargs)
    elif kspec["kty"] == "EC":
        item = ECKey(**_kwargs)
    else:
        item = JWK(**_kwargs)
    return item


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

