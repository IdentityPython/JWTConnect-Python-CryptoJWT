import json
from typing import List

from cryptojwt.jwk.x509 import import_private_key_from_pem_data
from cryptojwt.jwk.x509 import import_public_key_from_pem_data

from ..exception import UnknownKeyType
from . import JWK
from .ec import ECKey
from .hmac import SYMKey
from .jwk import key_from_jwk_dict
from .rsa import RSAKey
from .utils import harmonize_usage

K2C = {"RSA": RSAKey, "EC": ECKey, "oct": SYMKey}


def jwks_deserializer(data) -> List[JWK]:
    """Convert JWKS dictionary (as str or bytes) to JWK objects"""
    keys = json.loads(data.decode() if isinstance(data, bytes) else data)
    if isinstance(keys, dict) and "keys" in keys:
        return [key_from_jwk_dict(k) for k in keys["keys"]]
    elif isinstance(keys, list):
        return [key_from_jwk_dict(k) for k in keys]
    raise ValueError("Unknown JWKS format")


def der_private_deserializer(data, keytype, keyusage=None, kid=None) -> List[JWK]:
    """Convert PEM-encoded DER (as str or bytes) to JWK objects"""
    key_dict = {}
    _kty = keytype.lower()
    if _kty in ["rsa", "ec"]:
        key_dict["kty"] = _kty
        _key = import_private_key_from_pem_data(data if isinstance(data, bytes) else data.encode())
        key_dict["priv_key"] = _key
        key_dict["pub_key"] = _key.public_key()
    else:
        raise NotImplementedError("No support for DER decoding of key type {}".format(_kty))
    if not keyusage:
        key_dict["use"] = ["enc", "sig"]
    else:
        key_dict["use"] = harmonize_usage(keyusage)
    if kid:
        key_dict["kid"] = kid
    return jwk_dict_as_keys(key_dict)


def jwk_dict_as_keys(jwk_dict) -> List[JWK]:
    """
    Return JWK dictionary as JWK objects

    :param keys: JWK dictionary
    :return: list of JWK objects
    """

    res = []
    kty = jwk_dict["kty"]

    if kty.lower() in K2C:
        jwk_dict["kty"] = kty.lower()
    elif kty.upper() in K2C:
        jwk_dict["kty"] = kty.upper()
    else:
        raise UnknownKeyType(jwk_dict)

    try:
        usage = harmonize_usage(jwk_dict["use"])
    except KeyError:
        usage = [""]
    else:
        del jwk_dict["use"]

    kty = jwk_dict["kty"]
    for use in usage:
        try:
            key = K2C[kty](use=use, **jwk_dict)
        except KeyError:
            raise UnknownKeyType(jwk_dict)
        if not key.kid:
            key.add_kid()
        res.append(key)

    return res
