"""JWK wrapping"""

import json

from .. import JWE
from . import JWK
from .jwk import key_from_jwk_dict

__author__ = "jschlyter"

DEFAULT_WRAP_PARAMS = {
    "EC": {"alg": "ECDH-ES+A128KW", "enc": "A128GCM"},
    "RSA": {"alg": "RSA1_5", "enc": "A128CBC-HS256"},
    "oct": {"alg": "A128KW", "enc": "A128CBC-HS256"},
}


def wrap_key(key: JWK, wrapping_key: JWK, wrap_params: dict = DEFAULT_WRAP_PARAMS) -> str:
    message = json.dumps(key.serialize(private=True)).encode()
    try:
        enc_params = wrap_params[wrapping_key.kty]
    except KeyError:
        raise ValueError("Unsupported wrapping key type")
    _jwe = JWE(msg=message, **enc_params)
    return _jwe.encrypt(keys=[wrapping_key], kid=wrapping_key.kid)


def unwrap_key(jwe: str, wrapping_keys: JWK) -> JWK:
    _jwe = JWE()
    message = _jwe.decrypt(token=jwe, keys=wrapping_keys)
    return key_from_jwk_dict(json.loads(message))
