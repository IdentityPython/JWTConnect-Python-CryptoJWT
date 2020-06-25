import os

from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwk.wrap import unwrap_key
from cryptojwt.jwk.wrap import wrap_key

__author__ = 'jschlyter'

WRAPPING_KEYS = [
    SYMKey(use="enc", key=os.urandom(32)),
    new_ec_key(crv="P-256"),
    new_ec_key(crv="P-384"),
    new_rsa_key(size=2048),
    new_rsa_key(size=4096),
]

SECRET_KEYS = [
    SYMKey(use="enc", key=os.urandom(32)),
    new_ec_key(crv="P-256"),
    new_rsa_key(size=2048),
]


def test_wrap_default():
    for wrapping_key in WRAPPING_KEYS:
        for key in SECRET_KEYS:
            wrapped_key = wrap_key(key, wrapping_key)
            unwrapped_key = unwrap_key(wrapped_key, [wrapping_key])
            assert key == unwrapped_key

def test_wrap_params():
    wrap_params = {
        "EC": {"alg": "ECDH-ES+A256KW", "enc": "A256GCM"},
        "RSA": {"alg": "RSA1_5", "enc": "A256CBC-HS512"},
        "oct": {"alg": "A256KW", "enc": "A256CBC-HS512"},
    }
    for wrapping_key in WRAPPING_KEYS:
        for key in SECRET_KEYS:
            wrapped_key = wrap_key(key, wrapping_key, wrap_params)
            unwrapped_key = unwrap_key(wrapped_key, [wrapping_key])
            assert key == unwrapped_key
