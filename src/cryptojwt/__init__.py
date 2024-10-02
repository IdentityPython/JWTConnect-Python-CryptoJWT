"""JSON Web Token"""

import logging
from importlib.metadata import version

from cryptojwt.jwe.jwe import JWE
from cryptojwt.jwk import JWK
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar

from .exception import BadSyntax
from .utils import as_unicode, b64d, b64encode_item, split_token

__version__ = version("cryptojwt")

__all__ = [
    "JWE",
    "JWE",
    "JWK",
    "JWS",
    "JWT",
    "KeyBundle",
    "KeyJar",
    "BadSyntax",
    "as_unicode",
    "b64d",
    "b64encode_item",
    "split_token",
]

logger = logging.getLogger(__name__)

JWT_TYPES = ("JWT", "application/jws", "JWS", "JWE")

JWT_CLAIMS = {
    "iss": str,
    "sub": str,
    "aud": str,
    "exp": int,
    "nbf": int,
    "iat": int,
    "jti": str,
    "typ": str,
}

JWT_HEADERS = ["typ", "cty"]
