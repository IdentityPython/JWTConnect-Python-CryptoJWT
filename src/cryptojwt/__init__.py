"""JSON Web Token"""
import logging

import pkg_resources

from cryptojwt.jwe.jwe import JWE
from cryptojwt.jwk import JWK
from cryptojwt.jws.jws import JWS
from cryptojwt.jwt import JWT
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar

from .exception import BadSyntax
from .utils import as_unicode
from .utils import b64d
from .utils import b64encode_item
from .utils import split_token

try:
    from builtins import hex
    from builtins import str
    from builtins import zip
except ImportError:
    pass

__version__ = pkg_resources.get_distribution("cryptojwt").version

logger = logging.getLogger(__name__)

JWT_TYPES = (u"JWT", u"application/jws", u"JWS", u"JWE")

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
