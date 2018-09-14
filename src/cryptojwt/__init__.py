"""JSON Web Token"""
import json
import logging

from .exception import BadSyntax
from .utils import as_unicode
from .utils import b64encode_item
from .utils import b64d
from .utils import split_token

try:
    from builtins import zip
    from builtins import hex
    from builtins import str
except ImportError:
    pass

__version__ = '0.4.1'

logger = logging.getLogger(__name__)

JWT_TYPES = (u"JWT", u"application/jws", u"JWS", u"JWE")

JWT_CLAIMS = {"iss": str, "sub": str, "aud": str, "exp": int, "nbf": int,
              "iat": int, "jti": str, "typ": str}

JWT_HEADERS = ["typ", "cty"]

