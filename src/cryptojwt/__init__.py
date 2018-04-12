"""JSON Web Token"""
import base64
import json
import logging
import re
import struct

from cryptojwt.exception import BadSyntax

try:
    from builtins import zip
    from builtins import hex
    from builtins import str
except ImportError:
    pass

from binascii import unhexlify

__version__ = '0.3.0'

logger = logging.getLogger(__name__)

JWT_TYPES = (u"JWT", u"application/jws", u"JWS", u"JWE")

JWT_CLAIMS = {"iss": str, "sub": str, "aud": str, "exp": int, "nbf": int,
              "iat": int, "jti": str, "typ": str}

JWT_HEADERS = ["typ", "cty"]


# ---------------------------------------------------------------------------
# Helper functions


def intarr2bin(arr):
    return unhexlify(''.join(["%02x" % byte for byte in arr]))


def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def long2intarr(long_int):
    _bytes = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n):
    bys = long2intarr(n)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
    s = base64.urlsafe_b64encode(data).rstrip(b'=')
    return s.decode("ascii")


def base64_to_long(data):
    if isinstance(data, str):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))


def base64url_to_long(data):
    """
    Stricter then base64_to_long since it really checks that it's
    base64url encoded

    :param data: The base64 string
    :return:
    """
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    # verify that it's base64url encoded and not just base64
    # that is no '+' and '/' characters and not trailing "="s.
    if [e for e in [b'+', b'/', b'='] if e in data]:
        raise ValueError("Not base64url encoded")
    return intarr2long(struct.unpack('%sB' % len(_d), _d))


# =============================================================================

def b64e(b):
    """Base64 encode some bytes.

    Uses the url-safe - and _ characters, and doesn't pad with = characters."""
    return base64.urlsafe_b64encode(b).rstrip(b"=")


_b64_re = re.compile(b"^[A-Za-z0-9_-]*$")


def add_padding(b):
    # add padding chars
    m = len(b) % 4
    if m == 1:
        # NOTE: for some reason b64decode raises *TypeError* if the
        # padding is incorrect.
        raise BadSyntax(b, "incorrect padding")
    elif m == 2:
        b += b"=="
    elif m == 3:
        b += b"="
    return b


def b64d(b):
    """Decode some base64-encoded bytes.

    Raises BadSyntax if the string contains invalid characters or padding.

    :param b: bytes
    """

    cb = b.rstrip(b"=")  # shouldn't but there you are

    # Python's base64 functions ignore invalid characters, so we need to
    # check for them explicitly.
    if not _b64_re.match(cb):
        raise BadSyntax(cb, "base64-encoded data contains illegal characters")

    if cb == b:
        b = add_padding(b)

    return base64.urlsafe_b64decode(b)


def b64e_enc_dec(str, encode="utf-8", decode="ascii"):
    return b64e(str.encode(encode)).decode(decode)


def b64d_enc_dec(str, encode="ascii", decode="utf-8"):
    return b64d(str.encode(encode)).decode(decode)


# 'Stolen' from Werkzeug
def safe_str_cmp(a, b):
    """Compare two strings in constant time."""
    if len(a) != len(b):
        return False
    r = 0
    for c, d in zip(a, b):
        r |= ord(c) ^ ord(d)
    return r == 0


def constant_time_compare(a, b):
    """Compare two strings in constant time."""
    if len(a) != len(b):
        return False
    r = 0
    for c, d in zip(a, b):
        r |= c ^ d
    return r == 0


def as_bytes(s):
    """
    Convert an unicode string to bytes.
    :param s: Unicode / bytes string
    :return: bytes string
    """
    try:
        s = s.encode()
    except (AttributeError, UnicodeDecodeError):
        pass
    return s


def as_unicode(b):
    """
    Convert a byte string to a unicode string
    :param b: byte string
    :return: unicode string
    """
    try:
        b = b.decode()
    except (AttributeError, UnicodeDecodeError):
        pass
    return b


def bytes2str_conv(item):
    """
    """
    if isinstance(item, bytes):
        return item.decode("utf-8")
    elif item is None or isinstance(item, (str, int, bool)):
        return item
    elif isinstance(item, list):
        return [bytes2str_conv(i) for i in item]
    elif isinstance(item, dict):
        return dict([(k, bytes2str_conv(v)) for k, v in item.items()])

    raise ValueError("Can't convert {}.".format(repr(item)))


def b64encode_item(item):
    if isinstance(item, bytes):
        return b64e(item)
    elif isinstance(item, str):
        return b64e(item.encode("utf-8"))
    elif isinstance(item, int):
        return b64e(item)
    else:
        return b64e(json.dumps(bytes2str_conv(item),
                               separators=(",", ":")).encode("utf-8"))


def split_token(token):
    if not token.count(b"."):
        raise BadSyntax(token,
                        "expected token to contain at least one dot")
    return tuple(token.split(b"."))


class SimpleJWT(object):
    def __init__(self, **headers):
        if not headers.get("alg"):
            headers["alg"] = None
        self.headers = headers
        self.b64part = [b64encode_item(headers)]
        self.part = [b64d(self.b64part[0])]

    def unpack(self, token):
        """
        Unpacks a JWT into its parts and base64 decodes the parts
        individually

        :param token: The JWT
        """
        if isinstance(token, str):
            try:
                token = token.encode("utf-8")
            except UnicodeDecodeError:
                pass

        part = split_token(token)
        self.b64part = part
        self.part = [b64d(p) for p in part]
        #self.headers = json.loads(self.part[0].decode())
        self.headers = json.loads(as_unicode(self.part[0]))
        return self

    def pack(self, parts=None, headers=None):
        """
        Packs components into a JWT

        :param returns: The string representation of a JWT
        """
        if not headers:
            if self.headers:
                headers = self.headers
            else:
                headers = {'alg': 'none'}

        logging.debug('JWT header: {}'.format(headers))

        if not parts:
            return ".".join([a.decode() for a in self.b64part])

        self.part = [headers] + parts
        _all = self.b64part = [b64encode_item(headers)]
        _all.extend([b64encode_item(p) for p in parts])

        return ".".join([a.decode() for a in _all])

    def payload(self):
        _msg = as_unicode(self.part[1])

        # If not JSON web token assume JSON
        if "cty" in self.headers and self.headers["cty"].lower() != "jwt":
            pass
        else:
            try:
                _msg = json.loads(_msg)
            except ValueError:
                pass

        return _msg
