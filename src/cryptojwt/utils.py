import base64
import functools
import importlib
import json
import re
import struct
import warnings
from binascii import unhexlify
from typing import List

from cryptojwt.exception import BadSyntax

# ---------------------------------------------------------------------------
# Helper functions


def intarr2bin(arr):
    return unhexlify("".join(["%02x" % byte for byte in arr]))


def intarr2long(arr):
    return int("".join(["%02x" % byte for byte in arr]), 16)


def intarr2str(arr):
    return "".join([chr(c) for c in arr])


def long2intarr(long_int):
    _bytes: List[int] = []
    while long_int:
        long_int, r = divmod(long_int, 256)
        _bytes.insert(0, r)
    return _bytes


def long_to_base64(n, mlen=0):
    bys = long2intarr(n)
    if mlen:
        _len = mlen - len(bys)
        if _len:
            bys = [0] * _len + bys
    data = struct.pack("%sB" % len(bys), *bys)
    if not len(data):
        data = b"\x00"
    s = base64.urlsafe_b64encode(data).rstrip(b"=")
    return s.decode("ascii")


def base64_to_long(data):
    if isinstance(data, str):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(as_bytes(data) + b"==")
    return intarr2long(struct.unpack("%sB" % len(_d), _d))


def base64url_to_long(data):
    """
    Stricter then base64_to_long since it really checks that it's
    base64url encoded

    :param data: The base64 string
    :return:
    """
    _data = as_bytes(data)
    _d = base64.urlsafe_b64decode(_data + b"==")
    # verify that it's base64url encoded and not just base64
    # that is no '+' and '/' characters and not trailing "="s.
    if [e for e in [b"+", b"/", b"="] if e in _data]:
        raise ValueError("Not base64url encoded")
    return intarr2long(struct.unpack("%sB" % len(_d), _d))


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
    """"""
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
        return b64e(json.dumps(bytes2str_conv(item), separators=(",", ":")).encode("utf-8"))


def split_token(token):
    if not token.count(b"."):
        raise BadSyntax(token, "expected token to contain at least one dot")
    return tuple(token.split(b"."))


def deser(val):
    """
    Deserialize from a string representation of an long integer
    to the python representation of a long integer.

    :param val: The string representation of the long integer.
    :return: The long integer.
    """
    if isinstance(val, str):
        _val = val.encode("utf-8")
    else:
        _val = val

    return base64_to_long(_val)


def modsplit(name):
    """Split importable"""
    if ":" in name:
        _part = name.split(":")
        if len(_part) != 2:
            raise ValueError(f"Syntax error: {s}")
        return _part[0], _part[1]

    _part = name.split(".")
    if len(_part) < 2:
        raise ValueError(f"Syntax error: {s}")

    return ".".join(_part[:-1]), _part[-1]


def importer(name):
    """Import by name"""
    _part = modsplit(name)
    module = importlib.import_module(_part[0])
    return getattr(module, _part[1])


def qualified_name(cls):
    return cls.__module__ + "." + cls.__name__


# This is borrowed from
# https://stackoverflow.com/questions/49802412/how-to-implement-deprecation-in-python-with
# -argument-alias
# cudos to https://stackoverflow.com/users/2357112/user2357112-supports-monica


def deprecated_alias(**aliases):
    def deco(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            rename_kwargs(f.__name__, kwargs, aliases)
            return f(*args, **kwargs)

        return wrapper

    return deco


def rename_kwargs(func_name, kwargs, aliases):
    for alias, new in aliases.items():
        if alias in kwargs:
            if new in kwargs:
                raise TypeError("{} received both {} and {}".format(func_name, alias, new))
            warnings.warn("{} is deprecated; use {}".format(alias, new), DeprecationWarning)
            kwargs[new] = kwargs.pop(alias)
