import contextlib
import json
import logging

from cryptojwt.exception import HeaderError

from .utils import as_unicode, b64d, b64encode_item, split_token

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class SimpleJWT:
    """
    Basic JSON Web Token class that doesn't make any assumptions as to what
    can or should be in the payload
    """

    def __init__(self, **headers):
        if not headers.get("alg"):
            headers["alg"] = None
        self.headers = headers
        self.b64part = [b64encode_item(headers)]
        self.part = [b64d(self.b64part[0])]

    def unpack(self, token, **kwargs):
        """
        Unpacks a JWT into its parts and base64 decodes the parts
        individually

        :param token: The JWT
        :param kwargs: A possible empty set of claims to verify the header
            against.
        """
        if isinstance(token, str):
            with contextlib.suppress(UnicodeDecodeError):
                token = token.encode("utf-8")

        part = split_token(token)
        self.b64part = part
        self.part = [b64d(p) for p in part]
        self.headers = json.loads(as_unicode(self.part[0]))
        for key, val in kwargs.items():
            if not val and key in self.headers:
                continue

            try:
                _ok = self.verify_header(key, val)
            except KeyError:
                raise
            else:
                if not _ok:
                    raise HeaderError(f'Expected "{key}" to be "{val}", was "{self.headers[key]}"')

        return self

    def pack(self, parts=None, headers=None):
        """
        Packs components into a JWT

        :param parts: List of parts to pack
        :param headers: The JWT headers
        :return:
        """
        if not headers:
            headers = self.headers if self.headers else {"alg": "none"}

        logging.debug(f"(pack) JWT header: {headers}")

        if not parts:
            return ".".join([a.decode() for a in self.b64part])

        self.part = [headers] + parts
        _all = self.b64part = [b64encode_item(headers)]
        _all.extend([b64encode_item(p) for p in parts])

        return ".".join([a.decode() for a in _all])

    def payload(self):
        """
        Picks out the payload from the different parts of the signed/encrypted
        JSON Web Token. If the content type is said to be 'jwt' deserialize the
        payload into a Python object otherwise return as-is.

        :return: The payload
        """
        _msg = as_unicode(self.part[1])

        # If not JSON web token assume JSON
        if "cty" in self.headers and self.headers["cty"].lower() != "jwt":
            pass
        else:
            with contextlib.suppress(ValueError):
                _msg = json.loads(_msg)

        return _msg

    def verify_header(self, key, val):
        """
        Check that a particular header claim is present and has a specific value

        :param key: The claim
        :param val: The value of the claim
        :raises: KeyError if the claim is not present in the header
        :return: True if the claim exists in the header and has the prescribed
            value
        """

        if isinstance(val, list):
            return self.headers[key] in val
        else:
            return self.headers[key] == val

    def verify_headers(self, check_presence=True, **kwargs):
        """
        Check that a set of particular header claim are present and has
        specific values

        :param kwargs: The claim/value sets as a dictionary
        :return: True if the claim that appears in the header has the
            prescribed values. If a claim is not present in the header and
            check_presence is True then False is returned.
        """
        for key, val in kwargs.items():
            try:
                _ok = self.verify_header(key, val)
            except KeyError:
                if check_presence:
                    return False
                else:
                    pass
            else:
                if not _ok:
                    return False
        return True
