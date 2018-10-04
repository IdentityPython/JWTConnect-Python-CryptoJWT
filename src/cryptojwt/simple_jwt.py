import json
import logging

from .utils import as_unicode
from .utils import b64d
from .utils import b64encode_item
from .utils import split_token

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


class SimpleJWT(object):
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

        :param parts: List of parts to pack
        :param headers: The JWT headers
        :return:
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
            try:
                _msg = json.loads(_msg)
            except ValueError:
                pass

        return _msg