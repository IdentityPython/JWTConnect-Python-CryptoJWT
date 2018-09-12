import json

from .jwk import keyrep
from .jwk import jwk_wrap
from ..utils import bytes2str_conv


class JWKS(object):
    def __init__(self, httpc=None):
        self._keys = []
        self.httpc = httpc

    def load_dict(self, dikt):
        for kspec in dikt["keys"]:
            self._keys.append(keyrep(kspec))

    def load_jwks(self, jwks):
        """
        Load and create keys from a JWKS JSON representation

        Expects something on this form::

            {"keys":
                [
                    {"kty":"EC",
                     "crv":"P-256",
                     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use":"enc",
                    "kid":"1"},

                    {"kty":"RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb....."
                    "e":"AQAB",
                    "kid":"2011-04-29"}
                ]
            }

        :param jwks: The JWKS JSON string representation
        :return: list of 2-tuples containing key, type
        """
        self.load_dict(json.loads(jwks))
        return self

    def dump_jwks(self):
        """
        :return: A JWKS representation of the held keys
        """
        res = []
        for key in self._keys:
            res.append(bytes2str_conv(key.serialize()))

        return json.dumps({"keys": res})

    def load_from_url(self, url, verify=True):
        """
        Get and transform a JWKS into keys

        :param url: Where the JWKS can be found
        :param verify: SSL cert verification
        :return: list of keys
        """

        r = self.httpc.get(url, allow_redirects=True, verify=verify)
        if r.status_code == 200:
            return self.load_jwks(r.text)
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)

    def __getitem__(self, item):
        """
        Get all keys of a specific key type

        :param item: Key type
        :return: list of keys
        """
        kty = item.lower()
        return [k for k in self._keys if k.kty.lower() == kty]

    def __iter__(self):
        for k in self._keys:
            yield k

    def __len__(self):
        return len(self._keys)

    def keys(self):
        return self._keys

    def key_types(self):
        """

        :return: A list of key types !!! not keys
        """
        return list(set([k.kty for k in self._keys]))

    def __repr__(self):
        return self.dump_jwks()

    def __str__(self):
        return self.__repr__()

    def kids(self):
        return [k.kid for k in self._keys if k.kid]

    def by_kid(self, kid):
        return [k for k in self._keys if kid == k.kid]

    def wrap_add(self, keyinst, use="", kid=''):
        self._keys.append(jwk_wrap(keyinst, use, kid))

    def as_dict(self):
        _res = {}
        for kty, k in [(k.kty, k) for k in self._keys]:
            if kty not in ["RSA", "EC", "oct"]:
                if kty in ["rsa", "ec"]:
                    kty = kty.upper()
                else:
                    kty = kty.lower()

            try:
                _res[kty].append(k)
            except KeyError:
                _res[kty] = [k]
        return _res

    def add(self, item, enc="utf-8"):
        self._keys.append(keyrep(item, enc))

    def append(self, key):
        self._keys.append(key)


def load_jwks_from_url(url, httpc=None, verify=True):
    return JWKS(httpc=httpc).load_from_url(url, verify=verify).keys()


def load_jwks(spec):
    return JWKS().load_jwks(spec).keys()

