"""A basic class on which to build the JWS and JWE classes."""
import json
import logging

import requests

from cryptojwt.jwk import JWK
from cryptojwt.key_bundle import KeyBundle

from .exception import HeaderError
from .jwk.jwk import key_from_jwk_dict
from .jwk.rsa import RSAKey
from .jwk.rsa import import_rsa_key
from .jwk.x509 import load_x509_cert
from .utils import as_bytes
from .utils import as_unicode
from .utils import b64d

LOGGER = logging.getLogger(__name__)

__author__ = "Roland Hedberg"


class JWx:
    """A basic class with the commonalities between the JWS and JWE classes.

    :param alg: The signing algorithm
    :param jku: a URI that refers to a resource for a set of JSON-encoded
        public keys, one of which corresponds to the key used to digitally
        sign the JWS
    :param jwk: A JSON Web Key that corresponds to the key used to
        digitally sign the JWS
    :param x5u: a URI that refers to a resource for the X.509 public key
        certificate or certificate chain [RFC5280] corresponding to the key
        used to digitally sign the JWS.
    :param x5t: a base64url encoded SHA-1 thumbprint (a.k.a. digest) of the
        DER encoding of the X.509 certificate [RFC5280] corresponding to
        the key used to digitally sign the JWS.
    :param x5c: the X.509 public key certificate or certificate chain
        corresponding to the key used to digitally sign the JWS.
    :param kid: a hint indicating which key was used to secure the JWS.
    :param typ: the type of this object. 'JWS' == JWS Compact Serialization
        'JWS+JSON' == JWS JSON Serialization
    :param cty: the type of the secured content
    :param crit: indicates which extensions that are being used and MUST
        be understood and processed.
    :param kwargs: Extra header parameters
    :return: A class instance
    """

    args = ["alg", "jku", "jwk", "x5u", "x5t", "x5c", "kid", "typ", "cty", "crit"]

    def __init__(self, msg=None, with_digest=False, httpc=None, **kwargs):
        self.msg = msg

        self._dict = {}
        self.with_digest = with_digest
        if httpc:
            self.httpc = httpc
        else:
            self.httpc = requests.request

        self.jwt = None
        self._jwk = None
        self._jwks = None
        self._header = {}

        if kwargs:
            for key in self.args:
                try:
                    _val = kwargs[key]
                except KeyError:
                    continue

                if key == "jwk":
                    self._set_jwk(_val)
                    self._jwk = self._dict["jwk"]
                elif key == "x5c":
                    self._dict["x5c"] = _val
                    _pub_key = import_rsa_key(_val)
                    self._jwk = RSAKey(pub_key=_pub_key).to_dict()
                elif key == "jku":
                    self._jwks = KeyBundle(source=_val, httpc=self.httpc)
                    self._dict["jku"] = _val
                elif "x5u" in self:
                    try:
                        _spec = load_x509_cert(self["x5u"], self.httpc, {})
                        self._jwk = RSAKey(pub_key=_spec["rsa"]).to_dict()
                    except Exception:
                        # ca_chain = load_x509_cert_chain(self["x5u"])
                        raise ValueError("x5u")
                else:
                    self._dict[key] = _val

    def _set_jwk(self, val):
        if isinstance(val, dict):
            _k = key_from_jwk_dict(val)
            self._dict["jwk"] = val
        elif isinstance(val, str):
            # verify that it's a real JWK
            _val = json.loads(val)
            _j = key_from_jwk_dict(_val)
            self._dict["jwk"] = _val
        elif isinstance(val, JWK):
            self._dict["jwk"] = val.to_dict()
        else:
            raise ValueError("JWK must be a string a JSON object or a JWK instance")

    def __contains__(self, item):
        return item in self._dict

    def __getitem__(self, item):
        return self._dict[item]

    def __setitem__(self, key, value):
        self._dict[key] = value

    def __getattr__(self, item):
        try:
            return self._dict[item]
        except KeyError:
            raise AttributeError(item)

    def keys(self):
        """Return all keys."""
        return list(self._dict.keys())

    def _set_header_jwk(self, header, **kwargs):
        if "jwk" in self:
            header["jwk"] = self["jwk"]
        else:
            try:
                _jwk = kwargs["jwk"]
            except KeyError:
                pass
            else:
                try:
                    header["jwk"] = _jwk.serialize()  # JWK instance
                except AttributeError:
                    if isinstance(_jwk, dict):
                        header["jwk"] = _jwk  # dictionary
                    else:
                        _d = json.loads(_jwk)  # JSON
                        # Verify that it's a valid JWK
                        _k = key_from_jwk_dict(_d)
                        header["jwk"] = _d

    def headers(self, **kwargs):
        """Return the JWE/JWS header."""
        _header = self._header.copy()
        for param in self.args:
            try:
                _header[param] = kwargs[param]
            except KeyError:
                try:
                    if self._dict[param]:
                        _header[param] = self._dict[param]
                except KeyError:
                    pass

        self._set_header_jwk(_header, **kwargs)

        if "kid" in self:
            if not isinstance(self["kid"], str):
                raise HeaderError("kid of wrong value type")

        return _header

    def _get_keys(self):
        _keys = []
        if self._jwk:
            _keys.append(key_from_jwk_dict(self._jwk))
        if self._jwks is not None:
            _keys.extend(self._jwks.keys())
        return _keys

    def alg2keytype(self, alg):
        """Convert an algorithm identifier to a key type identifier."""
        raise NotImplementedError()

    def pick_keys(self, keys, use="", alg=""):
        """
        The assumption is that upper layer has made certain you only get
        keys you can use.

        :param alg: The crypto algorithm
        :param use: What the key should be used for
        :param keys: A list of JWK instances
        :return: A list of JWK instances that fulfill the requirements
        """
        if not alg:
            alg = self["alg"]

        if alg == "none":
            return []

        _k = self.alg2keytype(alg)
        if _k is None:
            LOGGER.error("Unknown algorithm '%s'", alg)
            raise ValueError("Unknown cryptography algorithm")

        LOGGER.debug("Picking key by key type=%s", _k)
        _kty = [
            _k.lower(),
            _k.upper(),
            _k.lower().encode("utf-8"),
            _k.upper().encode("utf-8"),
        ]
        _keys = [k for k in keys if k.kty in _kty]
        try:
            _kid = self["kid"]
        except KeyError:
            try:
                _kid = self.jwt.headers["kid"]
            except (AttributeError, KeyError):
                _kid = None

        LOGGER.debug("Picking key based on alg=%s, kid=%s and use=%s", alg, _kid, use)

        pkey = []
        for _key in _keys:
            LOGGER.debug("Picked: kid:%s, use:%s, kty:%s", _key.kid, _key.use, _key.kty)
            if _kid:
                if _kid != _key.kid:
                    continue

            if use and _key.use and _key.use != use:
                continue

            if alg and _key.alg and _key.alg != alg:
                continue

            pkey.append(_key)

        return pkey

    def _pick_alg(self, keys):
        alg = None
        try:
            alg = self["alg"]
        except KeyError:
            # try to get alg from key if there is only one
            if keys is not None and len(keys) == 1:
                key = next(iter(keys))  # first element from either list or dict
                if key.alg:
                    self["alg"] = alg = key.alg

        if not alg:
            self["alg"] = alg = "none"

        return alg

    def _decode(self, payload):
        _msg = b64d(as_bytes(payload))
        if "cty" in self:
            if self["cty"] == "JWT":
                _msg = json.loads(as_unicode(_msg))
        return _msg

    def dump_header(self):
        """Return all attributes with values."""
        return {x: self._dict[x] for x in self.args if x in self._dict}
