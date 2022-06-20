"""JSON Web Token"""
import json
import logging

from cryptojwt.jws.exception import JWSException

from ..exception import BadSignature
from ..exception import UnknownAlgorithm
from ..exception import WrongNumberOfParts
from ..jwk.asym import AsymmetricKey
from ..jwx import JWx
from ..simple_jwt import SimpleJWT
from ..utils import b64d_enc_dec
from ..utils import b64e_enc_dec
from ..utils import b64encode_item
from .dsa import ECDSASigner
from .exception import FormatError
from .exception import NoSuitableSigningKeys
from .exception import SignerAlgError
from .hmac import HMACSigner
from .pss import PSSSigner
from .rsa import RSASigner
from .utils import alg2keytype

try:
    from builtins import object
    from builtins import str
except ImportError:
    pass

logger = logging.getLogger(__name__)

KDESC = ["use", "kid", "kty"]

SIGNER_ALGS = {
    "HS256": HMACSigner("SHA256"),
    "HS384": HMACSigner("SHA384"),
    "HS512": HMACSigner("SHA512"),
    "RS256": RSASigner("RS256"),
    "RS384": RSASigner("RS384"),
    "RS512": RSASigner("RS512"),
    "ES256": ECDSASigner("ES256"),
    "ES384": ECDSASigner("ES384"),
    "ES512": ECDSASigner("ES512"),
    "PS256": PSSSigner("SHA256"),
    "PS384": PSSSigner("SHA384"),
    "PS512": PSSSigner("SHA512"),
    "none": None,
}


class JWSig(SimpleJWT):
    def sign_input(self):
        return self.b64part[0] + b"." + self.b64part[1]

    def signature(self):
        return self.part[2]

    def __len__(self):
        return len(self.part)

    def valid(self):
        if len(self) != 3:
            return False

        return True


class JWS(JWx):
    def __init__(self, msg=None, with_digest=False, httpc=None, **kwargs):
        JWx.__init__(self, msg, with_digest, httpc, **kwargs)
        if "alg" not in self:
            self["alg"] = "RS256"
        self._protected_headers = {}

    def alg_keys(self, keys, use, protected=None):
        _alg = self._pick_alg(keys)

        if keys:
            keys = self.pick_keys(keys, use=use, alg=_alg)
        else:
            keys = self.pick_keys(self._get_keys(), use=use, alg=_alg)

        xargs = protected or {}
        xargs["alg"] = _alg

        if keys:
            key = keys[0]
            if key.kid:
                xargs["kid"] = key.kid
        elif not _alg or _alg.lower() == "none":
            key = None
        else:
            if "kid" in self:
                raise NoSuitableSigningKeys(
                    "No key for algorithm: %s and kid: %s" % (_alg, self["kid"])
                )
            else:
                raise NoSuitableSigningKeys("No key for algorithm: %s" % _alg)

        return key, xargs, _alg

    def sign_compact(self, keys=None, protected=None, **kwargs):
        """
        Produce a JWS using the JWS Compact Serialization

        :param keys: A dictionary of keys
        :param protected: The protected headers (a dictionary)
        :param kwargs: claims you want to add to the standard headers
        :return: A signed JSON Web Token
        """

        _headers = self._header
        _headers.update(kwargs)

        key, xargs, _alg = self.alg_keys(keys, "sig", protected)

        if "typ" in self:
            xargs["typ"] = self["typ"]

        _headers.update(xargs)
        jwt = JWSig(**_headers)
        if _alg == "none":
            return jwt.pack(parts=[self.msg, ""])

        # All other cases
        try:
            _signer = SIGNER_ALGS[_alg]
        except KeyError:
            raise UnknownAlgorithm(_alg)

        _input = jwt.pack(parts=[self.msg])

        if isinstance(key, AsymmetricKey):
            sig = _signer.sign(_input.encode("utf-8"), key.private_key())
        else:
            sig = _signer.sign(_input.encode("utf-8"), key.key)

        logger.debug("Signed message using key with kid=%s" % key.kid)
        return ".".join([_input, b64encode_item(sig).decode("utf-8")])

    def verify_compact(self, jws=None, keys=None, allow_none=False, sigalg=None):
        """
        Verify a JWT signature

        :param jws: A signed JSON Web Token
        :param keys: A list of keys that can possibly be used to verify the
            signature
        :param allow_none: If signature algorithm 'none' is allowed
        :param sigalg: Expected sigalg
        :return: Dictionary with 2 keys 'msg' required, 'key' optional
        """
        return self.verify_compact_verbose(jws, keys, allow_none, sigalg)["msg"]

    def verify_compact_verbose(self, jws=None, keys=None, allow_none=False, sigalg=None):
        """
        Verify a JWT signature and return dict with validation results

        :param jws: A signed JSON Web Token
        :param keys: A list of keys that can possibly be used to verify the
            signature
        :param allow_none: If signature algorithm 'none' is allowed
        :param sigalg: Expected sigalg
        :return: Dictionary with 2 keys 'msg' required, 'key' optional.
            The value of 'msg' is the unpacked and verified message.
            The value of 'key' is the key used to verify the message
        """
        if jws:
            jwt = JWSig().unpack(jws)
            if len(jwt) != 3:
                raise WrongNumberOfParts(len(jwt))

            self.jwt = jwt
        elif not self.jwt:
            raise ValueError("Missing signed JWT")
        else:
            jwt = self.jwt

        try:
            _alg = jwt.headers["alg"]
        except KeyError:
            _alg = None
        else:
            if _alg is None or _alg.lower() == "none":
                if allow_none:
                    self.msg = jwt.payload()
                    return {"msg": self.msg}
                else:
                    raise SignerAlgError("none not allowed")

        if "alg" in self and self["alg"] and _alg:
            if isinstance(self["alg"], list):
                if _alg not in self["alg"]:
                    raise SignerAlgError(
                        "Wrong signing algorithm, expected {} got {}".format(self["alg"], _alg)
                    )
            elif _alg != self["alg"]:
                raise SignerAlgError(
                    "Wrong signing algorithm, expected {} got {}".format(self["alg"], _alg)
                )

        if sigalg and sigalg != _alg:
            raise SignerAlgError("Expected {0} got {1}".format(sigalg, jwt.headers["alg"]))

        self["alg"] = _alg

        if keys:
            _keys = self.pick_keys(keys)
        else:
            _keys = self.pick_keys(self._get_keys())

        if not _keys:
            if "kid" in self:
                raise NoSuitableSigningKeys("No key with kid: %s" % (self["kid"]))
            elif "kid" in self.jwt.headers:
                raise NoSuitableSigningKeys("No key with kid: %s" % (self.jwt.headers["kid"]))
            else:
                raise NoSuitableSigningKeys("No key for algorithm: %s" % _alg)

        verifier = SIGNER_ALGS[_alg]

        for key in _keys:
            if isinstance(key, AsymmetricKey):
                _key = key.public_key()
            else:
                _key = key.key

            try:
                if not verifier.verify(jwt.sign_input(), jwt.signature(), _key):
                    continue
            except (BadSignature, IndexError):
                pass
            except (ValueError, TypeError) as err:
                logger.warning('Exception "{}" caught'.format(err))
            else:
                logger.debug("Verified message using key with kid=%s" % key.kid)
                self.msg = jwt.payload()
                self.key = key
                self._protected_headers = jwt.headers.copy()
                return {"msg": self.msg, "key": key}

        raise BadSignature()

    def sign_json(self, keys=None, headers=None, flatten=False):
        """
        Produce JWS using the JWS JSON Serialization

        :param keys: list of keys to use for signing the JWS
        :param headers: list of tuples (protected headers, unprotected
            headers) for each signature
        :return: A signed message using the JSON serialization format.
        """

        def create_signature(protected, unprotected):
            protected_headers = protected or {}
            # always protect the signing alg header
            protected_headers.setdefault("alg", self.alg)
            _jws = JWS(self.msg, **protected_headers)
            encoded_header, payload, signature = _jws.sign_compact(
                protected=protected, keys=keys
            ).split(".")
            signature_entry = {"signature": signature}
            if unprotected:
                signature_entry["header"] = unprotected
            if encoded_header:
                signature_entry["protected"] = encoded_header

            return signature_entry

        res = {"payload": b64e_enc_dec(self.msg, "utf-8", "ascii")}

        if headers is None:
            headers = [(dict(alg=self.alg), None)]

        if flatten and len(headers) == 1:  # Flattened JWS JSON Serialization Syntax
            signature_entry = create_signature(*headers[0])
            res.update(signature_entry)
        else:
            res["signatures"] = []
            for protected, unprotected in headers:
                signature_entry = create_signature(protected, unprotected)
                res["signatures"].append(signature_entry)

        return json.dumps(res)

    def verify_json(self, jws, keys=None, allow_none=False, at_least_one=False):
        """
        Verifies a JSON serialized signed JWT. The object may contain multiple
        signatures. In the case that the verifier does not have the whole
        set of necessary keys she may chose to accept that some verifications
        fails due to no suitable key.

        :param jws: The JSON document representing the signed JSON
        :param keys: Keys that might be useful for verifying the signatures
        :param allow_none: Allow the None signature algorithm. Is the same
            as allowing no signature at all.
        :param at_least_one: At least one of the signatures must verify
            correctly. No suitable signing key is the only allowed exception.
        :return:
        """

        _jwss = json.loads(jws)

        try:
            _payload = _jwss["payload"]
        except KeyError:
            raise FormatError("Missing payload")

        try:
            _signs = _jwss["signatures"]
        except KeyError:
            # handle Flattened JWKS Serialization Syntax
            signature = {}
            for key in ["protected", "header", "signature"]:
                if key in _jwss:
                    signature[key] = _jwss[key]
            _signs = [signature]

        _claim = None
        _all_protected = {}
        for _sign in _signs:
            protected_headers = _sign.get("protected", "")
            token = b".".join(
                [
                    protected_headers.encode(),
                    _payload.encode(),
                    _sign["signature"].encode(),
                ]
            )

            unprotected_headers = _sign.get("header", {})
            all_headers = unprotected_headers.copy()
            if protected_headers:
                _protected = json.loads(b64d_enc_dec(protected_headers))
                _all_protected.update(_protected)
                all_headers.update(_protected)
            self.__init__(**all_headers)

            try:
                _tmp = self.verify_compact(token, keys, allow_none)
            except NoSuitableSigningKeys:
                if at_least_one is True:
                    logger.warning(
                        "Could not verify signature with headers: {}".format(all_headers)
                    )
                    continue
                else:
                    raise
            except JWSException as err:
                raise

            if _claim is None:
                _claim = _tmp
            else:
                if _claim != _tmp:
                    raise ValueError()

        if not _claim:
            raise NoSuitableSigningKeys("None")

        self._protected_headers = _all_protected
        return _claim

    def is_jws(self, jws):
        """

        :param jws:
        :return:
        """

        try:
            # JWS JSON serialization
            try:
                json_jws = json.loads(jws)
            except TypeError:
                jws = jws.decode("utf8")
                json_jws = json.loads(jws)

            return self._is_json_serialized_jws(json_jws)
        except ValueError:
            return self._is_compact_jws(jws)

    def _is_json_serialized_jws(self, json_jws):
        """
        Check if we've got a JSON serialized signed JWT.

        :param json_jws: The message
        :return: True/False
        """
        json_ser_keys = {"payload", "signatures"}
        flattened_json_ser_keys = {"payload", "signature"}
        if not json_ser_keys.issubset(json_jws.keys()) and not flattened_json_ser_keys.issubset(
            json_jws.keys()
        ):
            return False
        return True

    def _is_compact_jws(self, jws):
        """
        Check if we've got a compact signed JWT

        :param jws: The message
        :return: True/False
        """
        try:
            jwt = JWSig().unpack(jws)
        except Exception as err:
            logger.warning("Could not parse JWS: {}".format(err))
            return False

        if "alg" not in jwt.headers:
            return False

        if jwt.headers["alg"] is None:
            jwt.headers["alg"] = "none"

        if jwt.headers["alg"] not in SIGNER_ALGS:
            logger.debug("UnknownSignerAlg: %s" % jwt.headers["alg"])
            return False

        self.jwt = jwt
        return True

    def alg2keytype(self, alg):
        """
        Translate a signing algorithm into a specific key type.

        :param alg: The signing algorithm
        :return: A key type or None if there is no key type matching the
            algorithm
        """
        return alg2keytype(alg)

    def set_header_claim(self, key, value):
        """
        Set a specific claim in the header to a specific value.

        :param key: The name of the claim
        :param value: The value of the claim
        """
        self._header[key] = value

    def verify_alg(self, alg):
        """
        Specifically check that the 'alg' claim has a specific value

        :param alg: The expected alg value
        :return: True if the alg value in the header is the same as the one
            given. Returns False if no 'alg' claim exists in the header.
        """
        try:
            return self.jwt.verify_header("alg", alg)
        except KeyError:
            return False

    def protected_headers(self):
        return self._protected_headers.copy()


def factory(token, alg=""):
    """
    Instantiate an JWS instance if the token is a signed JWT.

    :param token: The token that might be a signed JWT
    :param alg: The expected signature algorithm
    :return: A JWS instance if the token was a signed JWT, otherwise None
    """

    _jw = JWS(alg=alg)
    if _jw.is_jws(token):
        return _jw
    else:
        return None
