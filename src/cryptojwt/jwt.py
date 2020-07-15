"""Basic JSON Web Token implementation."""
import json
import logging
import uuid
from datetime import datetime
from json import JSONDecodeError

from .exception import HeaderError
from .exception import VerificationError
from .jwe.jwe import JWE
from .jwe.jwe import factory as jwe_factory
from .jwe.utils import alg2keytype as jwe_alg2keytype
from .jws.exception import NoSuitableSigningKeys
from .jws.jws import JWS
from .jws.jws import factory as jws_factory
from .jws.utils import alg2keytype as jws_alg2keytype
from .utils import as_unicode

__author__ = "Roland Hedberg"

LOGGER = logging.getLogger(__name__)


def utc_time_sans_frac():
    """
    Produces UTC time without fractions

    :return: A number of seconds
    """
    return int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())


def pick_key(keys, use, alg="", key_type="", kid=""):
    """
    Based on given set of criteria pick out the keys that fulfill them from a
    given set of keys.

    :param keys: List of keys. These are :py:class:`cryptojwt.jwk.JWK`
        instances.
    :param use: What the key is going to be used for 'sig'/'enc'
    :param alg: crypto algorithm
    :param key_type: Type of key 'rsa'/'ec'/'oct'
    :param kid: Key ID
    :return: A list of keys that match the pattern
    """
    res = []
    if not key_type:
        if use == "sig":
            key_type = jws_alg2keytype(alg)
        else:
            key_type = jwe_alg2keytype(alg)

    for key in keys:
        if key.use and key.use != use:
            continue

        if key.kty != key_type:
            continue

        if key.kid and kid and key.kid != kid:
            continue

        if key.alg == "" and alg:
            if key_type == "EC":
                if key.crv != "P-{}".format(alg[2:]):
                    continue
        elif alg and key.alg != alg:
            continue

        res.append(key)
    return res


class JWT:
    jwt_parameters = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

    """The basic JSON Web Token class."""

    def __init__(
        self,
        key_jar=None,
        iss="",
        lifetime=0,
        sign=True,
        sign_alg="RS256",
        encrypt=False,
        enc_enc="A128CBC-HS256",
        enc_alg="RSA1_5",
        msg_cls=None,
        iss2msg_cls=None,
        skew=15,
        allowed_sign_algs=None,
        allowed_enc_algs=None,
        allowed_enc_encs=None,
        zip="",
    ):
        self.key_jar = key_jar  # KeyJar instance
        self.iss = iss  # My identifier
        self.lifetime = lifetime  # default life time of the signature
        self.sign = sign  # default signing or not
        self.alg = sign_alg  # default signing algorithm
        self.encrypt = encrypt  # default encrypting or not
        self.enc_alg = enc_alg  # CEK encryption algorithm
        self.enc_enc = enc_enc  # content encryption algorithm
        self.msg_cls = msg_cls  # message class
        self.with_jti = False  # If a jti should be added
        # A map between issuers and the message classes they use
        self.iss2msg_cls = iss2msg_cls or {}
        # Allowed time skew
        self.skew = skew
        # When verifying/decrypting
        self.allowed_sign_algs = allowed_sign_algs
        self.allowed_enc_algs = allowed_enc_algs
        self.allowed_enc_encs = allowed_enc_encs
        self.zip = zip

    def receiver_keys(self, recv, use):
        """
        Get the receivers keys.
        :param recv: The receiver identifier
        :param use: What the keys should be usable for
        :return: A list of keys.
        """
        return self.key_jar.get(use, issuer_id=recv)

    def receivers(self):
        """Return a list of identifiers.

        The list contains all the owners of keys that reside in this Key Jar.
        :return: List of identifiers
        """
        return self.key_jar.owners

    def my_keys(self, issuer_id="", use="sig"):
        _k = self.key_jar.get(use, issuer_id=issuer_id)
        if issuer_id != "":
            try:
                _k.extend(self.key_jar.get(use, issuer_id=""))
            except KeyError:
                pass
        return _k

    def _encrypt(self, payload, recv, cty="JWT", zip=""):
        kwargs = {"alg": self.enc_alg, "enc": self.enc_enc}

        if cty:
            kwargs["cty"] = cty
        if zip:
            kwargs["zip"] = zip

        # use the clients public key for encryption
        _jwe = JWE(payload, **kwargs)
        return _jwe.encrypt(self.receiver_keys(recv, "enc"), context="public")

    @staticmethod
    def put_together_aud(recv, aud=None):
        """

        :param recv: The intended receiver
        :param aud: A list of entity identifiers (the audience)
        :return: A possibly extended audience set
        """
        if aud:
            if recv and recv not in aud:
                _aud = [recv]
                _aud.extend(aud)
            else:
                _aud = aud
        elif recv:
            _aud = [recv]
        else:
            _aud = []

        return _aud

    def pack_init(self, recv, aud):
        """
        Gather initial information for the payload.

        :return: A dictionary with claims and values
        """
        argv = {"iss": self.iss, "iat": utc_time_sans_frac()}
        if self.lifetime:
            argv["exp"] = argv["iat"] + self.lifetime

        _aud = self.put_together_aud(recv, aud)
        if _aud:
            argv["aud"] = _aud

        return argv

    def pack_key(self, issuer_id="", kid=""):
        """
        Find a key to be used for signing the Json Web Token

        :param issuer_id: Owner of the keys to chose from
        :param kid: Key ID
        :return: One key
        """
        keys = pick_key(self.my_keys(issuer_id, "sig"), "sig", alg=self.alg, kid=kid)

        if not keys:
            raise NoSuitableSigningKeys("kid={}".format(kid))

        return keys[0]  # Might be more then one if kid == ''

    def pack(self, payload=None, kid="", issuer_id="", recv="", aud=None, **kwargs):
        """

        :param payload: Information to be carried as payload in the JWT
        :param kid: Key ID
        :param issuer_id: The owner of the the keys that are to be used for signing
        :param recv: The intended immediate receiver
        :param aud: Intended audience for this JWS/JWE, not expected to
            contain the recipient.
        :param kwargs: Extra keyword arguments
        :return: A signed or signed and encrypted Json Web Token
        """
        _args = {}
        if payload is not None:
            _args.update(payload)
        _args.update(self.pack_init(recv, aud))

        try:
            _encrypt = kwargs["encrypt"]
        except KeyError:
            _encrypt = self.encrypt
        else:
            del kwargs["encrypt"]

        if self.with_jti:
            try:
                _jti = kwargs["jti"]
            except KeyError:
                _jti = uuid.uuid4().hex

            _args["jti"] = _jti

        if not issuer_id and self.iss:
            issuer_id = self.iss

        if self.sign:
            if self.alg != "none":
                _key = self.pack_key(issuer_id, kid)
                # _args['kid'] = _key.kid
            else:
                _key = None

            _jws = JWS(json.dumps(_args), alg=self.alg)
            _sjwt = _jws.sign_compact([_key])
        else:
            _sjwt = json.dumps(_args)

        if _encrypt:
            if not self.sign:
                return self._encrypt(_sjwt, recv, cty="json", zip=self.zip)

            return self._encrypt(_sjwt, recv, zip=self.zip)
        else:
            return _sjwt

    def _verify(self, rj, token):
        """
        Verify a signed JSON Web Token

        :param rj: A :py:class:`cryptojwt.jws.JWS` instance
        :param token: The signed JSON Web Token
        :return: A verified message
        """
        keys = self.key_jar.get_jwt_verify_keys(rj.jwt)
        return rj.verify_compact(token, keys)

    def _decrypt(self, rj, token):
        """
        Decrypt an encrypted JsonWebToken

        :param rj: :py:class:`cryptojwt.jwe.JWE` instance
        :param token: The encrypted JsonWebToken
        :return:
        """
        if self.iss:
            keys = self.key_jar.get_jwt_decrypt_keys(rj.jwt, aud=self.iss)
        else:
            keys = self.key_jar.get_jwt_decrypt_keys(rj.jwt)
        return rj.decrypt(token, keys=keys)

    @staticmethod
    def verify_profile(msg_cls, info, **kwargs):
        """
        If a message type is known for this JSON document. Verify that the
        document complies with the message specifications.

        :param msg_cls: The message class. A
            :py:class:`oidcmsg.message.Message` instance
        :param info: The information in the JSON document as a dictionary
        :param kwargs: Extra keyword arguments used when doing the verification.
        :return: The verified message as a msg_cls instance.
        """
        _msg = msg_cls(**info)
        if not _msg.verify(**kwargs):
            raise VerificationError()
        return _msg

    def unpack(self, token):
        """
        Unpack a received signed or signed and encrypted Json Web Token

        :param token: The Json Web Token
        :return: If decryption and signature verification work the payload
            will be returned as a Message instance if possible.
        """
        if not token:
            raise KeyError

        _jwe_header = _jws_header = None

        # Check if it's an encrypted JWT
        darg = {}
        if self.allowed_enc_encs:
            darg["enc"] = self.allowed_enc_encs
        if self.allowed_enc_algs:
            darg["alg"] = self.allowed_enc_algs
        try:
            _decryptor = jwe_factory(token, **darg)
        except (KeyError, HeaderError):
            _decryptor = None

        if _decryptor:
            # Yes, try to decode
            _info = self._decrypt(_decryptor, token)
            _jwe_header = _decryptor.jwt.headers
            # Try to find out if the information encrypted was a signed JWT
            try:
                _content_type = _decryptor.jwt.headers["cty"]
            except KeyError:
                _content_type = ""
        else:
            _content_type = "jwt"
            _info = token

        # If I have reason to believe the information I have is a signed JWT
        if _content_type.lower() == "jwt":
            # Check that is a signed JWT
            if self.allowed_sign_algs:
                _verifier = jws_factory(_info, alg=self.allowed_sign_algs)
            else:
                _verifier = jws_factory(_info)

            if _verifier:
                _info = self._verify(_verifier, _info)
            else:
                raise Exception()
            _jws_header = _verifier.jwt.headers
        else:
            # So, not a signed JWT
            try:
                # A JSON document ?
                _info = json.loads(_info)
            except JSONDecodeError:  # Oh, no ! Not JSON
                return _info
            except TypeError:
                try:
                    _info = as_unicode(_info)
                    _info = json.loads(_info)
                except JSONDecodeError:  # Oh, no ! Not JSON
                    return _info

        # If I know what message class the info should be mapped into
        if self.msg_cls:
            _msg_cls = self.msg_cls
        else:
            try:
                # try to find a issuer specific message class
                _msg_cls = self.iss2msg_cls[_info["iss"]]
            except KeyError:
                _msg_cls = None

        if _msg_cls:
            vp_args = {"skew": self.skew}
            if self.iss:
                vp_args["aud"] = self.iss
            _info = self.verify_profile(_msg_cls, _info, **vp_args)
            _info.jwe_header = _jwe_header
            _info.jws_header = _jws_header
            return _info
        else:
            return _info


def remove_jwt_parameters(arg):
    """
    :param arg: A dictionary like object

    :return: The incoming arg with Jason Web Token parameters removed
    """

    for param in JWT.jwt_parameters:
        try:
            del arg[param]
        except KeyError:
            pass

    return arg
