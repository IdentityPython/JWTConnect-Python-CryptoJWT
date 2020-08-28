import logging
import zlib

from ..utils import as_bytes
from . import SUPPORTED
from .exception import NotSupportedAlgorithm
from .exception import ParameterError
from .jwekey import JWEKey
from .jwenc import JWEnc
from .rsa import RSAEncrypter

logger = logging.getLogger(__name__)

__author__ = "Roland Hedberg"


class JWE_RSA(JWEKey):
    args = [
        "msg",
        "alg",
        "enc",
        "epk",
        "zip",
        "jku",
        "jwk",
        "x5u",
        "x5t",
        "x5c",
        "kid",
        "typ",
        "cty",
        "apu",
        "crit",
    ]

    def encrypt(self, key, iv="", cek="", **kwargs):
        """
        Produces a JWE as defined in RFC7516 using RSA algorithms

        :param key: RSA key
        :param iv: Initialization vector
        :param cek: Content master key
        :param kwargs: Extra keyword arguments
        :return: A signed payload
        """

        _msg = as_bytes(self.msg)
        if "zip" in self:
            if self["zip"] == "DEF":
                _msg = zlib.compress(_msg)
            else:
                raise ParameterError("Zip has unknown value: %s" % self["zip"])

        kwarg_cek = cek or None

        _enc = self["enc"]
        iv = self._generate_iv(_enc, iv)
        cek = self._generate_key(_enc, cek)
        self["cek"] = cek

        logger.debug("cek: %s, iv: %s" % ([c for c in cek], [c for c in iv]))

        _encrypt = RSAEncrypter(self.with_digest).encrypt

        _alg = self["alg"]
        if kwarg_cek:
            jwe_enc_key = ""
        elif _alg == "RSA-OAEP":
            jwe_enc_key = _encrypt(cek, key, "pkcs1_oaep_padding")
        elif _alg == "RSA-OAEP-256":
            jwe_enc_key = _encrypt(cek, key, "pkcs1_oaep_256_padding")
        elif _alg == "RSA1_5":
            jwe_enc_key = _encrypt(cek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        jwe = JWEnc(**self.headers())

        try:
            _auth_data = kwargs["auth_data"]
        except KeyError:
            _auth_data = jwe.b64_encode_header()

        ctxt, tag, key = self.enc_setup(_enc, _msg, key=cek, iv=iv, auth_data=_auth_data)
        return jwe.pack(parts=[jwe_enc_key, iv, ctxt, tag])

    def decrypt(self, token, key, cek=None):
        """Decrypts a JWT

        :param token: The JWT
        :param key: A key to use for decrypting
        :param cek: Ephemeral cipher key
        :return: The decrypted message
        """
        if not isinstance(token, JWEnc):
            jwe = JWEnc().unpack(token)
        else:
            jwe = token

        self.jwt = jwe.encrypted_key()
        jek = jwe.encrypted_key()

        _decrypt = RSAEncrypter(self.with_digest).decrypt

        _alg = jwe.headers["alg"]
        if cek:
            pass
        elif _alg == "RSA-OAEP":
            cek = _decrypt(jek, key, "pkcs1_oaep_padding")
        elif _alg == "RSA-OAEP-256":
            cek = _decrypt(jek, key, "pkcs1_oaep_256_padding")
        elif _alg == "RSA1_5":
            cek = _decrypt(jek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        self["cek"] = cek
        enc = jwe.headers["enc"]
        if enc not in SUPPORTED["enc"]:
            raise NotSupportedAlgorithm(enc)

        auth_data = jwe.b64_protected_header()

        msg = self._decrypt(
            enc,
            cek,
            jwe.ciphertext(),
            auth_data=auth_data,
            iv=jwe.initialization_vector(),
            tag=jwe.authentication_tag(),
        )

        if "zip" in jwe.headers and jwe.headers["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg
