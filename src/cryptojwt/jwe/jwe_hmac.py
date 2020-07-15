import logging
import zlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from ..exception import MissingKey
from ..exception import WrongNumberOfParts
from ..jwk.hmac import SYMKey
from ..utils import as_bytes
from ..utils import intarr2str
from .jwekey import JWEKey
from .jwenc import JWEnc

logger = logging.getLogger(__name__)

__author__ = "Roland Hedberg"


class JWE_SYM(JWEKey):
    args = JWEKey.args[:]
    args.append("enc")

    def encrypt(self, key, iv="", cek="", **kwargs):
        """
        Produces a JWE as defined in RFC7516 using symmetric keys

        :param key: Shared symmetric key
        :param iv: Initialization vector
        :param cek: Content master key
        :param kwargs: Extra keyword arguments, just ignore for now.
        :return:
        """
        _msg = as_bytes(self.msg)

        _args = self._dict
        try:
            _args["kid"] = kwargs["kid"]
        except KeyError:
            pass

        jwe = JWEnc(**_args)

        # If no iv and cek are given generate them
        iv = self._generate_iv(self["enc"], iv)
        cek = self._generate_key(self["enc"], cek)
        if isinstance(key, SYMKey):
            try:
                kek = key.key.encode("utf8")
            except AttributeError:
                kek = key.key
        elif isinstance(key, bytes):
            kek = key
        else:
            kek = intarr2str(key)

        # The iv for this function must be 64 bit
        # Which is certainly different from the one above
        jek = aes_key_wrap(kek, cek, default_backend())

        _enc = self["enc"]
        _auth_data = jwe.b64_encode_header()
        ctxt, tag, cek = self.enc_setup(_enc, _msg, auth_data=_auth_data, key=cek, iv=iv)
        return jwe.pack(parts=[jek, iv, ctxt, tag])

    def decrypt(self, token, key=None, cek=None):
        logger.debug("SYM decrypt")
        if not key and not cek:
            raise MissingKey("On of key or cek must be specified")

        if isinstance(token, JWEnc):
            jwe = token
        else:
            jwe = JWEnc().unpack(token)

        if len(jwe) != 5:
            raise WrongNumberOfParts(len(jwe))

        if not cek:
            jek = jwe.encrypted_key()
            if isinstance(key, SYMKey):
                try:
                    key = key.key.encode("utf8")
                except AttributeError:
                    key = key.key
            # The iv for this function must be 64 bit
            cek = aes_key_unwrap(key, jek, default_backend())

        auth_data = jwe.b64_protected_header()
        msg = self._decrypt(
            jwe.headers["enc"],
            cek,
            jwe.ciphertext(),
            auth_data=auth_data,
            iv=jwe.initialization_vector(),
            tag=jwe.authentication_tag(),
        )

        if "zip" in self and self["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg
