import logging

from ..jwk.asym import AsymmetricKey
from ..jwk.ec import ECKey
from ..jwk.hmac import SYMKey
from ..jwk.jwk import key_from_jwk_dict
from ..jwk.rsa import RSAKey
from ..jwx import JWx
from .exception import DecryptionFailed
from .exception import NoSuitableDecryptionKey
from .exception import NoSuitableECDHKey
from .exception import NoSuitableEncryptionKey
from .exception import NotSupportedAlgorithm
from .exception import WrongEncryptionAlgorithm
from .jwe_ec import JWE_EC
from .jwe_hmac import JWE_SYM
from .jwe_rsa import JWE_RSA
from .jwenc import JWEnc
from .utils import alg2keytype

logger = logging.getLogger(__name__)

__author__ = "Roland Hedberg"


KEY_ERR = "Could not find any suitable encryption key for alg='{}'"


class JWE(JWx):
    args = [
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

    """
    :param msg: The message
    :param alg: Algorithm
    :param enc: Encryption Method
    :param epk: Ephemeral Public Key
    :param zip: Compression Algorithm
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
    :param kid: Key ID a hint indicating which key was used to secure the
        JWS.
    :param typ: the type of this object. 'JWS' == JWS Compact Serialization
        'JWS+JSON' == JWS JSON Serialization
    :param cty: Content Type
    :param apu: Agreement PartyUInfo
    :param crit: indicates which extensions that are being used and MUST
        be understood and processed.
    :return: A class instance
    """

    def encrypt(self, keys=None, cek="", iv="", **kwargs):
        """
        Encrypt a payload.

        :param keys: A set of possibly usable keys
        :param cek: Content master key
        :param iv: Initialization vector
        :param kwargs: Extra key word arguments
        :return: Encrypted message
        """

        _alg = self["alg"]

        # Find Usable Keys
        if keys:
            keys = self.pick_keys(keys, use="enc")
        else:
            keys = self.pick_keys(self._get_keys(), use="enc")

        if not keys:
            logger.error(KEY_ERR.format(_alg))
            raise NoSuitableEncryptionKey(_alg)

        # Determine Encryption Class by Algorithm
        if _alg in ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]:
            encrypter = JWE_RSA(self.msg, **self._dict)
        elif _alg.startswith("A") and _alg.endswith("KW"):
            encrypter = JWE_SYM(self.msg, **self._dict)
        else:  # _alg.startswith("ECDH-ES"):
            encrypter = JWE_EC(**self._dict)
            cek, encrypted_key, iv, params, eprivk = encrypter.enc_setup(
                self.msg, key=keys[0], **self._dict
            )
            kwargs["encrypted_key"] = encrypted_key
            kwargs["params"] = params

        if cek:
            kwargs["cek"] = cek

        if iv:
            kwargs["iv"] = iv

        for key in keys:
            if isinstance(key, SYMKey):
                _key = key.key
            elif isinstance(key, ECKey):
                _key = key.public_key()
            else:  # isinstance(key, RSAKey):
                _key = key.public_key()

            if key.kid:
                encrypter["kid"] = key.kid

            try:
                token = encrypter.encrypt(key=_key, **kwargs)
                self["cek"] = encrypter.cek if "cek" in encrypter else None
            except TypeError as err:
                raise err
            else:
                logger.debug("Encrypted message using key with kid={}".format(key.kid))
                return token

        # logger.error("Could not find any suitable encryption key")
        # raise NoSuitableEncryptionKey()

    def decrypt(self, token=None, keys=None, alg=None, cek=None):
        if token:
            _jwe = JWEnc().unpack(token)
            # header, ek, eiv, ctxt, tag = token.split(b".")
            # self.parse_header(header)
        elif self.jwt:
            _jwe = self.jwt
        else:
            raise ValueError("Nothing to decrypt")

        _alg = _jwe.headers["alg"]
        if alg and alg != _alg:
            raise WrongEncryptionAlgorithm()

        # Find appropriate keys
        if keys:
            keys = self.pick_keys(keys, use="enc", alg=_alg)
        else:
            keys = self.pick_keys(self._get_keys(), use="enc", alg=_alg)

        try:
            keys.append(key_from_jwk_dict(_jwe.headers["jwk"]))
        except KeyError:
            pass

        if not keys and not cek:
            raise NoSuitableDecryptionKey(_alg)

        if _alg in ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]:
            decrypter = JWE_RSA(**self._dict)
        elif _alg.startswith("A") and _alg.endswith("KW"):
            decrypter = JWE_SYM(self.msg, **self._dict)
        elif _alg.startswith("ECDH-ES"):
            decrypter = JWE_EC(**self._dict)

            if isinstance(keys[0], AsymmetricKey):
                _key = keys[0].private_key()
            else:
                _key = keys[0].key

            cek = decrypter.dec_setup(_jwe, key=_key)
        else:
            raise NotSupportedAlgorithm

        if cek:
            try:
                msg = decrypter.decrypt(_jwe, cek=cek)
                self["cek"] = decrypter.cek if "cek" in decrypter else None
            except (KeyError, DecryptionFailed):
                pass
            else:
                logger.debug("Decrypted message using exiting CEK")
                return msg

        for key in keys:
            if isinstance(key, AsymmetricKey):
                _key = key.private_key()
            else:
                _key = key.key

            try:
                msg = decrypter.decrypt(_jwe, _key)
                self["cek"] = decrypter.cek if "cek" in decrypter else None
            except (KeyError, DecryptionFailed):
                pass
            else:
                logger.debug("Decrypted message using key with kid=%s" % key.kid)
                return msg

        raise DecryptionFailed("No available key that could decrypt the message")

    def alg2keytype(self, alg):
        return alg2keytype(alg)


def factory(token, alg="", enc=""):
    try:
        _jwt = JWEnc().unpack(token, alg=alg, enc=enc)
    except KeyError:
        return None

    if _jwt.is_jwe():
        _jwe = JWE()
        _jwe.jwt = _jwt
        return _jwe
    else:
        return None
