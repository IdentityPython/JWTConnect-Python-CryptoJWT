from ..jwx import JWx
from . import KEY_LEN_BYTES
from .aes import AES_CBCEncrypter
from .aes import AES_GCMEncrypter
from .exception import DecryptionFailed
from .exception import NotSupportedAlgorithm
from .utils import alg2keytype
from .utils import get_random_bytes
from .utils import split_ctx_and_tag


class JWEKey(JWx):
    @staticmethod
    def _generate_iv(encalg, iv=""):
        if iv:
            return iv
        else:
            _iv = get_random_bytes(16)

        return _iv

    @staticmethod
    def _generate_key(encalg, cek=""):
        if cek:
            return cek

        try:
            _key = get_random_bytes(KEY_LEN_BYTES[encalg])
        except KeyError:
            try:
                _key = get_random_bytes(KEY_LEN_BYTES[encalg])
            except KeyError:
                raise ValueError("Unsupported encryption algorithm %s" % encalg)

        return _key

    def alg2keytype(self, alg):
        return alg2keytype(alg)

    def enc_setup(self, enc_alg, msg, auth_data=b"", key=None, iv=""):
        """Encrypt JWE content.

        :param enc_alg: The JWE "enc" value specifying the encryption algorithm
        :param msg: The plain text message
        :param auth_data: Additional authenticated data
        :param key: Key (CEK)
        :return: Tuple (ciphertext, tag), both as bytes
        """

        iv = self._generate_iv(enc_alg, iv)

        if enc_alg in ["A192GCM", "A128GCM", "A256GCM"]:
            aes = AES_GCMEncrypter(key=key)
            ctx, tag = split_ctx_and_tag(aes.encrypt(msg, iv, auth_data))
        elif enc_alg in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
            aes = AES_CBCEncrypter(key=key)
            ctx, tag = aes.encrypt(msg, iv, auth_data)
        else:
            raise NotSupportedAlgorithm(enc_alg)

        return ctx, tag, aes.key

    @staticmethod
    def _decrypt(enc, key, ctxt, iv, tag, auth_data=b""):
        """Decrypt JWE content.

        :param enc: The JWE "enc" value specifying the encryption algorithm
        :param key: Key (CEK)
        :param iv : Initialization vector
        :param auth_data: Additional authenticated data (AAD)
        :param ctxt : Ciphertext
        :param tag: Authentication tag
        :return: plain text message or None if decryption failed
        """
        if enc in ["A128GCM", "A192GCM", "A256GCM"]:
            aes = AES_GCMEncrypter(key=key)
        elif enc in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
            aes = AES_CBCEncrypter(key=key)
        else:
            raise Exception("Unsupported encryption algorithm %s" % enc)

        try:
            return aes.decrypt(ctxt, iv=iv, auth_data=auth_data, tag=tag)
        except DecryptionFailed:
            raise
