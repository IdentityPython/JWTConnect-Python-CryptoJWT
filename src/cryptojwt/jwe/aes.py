import os
from struct import pack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.padding import PKCS7

from ..exception import MissingKey
from ..exception import Unsupported
from ..exception import VerificationError
from . import Encrypter
from .exception import UnsupportedBitLength
from .utils import get_keys_seclen_dgst


class AES_CBCEncrypter(Encrypter):
    """"""

    def __init__(self, key_len=32, key=None, msg_padding="PKCS7"):
        Encrypter.__init__(self)
        if key:
            self.key = key
        else:
            self.key = os.urandom(key_len)

        if msg_padding == "PKCS7":
            self.padder = PKCS7(128).padder()
            self.unpadder = PKCS7(128).unpadder()
        else:
            raise Unsupported("Message padding: {}".format(msg_padding))

        self.iv = None

    def _mac(self, hash_key, hash_func, auth_data, iv, enc_msg, key_len):
        al = pack("!Q", 8 * len(auth_data))
        h = hmac.HMAC(hash_key, hash_func(), backend=default_backend())
        h.update(auth_data)
        h.update(iv)
        h.update(enc_msg)
        h.update(al)
        m = h.finalize()
        return m[:key_len]

    def encrypt(self, msg, iv="", auth_data=b""):
        if not iv:
            iv = os.urandom(16)
            self.iv = iv
        else:
            self.iv = iv

        hash_key, enc_key, key_len, hash_func = get_keys_seclen_dgst(self.key, iv)

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pmsg = self.padder.update(msg)
        pmsg += self.padder.finalize()
        ct = encryptor.update(pmsg)
        ct += encryptor.finalize()
        tag = self._mac(hash_key, hash_func, auth_data, iv, ct, key_len)
        return ct, tag

    def decrypt(self, msg, iv="", auth_data=b"", tag=b"", key=None):
        if key is None:
            if self.key:
                key = self.key
            else:
                raise MissingKey("No available key")

        hash_key, enc_key, key_len, hash_func = get_keys_seclen_dgst(key, iv)

        comp_tag = self._mac(hash_key, hash_func, auth_data, iv, msg, key_len)
        if comp_tag != tag:
            raise VerificationError("AES-CBC HMAC")

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        ctext = decryptor.update(msg)
        ctext += decryptor.finalize()
        unpad = self.unpadder.update(ctext)
        unpad += self.unpadder.finalize()
        return unpad


class AES_GCMEncrypter(Encrypter):
    def __init__(self, bit_length=0, key=None):
        Encrypter.__init__(self)
        if key:
            self.key = AESGCM(key)
        elif bit_length:
            if bit_length not in [128, 192, 256]:
                raise UnsupportedBitLength(bit_length)

            self.key = AESGCM(AESGCM.generate_key(bit_length=bit_length))
        else:
            raise ValueError("Need key or key bit length")

    def encrypt(self, msg, iv="", auth_data=None):
        """
        Encrypts and authenticates the data provided as well as authenticating
        the associated_data.

        :param msg: The message to be encrypted
        :param iv: MUST be present, at least 96-bit long
        :param auth_data: Associated data
        :return: The cipher text bytes with the 16 byte tag appended.
        """
        if not iv:
            raise ValueError("Missing Nonce")

        return self.key.encrypt(iv, msg, auth_data)

    def decrypt(self, cipher_text, iv="", auth_data=None, tag=b""):
        """
        Decrypts the data and authenticates the associated_data (if provided).

        :param cipher_text: The data to decrypt including tag
        :param iv: Initialization Vector
        :param auth_data: Associated data
        :param tag: Authentication tag
        :return: The original plaintext
        """
        if not iv:
            raise ValueError("Missing Nonce")

        return self.key.decrypt(iv, cipher_text + tag, auth_data)
