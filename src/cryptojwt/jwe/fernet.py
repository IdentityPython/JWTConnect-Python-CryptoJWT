import base64
import os
from typing import Optional
from typing import Union

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptojwt.jwe import Encrypter
from cryptojwt.utils import as_bytes

DEFAULT_ITERATIONS = 390000


class FernetEncrypter(Encrypter):
    def __init__(
        self,
        password: Optional[str] = None,
        salt: Optional[bytes] = "",
        key: Optional[bytes] = None,
        hash_alg: Optional[str] = "SHA256",
        digest_size: Optional[int] = 0,
        iterations: Optional[int] = DEFAULT_ITERATIONS,
    ):
        Encrypter.__init__(self)

        if key is not None:
            if not isinstance(key, bytes):
                raise TypeError("Raw key must be bytes")
            if len(key) != 32:
                raise ValueError("Raw key must be 32 bytes")
            self.key = base64.urlsafe_b64encode(key)
        elif password is not None:
            _alg = getattr(hashes, hash_alg)
            # A bit special for SHAKE* and BLAKE* hashes
            if hash_alg.startswith("SHAKE") or hash_alg.startswith("BLAKE"):
                _algorithm = _alg(digest_size)
            else:
                _algorithm = _alg()
            salt = as_bytes(salt) if salt else os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=_algorithm, length=32, salt=salt, iterations=iterations)
            self.key = base64.urlsafe_b64encode(kdf.derive(as_bytes(password)))
        else:
            self.key = Fernet.generate_key()

        self.core = Fernet(self.key)

    def encrypt(self, msg: Union[str, bytes], **kwargs) -> bytes:
        text = as_bytes(msg)
        # Padding to block size of AES
        if len(text) % 16:
            text += b" " * (16 - len(text) % 16)
        return self.core.encrypt(as_bytes(text))

    def decrypt(self, msg: Union[str, bytes], **kwargs) -> bytes:
        dec_text = self.core.decrypt(as_bytes(msg))
        dec_text = dec_text.rstrip(b" ")
        return dec_text
