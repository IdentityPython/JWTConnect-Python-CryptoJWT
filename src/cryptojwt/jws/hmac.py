from cryptography.hazmat.primitives import hashes, hmac

from ..exception import Unsupported
from . import Signer


class HMACSigner(Signer):
    def __init__(self, algorithm="SHA256"):
        if algorithm == "SHA256":
            self.algorithm = hashes.SHA256
        elif algorithm == "SHA384":
            self.algorithm = hashes.SHA384
        elif algorithm == "SHA512":
            self.algorithm = hashes.SHA512
        else:
            raise Unsupported(f"algorithm: {algorithm}")

    def sign(self, msg, key):
        """
        Create a signature over a message as defined in RFC7515 using a
        symmetric key

        :param msg: The message
        :param key: The key
        :return: A signature
        """
        h = hmac.HMAC(key, self.algorithm())
        h.update(msg)
        return h.finalize()

    def verify(self, msg, sig, key):
        """
        Verifies whether sig is the correct message authentication code of data.

        :param msg: The data
        :param sig: The message authentication code to verify against data.
        :param key: The key to use
        :return: Returns true if the mac was valid otherwise it will raise an
            Exception.
        """
        try:
            h = hmac.HMAC(key, self.algorithm())
            h.update(msg)
            h.verify(sig)
            return True
        except Exception:
            return False
