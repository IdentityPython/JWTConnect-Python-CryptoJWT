import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend

from . import Signer

from ..exception import UnSupported
from ..exception import BadSignature
from ..utils import safe_str_cmp
from ..utils import constant_time_compare


class HMACSigner(Signer):
    def __init__(self, algorithm='SHA256'):
        if algorithm == 'SHA256':
            self.algorithm = hashes.SHA256
        elif algorithm == 'SHA384':
            self.algorithm = hashes.SHA384
        elif algorithm == 'SHA512':
            self.algorithm = hashes.SHA512
        else:
            raise UnSupported('algorithm: {}'.format(algorithm))

    def sign(self, msg, key):
        h = hmac.HMAC(key, self.algorithm(), default_backend())
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
            h = hmac.HMAC(key, self.algorithm(), default_backend())
            h.update(msg)
            h.verify(sig)
            return True
        except:
            return False


