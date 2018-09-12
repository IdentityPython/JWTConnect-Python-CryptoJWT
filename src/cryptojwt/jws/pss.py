import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

from . import Signer

from ..exception import UnSupported
from ..exception import BadSignature

logger = logging.getLogger(__name__)


class PSSSigner(Signer):
    def __init__(self, algorithm='SHA256'):
        if algorithm == 'SHA256':
            self.hash_algorithm = hashes.SHA256
        elif algorithm == 'SHA384':
            self.hash_algorithm = hashes.SHA384
        elif algorithm == 'SHA512':
            self.hash_algorithm = hashes.SHA512
        else:
            raise UnSupported('algorithm: {}'.format(algorithm))

    def sign(self, msg, key):
        hasher = hashes.Hash(self.hash_algorithm(), backend=default_backend())
        hasher.update(msg)
        digest = hasher.finalize()
        sig = key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm()),
                salt_length=padding.PSS.MAX_LENGTH),
            utils.Prehashed(self.hash_algorithm()))
        return sig

    def verify(self, msg, signature, key):
        try:
            key.verify(signature, msg,
                       padding.PSS(mgf=padding.MGF1(self.hash_algorithm()),
                                   salt_length=padding.PSS.MAX_LENGTH),
                       self.hash_algorithm())
        except InvalidSignature as err:
            raise BadSignature(err)
        else:
            return True
