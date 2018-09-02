from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from .utils import parse_rsa_algorithm
from . import Signer

from ..exception import BadSignature


class RSASigner(Signer):
    def __init__(self, algorithm='SHA256'):
        (self.hash, self.padding) = parse_rsa_algorithm(algorithm)

    def sign(self, msg, key):
        """Computes the signature for message.

        :param msg: the message.
        :type msg: bytearray
        :returns: bytes, the signature of data.
        :rtype: bytearray
        """

        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError(
                "The private key must be an instance of rsa.RSAPrivateKey")
        sig = key.sign(msg, self.padding, self.hash)
        return sig

    def verify(self, msg, signature, key):
        """
        Verifies whether signature is a valid signature for message

        :param msg: the message
        :type msg: bytearray
        :param signature: The signature to be verified
        :type signature: bytearray
        :param key: The key
        :return: True is the signature is valid otherwise False
        """

        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError(
                "The public key must be an instance of RSAPublicKey")
        try:
            key.verify(signature, msg, self.padding, self.hash)
        except InvalidSignature as err:
            raise BadSignature(str(err))
        except AttributeError:  # If private key
            return False
        else:
            return True