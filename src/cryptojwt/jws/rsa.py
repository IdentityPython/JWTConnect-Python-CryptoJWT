from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

from ..exception import BadSignature
from . import Signer
from .utils import parse_rsa_algorithm


class RSASigner(Signer):
    def __init__(self, algorithm="RS256"):
        (self.hash, self.padding) = parse_rsa_algorithm(algorithm)

    def sign(self, msg, key):
        """
        Create a signature over a message as defined in RFC7515 using an
        RSA key

        :param msg: the message.
        :type msg: bytes
        :returns: bytes, the signature of data.
        :rtype: bytes
        """

        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("The key must be an instance of rsa.RSAPrivateKey")
        sig = key.sign(msg, self.padding, self.hash)
        return sig

    def verify(self, msg, signature, key):
        """
        Verifies whether signature is a valid signature for message

        :param msg: the message
        :type msg: bytes
        :param signature: The signature to be verified
        :type signature: bytes
        :param key: The key
        :return: True is the signature is valid otherwise False
        """

        if not isinstance(key, rsa.RSAPublicKey):
            raise TypeError("The public key must be an instance of RSAPublicKey")
        try:
            key.verify(signature, msg, self.padding, self.hash)
        except InvalidSignature as err:
            raise BadSignature(str(err))
        except AttributeError:
            return False
        else:
            return True
