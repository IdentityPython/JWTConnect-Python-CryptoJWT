import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from ..exception import BadSignature, Unsupported
from . import Signer

logger = logging.getLogger(__name__)


class PSSSigner(Signer):
    def __init__(self, algorithm="SHA256"):
        if algorithm == "SHA256":
            self.hash_algorithm = hashes.SHA256
        elif algorithm == "SHA384":
            self.hash_algorithm = hashes.SHA384
        elif algorithm == "SHA512":
            self.hash_algorithm = hashes.SHA512
        else:
            raise Unsupported(f"algorithm: {algorithm}")

    def sign(self, msg, key):
        """
        Create a signature over a message

        :param msg: The message
        :param key: The key
        :return: A signature
        """
        hasher = hashes.Hash(self.hash_algorithm())
        hasher.update(msg)
        digest = hasher.finalize()
        sig = key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(self.hash_algorithm()),
        )
        return sig

    def verify(self, msg, signature, key):
        """
        Verify a message signature

        :param msg: The message
        :param sig: A signature
        :param key: A ec.EllipticCurvePublicKey to use for the verification.
        :raises: BadSignature if the signature can't be verified.
        :return: True
        """
        try:
            key.verify(
                signature,
                msg,
                padding.PSS(
                    mgf=padding.MGF1(self.hash_algorithm()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                self.hash_algorithm(),
            )
        except InvalidSignature as exc:
            raise BadSignature(exc) from exc
        else:
            return True
