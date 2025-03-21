from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ..exception import BadSignature, Unsupported
from . import Signer


class ECDSASigner(Signer):
    def __init__(self, algorithm="ES256"):
        if algorithm == "ES256":
            self.hash_algorithm = hashes.SHA256
            self.curve_name = "secp256r1"
        elif algorithm == "ES256K":
            self.hash_algorithm = hashes.SHA256
            self.curve_name = "secp256k1"
        elif algorithm == "ES384":
            self.hash_algorithm = hashes.SHA384
            self.curve_name = "secp384r1"
        elif algorithm == "ES512":
            self.hash_algorithm = hashes.SHA512
            self.curve_name = "secp521r1"
        else:
            raise Unsupported(f"algorithm: {algorithm}")

        self.algorithm = algorithm

    def sign(self, msg, key):
        """
        Create a signature over a message as defined in RFC7515 using an
        Elliptic curve key

        :param msg: The message
        :param key: An ec.EllipticCurvePrivateKey instance
        :return:
        """

        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError("The private key must be an instance of ec.EllipticCurvePrivateKey")

        self._cross_check(key.public_key())
        num_bits = key.curve.key_size
        num_bytes = (num_bits + 7) // 8
        asn1sig = key.sign(msg, ec.ECDSA(self.hash_algorithm()))
        # Cryptography returns ASN.1-encoded signature data; decode as JWS
        # uses raw signatures (r||s)
        (r, s) = decode_dss_signature(asn1sig)
        return int.to_bytes(r, num_bytes, "big") + int.to_bytes(s, num_bytes, "big")

    def verify(self, msg, sig, key):
        """
        Verify a message signature

        :param msg: The message
        :param sig: A signature
        :param key: A ec.EllipticCurvePublicKey to use for the verification.
        :raises: BadSignature if the signature can't be verified.
        :return: True
        """
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError("The public key must be an instance of ec.EllipticCurvePublicKey")
        self._cross_check(key)

        num_bits = key.curve.key_size
        num_bytes = (num_bits + 7) // 8
        if len(sig) != 2 * num_bytes:
            raise ValueError("Invalid signature")

        try:
            # cryptography uses ASN.1-encoded signature data; split JWS
            # signature (r||s) and encode before verification
            (r, s) = self._split_raw_signature(sig)
            asn1sig = encode_dss_signature(r, s)
            key.verify(asn1sig, msg, ec.ECDSA(self.hash_algorithm()))
        except InvalidSignature as exc:
            raise BadSignature(exc) from exc
        else:
            return True

    def _cross_check(self, pub_key):
        """
        In Ecdsa, both the key and the algorithm define the curve.
        Therefore, we must crosscheck them to make sure they're the same.

        :param key:
        :raises: ValueError is the curves are not the same
        """
        if self.curve_name != pub_key.curve.name:
            raise ValueError(
                f"The curve in private key {pub_key.curve.name} and in algorithm {self.curve_name} don't "
                "match"
            )

    @staticmethod
    def _split_raw_signature(sig):
        """
        Split raw signature into components

        :param sig: The signature
        :return: A 2-tuple
        """
        c_length = len(sig) // 2
        r = int.from_bytes(sig[:c_length], byteorder="big")
        s = int.from_bytes(sig[c_length:], byteorder="big")
        return r, s
