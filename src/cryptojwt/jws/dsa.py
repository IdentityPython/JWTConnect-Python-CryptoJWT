from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.utils import int_from_bytes
from cryptography.utils import int_to_bytes

from . import Signer

from ..exception import UnSupported, UnsupportedAlgorithm
from ..exception import BadSignature


class ECDSASigner(Signer):
    def __init__(self, algorithm='ES256'):
        if algorithm == 'ES256':
            self.hash_algorithm = hashes.SHA256
            self.curve_name = "secp256r1"
        elif algorithm == 'ES384':
            self.hash_algorithm = hashes.SHA384
            self.curve_name = "secp384r1"
        elif algorithm == 'ES512':
            self.hash_algorithm = hashes.SHA512
            self.curve_name = "secp521r1"
        else:
            raise UnSupported('algorithm: {}'.format(algorithm))

        self.algorithm = algorithm

    def sign(self, msg, key):
        # cryptography returns ASN.1-encoded signature data; decode as JWS
        # uses raw signatures (r||s)

        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise TypeError(
                "The private key must be an instance of "
                "ec.EllipticCurvePrivateKey")

        self._cross_check(key.public_key())

        asn1sig = key.sign(msg, ec.ECDSA(self.hash_algorithm()))
        (r, s) = decode_dss_signature(asn1sig)
        return int_to_bytes(r) + int_to_bytes(s)

    def verify(self, msg, sig, key):
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise TypeError(
                "The public key must be an instance of "
                "ec.EllipticCurvePublicKey")
        self._cross_check(key)

        try:
            # cryptography uses ASN.1-encoded signature data; split JWS
            # signature (r||s) and encode before verification
            (r, s) = self._split_raw_signature(sig)
            asn1sig = encode_dss_signature(r, s)
            key.verify(asn1sig, msg, ec.ECDSA(self.hash_algorithm()))
        except InvalidSignature as err:
            raise BadSignature(err)
        else:
            return True

    def _cross_check(self, pub_key):
        """
        In Ecdsa, both the key and the algorithm define the curve.
        Therefore, we must cross check them to make sure they're the same.
        :param key:
        :return:
        """
        if self.curve_name != pub_key.curve.name:
            raise ValueError(
                "The curve in private key {} and in algorithm {} don't "
                "match".format(pub_key.curve.name, self.curve_name))

    @staticmethod
    def _split_raw_signature(sig):
        """Split raw signature into components"""
        c_length = len(sig) // 2
        r = int_from_bytes(sig[:c_length], byteorder='big')
        s = int_from_bytes(sig[c_length:], byteorder='big')
        return (r, s)
