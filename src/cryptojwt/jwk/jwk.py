import copy

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_dmp1
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_dmq1
from cryptography.hazmat.primitives.asymmetric.rsa import rsa_crt_iqmp

from ..exception import MissingValue
from ..exception import WrongKeyType
from ..exception import UnknownKeyType
from ..exception import UnsupportedAlgorithm
from ..utils import base64url_to_long, b64d, as_bytes

from .ec import ECKey
from .ec import NIST2SEC
from .rsa import RSAKey
from .hmac import SYMKey


def key_from_jwk_dict(jwk_dict):
    """Load JWK from dictionary

    :param jwk_dict: Dictionary representing a JWK
    """

    # uncouple from the original item
    _jwk_dict = copy.copy(jwk_dict)

    if _jwk_dict['kty'] == 'EC':
        if _jwk_dict["crv"] in NIST2SEC:
            curve = NIST2SEC[_jwk_dict["crv"]]()
        else:
            raise UnsupportedAlgorithm(
                "Unknown curve: %s" % (_jwk_dict["crv"]))

        if _jwk_dict.get("d", None) is not None:
            # Ecdsa private key.
            _jwk_dict['priv_key'] = ec.derive_private_key(
                base64url_to_long(_jwk_dict["d"]), curve,
                backends.default_backend())
            _jwk_dict['pub_key'] = _jwk_dict['priv_key'].public_key()
        else:
            # Ecdsa public key.
            ec_pub_numbers = ec.EllipticCurvePublicNumbers(
                base64url_to_long(_jwk_dict["x"]),
                base64url_to_long(_jwk_dict["y"]), curve)
            _jwk_dict['pub_key'] = ec_pub_numbers.public_key(
                backends.default_backend())
        return ECKey(**_jwk_dict)
    elif _jwk_dict['kty'] == 'RSA':
        rsa_pub_numbers = rsa.RSAPublicNumbers(
            base64url_to_long(_jwk_dict["e"]),
            base64url_to_long(_jwk_dict["n"]))
        if _jwk_dict.get("p", None) is not None:
            # Rsa private key. These MUST be present
            p_long = base64url_to_long(_jwk_dict["p"])
            q_long = base64url_to_long(_jwk_dict["q"])
            d_long = base64url_to_long(_jwk_dict["d"])
            # If not present these can be calculated from the others
            if 'dp' not in _jwk_dict:
                dp_long = rsa_crt_dmp1(d_long, p_long)
            else:
                dp_long = base64url_to_long(_jwk_dict["dp"])
            if 'dq' not in _jwk_dict:
                dq_long = rsa_crt_dmq1(d_long, q_long)
            else:
                dq_long = base64url_to_long(_jwk_dict["dq"])
            if 'qi' not in _jwk_dict:
                qi_long = rsa_crt_iqmp(p_long, q_long)
            else:
                qi_long = base64url_to_long(_jwk_dict["qi"])

            rsa_priv_numbers = rsa.RSAPrivateNumbers(
                p_long, q_long, d_long,
                dp_long, dq_long, qi_long, rsa_pub_numbers)
            _jwk_dict['priv_key'] = rsa_priv_numbers.private_key(
                backends.default_backend())
            _jwk_dict['pub_key'] = _jwk_dict['priv_key'].public_key()
        else:
            _jwk_dict['pub_key'] = rsa_pub_numbers.public_key(
                backends.default_backend())
            
        if _jwk_dict['kty'] != "RSA":
            raise WrongKeyType('"{}" should have been "RSA"'.format(_jwk_dict[
                                                                        'kty']))
        return RSAKey(**_jwk_dict)
    elif _jwk_dict['kty'] == 'oct':
        if not 'key' in _jwk_dict and not 'k' in _jwk_dict:
            raise MissingValue(
                'There has to be one of "k" or "key" in a symmetric key')

        return SYMKey(**_jwk_dict)
    else:
        raise UnknownKeyType


def jwk_wrap(key, use="", kid=""):
    """
    Instantiate a Key instance with the given key

    :param key: The keys to wrap
    :param use: What the key are expected to be use for
    :param kid: A key id
    :return: The Key instance
    """
    if isinstance(key, rsa.RSAPublicKey) or isinstance(key, rsa.RSAPrivateKey):
        kspec = RSAKey(use=use, kid=kid).load_key(key)
    elif isinstance(key, str):
        kspec = SYMKey(key=key, use=use, kid=kid)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        kspec = ECKey(use=use, kid=kid).load_key(key)
    else:
        raise Exception("Unknown key type:key=" + str(type(key)))

    kspec.serialize()
    return kspec

