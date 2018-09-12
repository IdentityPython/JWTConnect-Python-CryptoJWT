from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from .asym import AsymmetricKey

from ..exception import DeSerializationNotPossible
from ..exception import JWKESTException
from ..exception import SerializationNotPossible
from ..utils import as_unicode
from ..utils import deser
from ..utils import long_to_base64

# This is used to translate between the curve representation in
# Cryptography and the one used by NIST (and in RFC 7518)
NIST2SEC = {
    'K-571': ec.SECT571K1,
    'K-409': ec.SECT409K1,
    'K-283': ec.SECT283K1,
    'K-233': ec.SECT233K1,
    'K-163': ec.SECT163K1,
    'P-521': ec.SECP521R1,
    'P-384': ec.SECP384R1,
    'P-256': ec.SECP256R1,
    'P-224': ec.SECP224R1,
    'P-192': ec.SECP192R1,
    }

SEC2NIST = dict([(s.name, n) for n, s in NIST2SEC.items()])


def ec_construct_public(num):
    ecpn = ec.EllipticCurvePublicNumbers(num['x'], num['y'],
                                         NIST2SEC[as_unicode(num['crv'])]())
    return ecpn.public_key(default_backend())


def ec_construct_private(num):
    pub_ecpn = ec.EllipticCurvePublicNumbers(num['x'], num['y'],
                                             NIST2SEC[as_unicode(num['crv'])]())
    priv_ecpn = ec.EllipticCurvePrivateNumbers(num['d'], pub_ecpn)
    return priv_ecpn.private_key(default_backend())


class ECKey(AsymmetricKey):
    """
    JSON Web key representation of a Elliptic curve key.
    According to RFC 7517 a JWK representation of a EC key can look like
    this::
        {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
        }

    Parameters according to https://tools.ietf.org/html/rfc7518#section-6.2
    """
    members = AsymmetricKey.members[:]
    # The elliptic curve specific attributes
    members.extend(["crv", "x", "y", "d"])
    longs = ['x', 'y', 'd']
    public_members = AsymmetricKey.public_members[:]
    public_members.extend(["kty", "alg", "use", "kid", "crv", "x", "y"])
    required = ['crv', 'key', 'x', 'y']

    def __init__(self, kty="EC", alg="", use="", kid="", key=None,
                 crv="", x="", y="", d="", **kwargs):
        AsymmetricKey.__init__(self, kty, alg, use, kid, key, **kwargs)
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d

        if not self.pub_key and not self.priv_key:
            if self.x and self.y and self.crv:
                self.verify()
                self.deserialize()
            elif any([self.x, self.y, self.crv]):
                raise JWKESTException('Missing required parameter')
        elif self.priv_key and not self.pub_key:
            self.pub_key = self.priv_key.public_key()
            self._serialize(self.priv_key)

    def deserialize(self):
        """
        Starting with information gathered from the on-the-wire representation
        of an elliptic curve key (a JWK) initiate an
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
        or EllipticCurvePrivateKey instance. So we have to get from having::
            {
              "kty":"EC",
              "crv":"P-256",
              "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
            }
        to having a key that can be used for signing/verifying and/or
        encrypting/decrypting.
        If 'd' has value then we're dealing with a private key otherwise
        a public key. 'x' and 'y' must have values.
        If self.key has a value beforehand this will overwrite what ever
        was there to begin with.

        x, y and d (if present) must be strings or bytes.
        """

        if isinstance(self.x, (str, bytes)):
            _x = deser(self.x)
        else:
            raise ValueError('"x" MUST be a string')
        if isinstance(self.y, (str, bytes)):
            _y = deser(self.y)
        else:
            raise ValueError('"y" MUST be a string')

        if self.d:
            try:
                if isinstance(self.d, (str, bytes)):
                    _d = deser(self.d)
                    self.priv_key = ec_construct_private(
                        {'x': _x, 'y': _y, 'crv': self.crv, 'd': _d})
            except ValueError as err:
                raise DeSerializationNotPossible(str(err))
        else:
            self.pub_key = ec_construct_public(
                {'x': _x, 'y': _y, 'crv': self.crv})

    def _serialize(self, key):
        if isinstance(key, ec.EllipticCurvePublicKey):
            pn = key.public_numbers()
            self.x = long_to_base64(pn.x)
            self.y = long_to_base64(pn.y)
            self.crv = SEC2NIST[pn.curve.name]
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            pn = key.private_numbers()
            self.x = long_to_base64(pn.public_numbers.x)
            self.y = long_to_base64(pn.public_numbers.y)
            self.crv = SEC2NIST[pn.public_numbers.curve.name]
            self.d = long_to_base64(pn.private_value)

    def serialize(self, private=False):
        """
        Go from a
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
        or EllipticCurvePublicKey instance to a JWK representation.

        :param private: Whether we should include the private parts or not.
        :return: A JWK as a dictionary
        """
        if self.priv_key:
            self._serialize(self.priv_key)
        else:
            self._serialize(self.pub_key)

        res = self.common()

        res.update({
            # "crv": SEC2NIST[self.crv.name],
            "crv": self.crv,
            "x": self.x,
            "y": self.y
            })

        if private and self.d:
            res["d"] = self.d

        return res

    def load_key(self, key):
        """
        Load an Elliptic curve key

        :param key: An elliptic curve key instance
        :return:
        """
        self._serialize(key)
        if isinstance(key, ec.EllipticCurvePrivateKey):
            self.priv_key = key
            self.pub_key = key.public_key()
        else:
            self.pub_key = key

        return self

    def decryption_key(self):
        return self.get_key(private=True)

    def encryption_key(self, private=False, **kwargs):
        # both for encryption and decryption.
        return self.get_key(private=private)

    def __eq__(self, other):
        """
        Verify that the other key has the same properties as myself.

        :param other: The other key
        :return: True if the keys as the same otherwise False
        """

        if cmp_keys(self.pub_key, other.pub_key, ec.EllipticCurvePublicKey):
            if other.private_key():
                if cmp_keys(self.priv_key, other.priv_key,
                            ec.EllipticCurvePublicKey):
                    return False
            else:
                return True

        return False


def cmp_keys(a, b, key_type):
    if isinstance(a, key_type):
        if isinstance(b, key_type):
            if a.curve != b.curve:
                return False
            if a.key_size != b.key_size:
                return False
            if isinstance(a, ec.EllipticCurvePrivateKey):
                if a.private_numbers() != b.private_numbers():
                    return False
            else:
                if a.public_numbers() != b.public_numbers():
                    return False
            return True

    return False
