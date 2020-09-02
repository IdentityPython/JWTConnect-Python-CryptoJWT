import base64
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..exception import DeSerializationNotPossible
from ..exception import JWKESTException
from ..exception import SerializationNotPossible
from ..exception import UnsupportedKeyType
from ..utils import as_unicode
from ..utils import deser
from ..utils import long_to_base64
from . import JWK
from .asym import AsymmetricKey
from .x509 import der_cert
from .x509 import import_private_key_from_pem_file
from .x509 import import_public_key_from_pem_data
from .x509 import import_public_key_from_pem_file
from .x509 import x5t_calculation

logger = logging.getLogger(__name__)

PREFIX = "-----BEGIN CERTIFICATE-----"
POSTFIX = "-----END CERTIFICATE-----"


def generate_and_store_rsa_key(key_size=2048, filename="rsa.key", passphrase=""):
    """
    Generate a private RSA key and store a PEM representation of it in a
    file.

    :param key_size: The size of the key, default 2048 bytes.
    :param filename: The name of the file to which the key should be written
    :param passphrase: If the PEM representation should be protected with a
        pass phrase.
    :return: A
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey instance
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )

    with open(filename, "wb") as keyfile:
        if passphrase:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )
        else:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        keyfile.write(pem)
        keyfile.close()
    return private_key


def import_private_rsa_key_from_file(filename, passphrase=None):
    """
    Read a private RSA key from a PEM file.

    :param filename: The name of the file
    :param passphrase: A pass phrase to use to unpack the PEM file.
    :return: A
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey instance
    """
    private_key = import_private_key_from_pem_file(filename, passphrase)
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key
    else:
        return ValueError("Not a RSA key")


def import_public_rsa_key_from_file(filename):
    """
    Read a public RSA key from a PEM file.

    :param filename: The name of the file
    :param passphrase: A pass phrase to use to unpack the PEM file.
    :return: A cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey instance
    """
    public_key = import_public_key_from_pem_file(filename)
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key
    else:
        return ValueError("Not a RSA key")


def import_rsa_key(pem_data):
    """
    Extract an RSA key from a PEM-encoded X.509 certificate

    :param pem_data: RSA key encoded in standard form
    :return: rsa.RSAPublicKey instance
    """
    public_key = import_public_key_from_pem_data(pem_data)
    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key
    else:
        return ValueError("Not a RSA key")


def import_rsa_key_from_cert_file(pem_file):
    with open(pem_file, "r") as cert_file:
        return import_rsa_key(cert_file.read())


def rsa_eq(key1, key2):
    """
    Only works for RSAPublic Keys

    :param key1:
    :param key2:
    :return:
    """
    pn1 = key1.public_numbers()
    pn2 = key2.public_numbers()
    # Check if two RSA keys are in fact the same
    if pn1 == pn2:
        return True
    else:
        return False


def x509_rsa_load(txt):
    """So I get the same output format as loads produces
    :param txt:
    :return:
    """
    pub_key = import_rsa_key(txt)
    if isinstance(pub_key, rsa.RSAPublicKey):
        return [("rsa", pub_key)]


def rsa_construct_public(numbers):
    rpn = rsa.RSAPublicNumbers(**numbers)
    return rpn.public_key(default_backend())


def rsa_construct_private(numbers):
    args = dict([(k, v) for k, v in numbers.items() if k in ["n", "e", "d"]])
    cnum = {"d": numbers["d"]}
    if "p" not in numbers and "q" not in numbers:
        (p, q) = rsa.rsa_recover_prime_factors(**args)
        cnum["p"] = p
        cnum["q"] = q
    else:
        cnum["p"] = numbers["p"]
        cnum["q"] = numbers["q"]

    try:
        cnum["dmp1"] = numbers["dp"]
    except KeyError:
        cnum["dmp1"] = rsa.rsa_crt_dmp1(cnum["d"], cnum["p"])
    else:
        if not numbers["dp"]:
            cnum["dmp1"] = rsa.rsa_crt_dmp1(cnum["d"], cnum["p"])

    try:
        cnum["dmq1"] = numbers["dq"]
    except KeyError:
        cnum["dmq1"] = rsa.rsa_crt_dmq1(cnum["d"], cnum["q"])
    else:
        if not numbers["dq"]:
            cnum["dmq1"] = rsa.rsa_crt_dmq1(cnum["d"], cnum["q"])

    try:
        cnum["iqmp"] = numbers["di"]
    except KeyError:
        cnum["iqmp"] = rsa.rsa_crt_iqmp(cnum["p"], cnum["q"])
    else:
        if not numbers["di"]:
            cnum["iqmp"] = rsa.rsa_crt_iqmp(cnum["p"], cnum["q"])

    rpubn = rsa.RSAPublicNumbers(e=numbers["e"], n=numbers["n"])
    rprivn = rsa.RSAPrivateNumbers(public_numbers=rpubn, **cnum)
    return rprivn.private_key(default_backend())


def cmp_public_numbers(pn1, pn2):
    """
    Compare 2 sets of public numbers. These is a way to compare
    2 public RSA keys. If the sets are the same then the keys are the same.

    :param pn1: The set of values belonging to the 1st key
    :param pn2: The set of values belonging to the 2nd key
    :return: True is the sets are the same otherwise False.
    """
    if pn1.n == pn2.n:
        if pn1.e == pn2.e:
            return True
    return False


def cmp_private_numbers(pn1, pn2):
    """
    Compare 2 sets of private numbers. This is for comparing 2
    private RSA keys.

    :param pn1: The set of values belonging to the 1st key
    :param pn2: The set of values belonging to the 2nd key
    :return: True is the sets are the same otherwise False.
    """
    if not cmp_public_numbers(pn1.public_numbers, pn2.public_numbers):
        return False

    for param in ["d", "p", "q"]:
        if getattr(pn1, param) != getattr(pn2, param):
            return False
    return True


class RSAKey(AsymmetricKey):
    """
    JSON Web key representation of a RSA key
    The name of parameters used in this class are the same as
    specified in the RFC 7517.

    According to RFC7517 the JWK representation of a RSA (public key) can be
    something like this:

        {
        "kty": "RSA",
        "use": "sig",
        "kid": "1b94c",
        "n": "vrjOfz9Ccdgx5nQudyhdoR17V...",
        "e": "AQAB",
        }

    Parameters according to https://tools.ietf.org/html/rfc7518#section-6.3
    """

    members = JWK.members[:]
    # These are the RSA key specific parameters, they are always supposed to
    # be strings or bytes
    members.extend(["n", "e", "d", "p", "q"])
    # The parameters that represent long ints in the key instances
    longs = ["n", "e", "d", "p", "q", "dp", "dq", "di", "qi"]
    public_members = JWK.public_members[:]
    # the public members of the key
    public_members.extend(["n", "e"])
    required = ["kty", "n", "e"]

    def __init__(
        self,
        kty="RSA",
        alg="",
        use="",
        kid="",
        x5c=None,
        x5t="",
        x5u="",
        n="",
        e="",
        d="",
        p="",
        q="",
        dp="",
        dq="",
        di="",
        qi="",
        **kwargs
    ):
        AsymmetricKey.__init__(self, kty, alg, use, kid, x5c, x5t, x5u, **kwargs)
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.di = di
        self.qi = qi

        has_public_key_parts = len(self.n) > 0 and len(self.e)
        has_x509_cert_chain = len(self.x5c) > 0

        if self.priv_key:
            self._serialize(self.priv_key)
            self.pub_key = self.priv_key.public_key()
        elif self.pub_key:
            self._serialize(self.pub_key)
        elif has_public_key_parts:
            self.deserialize()
        elif has_x509_cert_chain:
            self.deserialize()
        elif not self.n and not self.e:
            pass
        else:  # one of n or e but not both
            raise JWKESTException("Missing required parameter")

    def deserialize(self):
        """
        Based on a text based representation of an RSA key this method
        instantiates a
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey or
        RSAPublicKey instance

        """

        # first look for the public parts of a RSA key
        if self.n and self.e:
            try:
                numbers = {}
                # loop over all the parameters that define a RSA key
                for param in self.longs:
                    item = getattr(self, param)
                    if not item:
                        continue
                    else:
                        try:
                            val = int(deser(item))
                        except Exception:
                            raise
                        else:
                            numbers[param] = val

                if "d" in numbers:
                    self.priv_key = rsa_construct_private(numbers)
                    self.pub_key = self.priv_key.public_key()
                else:
                    self.pub_key = rsa_construct_public(numbers)
            except ValueError as err:
                raise DeSerializationNotPossible("%s" % err)

        if self.x5c:
            _cert_chain = []
            for der_data in self.x5c:
                _cert_chain.append(der_cert(base64.b64decode(der_data)))

            if self.x5t:  # verify the cert thumbprint
                if isinstance(self.x5t, bytes):
                    _x5t = self.x5t
                else:
                    _x5t = self.x5t.encode("ascii")
                if _x5t != x5t_calculation(self.x5c[0]):
                    raise DeSerializationNotPossible(
                        "The thumbprint 'x5t' does not match the certificate."
                    )

            if self.pub_key:
                if not rsa_eq(self.pub_key, _cert_chain[0].public_key()):
                    raise ValueError("key described by components and key in x5c not equal")
            else:
                self.pub_key = _cert_chain[0].public_key()

            self._serialize(self.pub_key)
            if len(self.x5c) > 1:  # verify chain
                pass

        if not self.priv_key and not self.pub_key:
            raise DeSerializationNotPossible()

    def serialize(self, private=False):
        """
        Given a cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey or
        RSAPublicKey instance construct the JWK representation.

        :param private: Should I do the private part or not
        :return: A JWK as a dictionary
        """
        if not self.priv_key and not self.pub_key:
            raise SerializationNotPossible()

        res = self.common()

        public_longs = list(set(self.public_members) & set(self.longs))
        for param in public_longs:
            item = getattr(self, param)
            if item:
                res[param] = item

        if private:
            for param in self.longs:
                if not private and param in ["d", "p", "q", "dp", "dq", "di", "qi"]:
                    continue
                item = getattr(self, param)
                if item:
                    res[param] = item
        if self.x5c:
            res["x5c"] = [as_unicode(x) for x in self.x5c]

        return res

    def _serialize(self, key):
        if isinstance(key, rsa.RSAPrivateKey):
            pn = key.private_numbers()
            self.n = long_to_base64(pn.public_numbers.n)
            self.e = long_to_base64(pn.public_numbers.e)
            self.d = long_to_base64(pn.d)
            self.p = long_to_base64(pn.p)
            self.q = long_to_base64(pn.q)
        elif isinstance(key, rsa.RSAPublicKey):
            pn = key.public_numbers()
            self.n = long_to_base64(pn.n)
            self.e = long_to_base64(pn.e)
        else:
            raise UnsupportedKeyType()

    def load_key(self, key):
        """
        Load a RSA key. Try to serialize the key before binding it to this
        instance.

        :param key: An RSA key instance
        """

        self._serialize(key)
        if isinstance(key, rsa.RSAPrivateKey):
            self.priv_key = key
            self.pub_key = key.public_key()
        else:
            self.pub_key = key

        return self

    def load(self, filename):
        """
        Load a RSA key from a PEM encoded file. Once we have the key do a serialization.

        :param filename: File name
        """
        return self.load_key(import_private_rsa_key_from_file(filename))

    def __eq__(self, other):
        """
        Verify that this other key is the same as myself.

        :param other: The other key
        :return: True if equal otherwise False
        """
        if not isinstance(other, RSAKey):
            return False

        if not self.pub_key:
            self.deserialize()

        if not other.pub_key:
            other.deserialize()

        if self.use and other.use:
            if self.use != other.use:
                return False

        if self.kid:
            if other.kid:
                if self.kid != other.kid:
                    return False
            else:
                return False
        else:
            if other.kid:
                return False

        try:
            pn1 = self.priv_key.private_numbers()
            pn2 = other.priv_key.private_numbers()
        except Exception:
            try:
                return cmp_public_numbers(
                    self.pub_key.public_numbers(), other.pub_key.public_numbers()
                )
            except Exception:
                return False
        else:
            return cmp_private_numbers(pn1, pn2)


def new_rsa_key(key_size=2048, kid="", public_exponent=65537, **kwargs):
    """
    Creates a new RSA key pair and wraps it in a
    :py:class:`cryptojwt.jwk.rsa.RSAKey` instance

    :param key_size: The size of the key
    :param kid: The key ID
    :param public_exponent: The value of the public exponent.
    :return: A :py:class:`cryptojwt.jwk.rsa.RSAKey` instance
    """

    _key = rsa.generate_private_key(
        public_exponent=public_exponent, key_size=key_size, backend=default_backend()
    )

    _rk = RSAKey(priv_key=_key, kid=kid, **kwargs)
    if not _rk.kid:
        _rk.add_kid()

    return _rk
