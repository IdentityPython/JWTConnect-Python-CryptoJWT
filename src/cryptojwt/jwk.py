import base64
import hashlib
import logging
import json

from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

from requests import request

from cryptojwt import as_bytes, bytes2str_conv
from cryptojwt import as_unicode
from cryptojwt import base64_to_long
from cryptojwt import base64url_to_long
from cryptojwt import b64d
from cryptojwt import b64e
from cryptojwt import long_to_base64
from cryptojwt.exception import HeaderError
from cryptojwt.exception import JWKESTException
from cryptojwt.exception import JWKException
from cryptojwt.exception import UnknownAlgorithm
from cryptojwt.exception import DeSerializationNotPossible
from cryptojwt.exception import SerializationNotPossible

__author__ = 'roland hedberg'

logger = logging.getLogger(__name__)

PREFIX = "-----BEGIN CERTIFICATE-----"
POSTFIX = "-----END CERTIFICATE-----"


def dicthash(d):
    return hash(repr(sorted(d.items())))


def intarr2str(arr):
    return "".join([chr(c) for c in arr])


def sha256_digest(msg):
    return hashlib.sha256(as_bytes(msg)).digest()


def sha384_digest(msg):
    return hashlib.sha384(as_bytes(msg)).digest()


def sha512_digest(msg):
    return hashlib.sha512(as_bytes(msg)).digest()


DIGEST_HASH = {
    'SHA-256': sha256_digest,
    'SHA-384': sha384_digest,
    'SHA-512': sha512_digest
}


# =============================================================================


def generate_and_store_rsa_key(key_size=2048, filename='rsa.key',
                               passphrase=''):
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=key_size,
                                           backend=default_backend())

    with open(filename, "wb") as keyfile:
        if passphrase:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase))
        else:
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption())
        keyfile.write(pem)
        keyfile.close()
    return private_key


def import_private_rsa_key_from_file(filename, passphrase=None):
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=passphrase,
            backend=default_backend())
    return private_key


def import_public_rsa_key_from_file(filename):
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend())
    return public_key


def import_rsa_key(pem_data):
    """
    Extract an RSA key from a PEM-encoded certificate

    :param pem_data: RSA key encoded in standard form
    :return: RSA public key instance
    """
    if not pem_data.startswith(PREFIX):
        pem_data = bytes('{}\n{}\n{}'.format(PREFIX, pem_data, POSTFIX),
                         'utf-8')
    else:
        pem_data = bytes(pem_data, 'utf-8')
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert.public_key()


def import_rsa_key_from_cert_file(pem_file):
    with open(pem_file, 'r') as cert_file:
        return import_rsa_key(cert_file.read())


def der_cert(der_data):
    """
    Load a DER encoded certificate

    @param der_data: DER-encoded certificate
    @return: RSA instance
    """
    if isinstance(der_data, str):
        der_data = bytes(der_data, 'utf-8')
    cert = x509.load_der_x509_certificate(der_data, default_backend())
    return cert


def load_x509_cert(url, spec2key):
    """
    Get and transform a X509 cert into a key.

    :param url: Where the X509 cert can be found
    :param spec2key: A dictionary over keys already seen
    :return: List of 2-tuples (keytype, key)
    """
    try:
        r = request("GET", url, allow_redirects=True)
        if r.status_code == 200:
            cert = str(r.text)
            try:
                public_key = spec2key[cert]  # If I've already seen it
            except KeyError:
                public_key = import_rsa_key(cert)
                spec2key[cert] = public_key
            if isinstance(public_key, rsa.RSAPublicKey):
                return [("rsa", public_key)]
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)
    except Exception as err:  # not a RSA key
        logger.warning("Can't load key: %s" % err)
        return []


def rsa_load(filename, passphrase=None):
    """Read a PEM-encoded RSA private key from a file."""
    with open(filename, "rb") as key_file:
        pem_data = key_file.read()
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=passphrase,
            backend=default_backend())

    return private_key


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
    """ So I get the same output format as loads produces
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
    args = dict([(k, v) for k, v in numbers.items() if k in ['n', 'e', 'd']])
    cnum = {'d': numbers['d']}
    if 'p' not in numbers and 'q' not in numbers:
        (p, q) = rsa.rsa_recover_prime_factors(**args)
        cnum['p'] = p
        cnum['q'] = q
    else:
        cnum['p'] = numbers['p']
        cnum['q'] = numbers['q']

    try:
        cnum['dmp1'] = numbers['dp']
    except KeyError:
        cnum['dmp1'] = rsa.rsa_crt_dmp1(cnum['d'], cnum['p'])
    else:
        if not numbers['dp']:
            cnum['dmp1'] = rsa.rsa_crt_dmp1(cnum['d'], cnum['p'])

    try:
        cnum['dmq1'] = numbers['dq']
    except KeyError:
        cnum['dmq1'] = rsa.rsa_crt_dmq1(cnum['d'], cnum['q'])
    else:
        if not numbers['dq']:
            cnum['dmq1'] = rsa.rsa_crt_dmq1(cnum['d'], cnum['q'])

    try:
        cnum['iqmp'] = numbers['di']
    except KeyError:
        cnum['iqmp'] = rsa.rsa_crt_iqmp(cnum['p'], cnum['p'])
    else:
        if not numbers['di']:
            cnum['iqmp'] = rsa.rsa_crt_iqmp(cnum['p'], cnum['p'])

    rpubn = rsa.RSAPublicNumbers(e=numbers['e'], n=numbers['n'])
    rprivn = rsa.RSAPrivateNumbers(public_numbers=rpubn, **cnum)
    return rprivn.private_key(default_backend())


def ec_construct_public(num):
    ecpn = ec.EllipticCurvePublicNumbers(num['x'], num['y'],
                                         NIST2SEC[as_unicode(num['crv'])]())
    return ecpn.public_key(default_backend())


def ec_construct_private(num):
    pub_ecpn = ec.EllipticCurvePublicNumbers(num['x'], num['y'],
                                             NIST2SEC[as_unicode(num['crv'])]())
    priv_ecpn = ec.EllipticCurvePrivateNumbers(num['d'], pub_ecpn)
    return priv_ecpn.private_key(default_backend())


def key_from_jwk_dict(jwk_dict, private=True):
    """Load JWK from dictionary"""
    if jwk_dict['kty'] == 'EC':
        if private:
            return ECKey(kid=jwk_dict['kid'],
                         crv=jwk_dict['crv'],
                         x=jwk_dict['x'],
                         y=jwk_dict['y'],
                         d=jwk_dict['d'])
        else:
            return ECKey(kid=jwk_dict['kid'],
                         crv=jwk_dict['crv'],
                         x=jwk_dict['x'],
                         y=jwk_dict['y'])
    elif jwk_dict['kty'] == 'RSA':
        if private:
            return RSAKey(kid=jwk_dict['kid'],
                          n=jwk_dict['n'],
                          e=jwk_dict['e'],
                          d=jwk_dict['d'],
                          p=jwk_dict['p'],
                          q=jwk_dict['q'])
        else:
            return RSAKey(kid=jwk_dict['kid'],
                          n=jwk_dict['n'],
                          e=jwk_dict['e'])
    elif jwk_dict['kty'] == 'oct':
        return SYMKey(kid=jwk_dict['kid'],
                      k=jwk_dict['k'])
    else:
        raise UnknownAlgorithm


def x5t_calculation(cert):
    """
    base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
    encoding of an X.509 certificate.

    :param cert: DER encoded X.509 certificate
    :return: x5t value
    """
    if isinstance(cert, str):
        der_cert = base64.b64decode(cert.encode('ascii'))
    else:
        der_cert = base64.b64decode(cert)

    return b64e(hashlib.sha1(der_cert).digest())


class Key(object):
    """
    Basic JSON Web key class. Jason Web keys are described in
    RFC 7517 (https://tools.ietf.org/html/rfc7517).
    The name of parameters used in this class are the same as
    specified in RFC 7518 (https://tools.ietf.org/html/rfc7518).

    """
    members = ["kty", "alg", "use", "kid", "x5c", "x5t", "x5u"]
    longs = []
    public_members = ["kty", "alg", "use", "kid", "x5c", "x5t", "x5u"]
    required = ['kty']

    def __init__(self, kty="", alg="", use="", kid="", key=None, x5c=None,
                 x5t="", x5u="", **kwargs):
        self.key = key
        self.extra_args = kwargs

        # want kty, alg, use and kid to be strings
        if isinstance(kty, str):
            self.kty = kty
        else:
            self.kty = as_unicode(kty)

        if isinstance(alg, str):
            self.alg = alg
        else:
            self.alg = as_unicode(alg)

        if isinstance(use, str):
            self.use = use
        else:
            self.use = as_unicode(use)

        if isinstance(kid, str):
            self.kid = kid
        else:
            self.kid = as_unicode(kid)

        self.x5c = x5c or []
        self.x5t = x5t
        self.x5u = x5u
        self.inactive_since = 0

    def to_dict(self):
        """
        A wrapper for to_dict the makes sure that all the private information
        as well as extra arguments are included. This method should *not* be
        used for exporting information about the key.
        """
        res = self.serialize(private=True)
        res.update(self.extra_args)
        return res

    def common(self):
        """
        Return the set of parameters that are common to all types of keys.

        :return: Dictionary
        """
        res = {"kty": self.kty}
        if self.use:
            res["use"] = self.use
        if self.kid:
            res["kid"] = self.kid
        if self.alg:
            res["alg"] = self.alg
        return res

    def __str__(self):
        return str(self.to_dict())

    def deserialize(self):
        """
        Starting with information gathered from the on-the-wire representation
        initiate an appropriate key.
        """
        pass

    def serialize(self, private=False):
        """
        map key characteristics into attribute values that can be used
        to create an on-the-wire representation of the key
        """
        pass

    def get_key(self, private=False, **kwargs):
        """
        Get a keys useful for signing and/or encrypting information.

        :param private: Private key requested
        :return: A key instance. This can be an RSA, EC or other
        type of key.
        """
        if not self.key:
            self.deserialize()

        if not private and hasattr(self.key, 'public_key'):
            return self.key.public_key()

        if private and not self.is_private_key():
            raise ValueError("Not a private key")

        return self.key

    def verify(self):
        """
        Verify that the information gathered from the on-the-wire
        representation is of the right type.
        This is supposed to be run before the info is deserialized.
        """
        for param in self.longs:
            item = getattr(self, param)
            if not item or isinstance(item, str):
                continue

            if isinstance(item, bytes):
                item = item.decode('utf-8')
                setattr(self, param, item)

            try:
                _ = base64url_to_long(item)
            except Exception:
                return False
            else:
                if [e for e in ['+', '/', '='] if e in item]:
                    return False

        if self.kid:
            if not isinstance(self.kid, str):
                raise HeaderError("kid of wrong value type")
        return True

    def __eq__(self, other):
        """
        Compare 2 Key instances to find out if they represent the same key

        :param other: The other Key instance
        :return: True if they are the same otherwise False.
        """
        if self.__class__ != other.__class__:
            return False

        if set(self.__dict__.keys()) != set(other.__dict__.keys()):
            return False

        for key in self.public_members:
            if getattr(other, key) != getattr(self, key):
                return False

        return True

    def keys(self):
        return list(self.to_dict().keys())

    def thumbprint(self, hash_function, members=None):
        """
        Create a thumbprint of the key following the outline in
        https://tools.ietf.org/html/draft-jones-jose-jwk-thumbprint-01

        :param hash_function: A hash function to use for hashing the
            information
        :param members: Which attributes of the Key instance that should
            be included when computing the hash value.
        :return: A base64 encode hash over a set of Key attributes
        """
        if members is None:
            members = self.required

        members.sort()
        ser = self.serialize()
        _se = []
        for elem in members:
            try:
                _val = ser[elem]
            except KeyError:  # should never happen with the required set
                pass
            else:
                if isinstance(_val, bytes):
                    _val = as_unicode(_val)
                _se.append('"{}":{}'.format(elem, json.dumps(_val)))
        _json = '{{{}}}'.format(','.join(_se))

        return b64e(DIGEST_HASH[hash_function](_json))

    def add_kid(self):
        """
        Construct a Key ID using the thumbprint method and add it to
        the key attributes.
        """
        self.kid = b64e(self.thumbprint('SHA-256')).decode('utf8')

    def is_private_key(self):
        for p in self.members:
            if p not in self.public_members:
                if getattr(self, p):
                    return True
        return False

    def is_public_key(self):
        return not self.is_private_key()


def deser(val):
    """
    Deserialize from a string representation of an long integer
    to the python representation of a long integer.

    :param val: The string representation of the long integer.
    :return: The long integer.
    """
    if isinstance(val, str):
        _val = val.encode("utf-8")
    else:
        _val = val

    return base64_to_long(_val)


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

    for param in ['d', 'p', 'q']:
        if getattr(pn1, param) != getattr(pn2, param):
            return False
    return True


class RSAKey(Key):
    """
    JSON Web key representation of a RSA key
    The name of parameters used in this class are the same as
    specified in the RFC 7517.

    According to RFC7517 the JWK representation of a RSA (public key) can be
    something like this:

        {
        "kty":"RSA",
        "use":"sig",
        "kid":"1b94c",
        "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08
        PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q
        u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a
        YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH
        MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv
        VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
        "e":"AQAB",
        }

    Parameters according to https://tools.ietf.org/html/rfc7518#section-6.3
    """
    members = Key.members[:]
    # These are the RSA key specific parameters, they are always supposed to
    # be strings or bytes
    members.extend(["n", "e", "d", "p", "q"])
    # The parameters that represent long ints in the key instances
    longs = ["n", "e", "d", "p", "q", "dp", "dq", "di", "qi"]
    public_members = Key.public_members[:]
    # the public members of the key
    public_members.extend(["n", "e"])
    required = ['kty', 'n', 'e']

    def __init__(self, kty="RSA", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u="", n="", e="", d="", p="", q="",
                 dp="", dq="", di="", qi="", **kwargs):
        Key.__init__(self, kty, alg, use, kid, key, x5c, x5t, x5u, **kwargs)
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

        if self.key:
            self._serialize(self.key)
        elif has_public_key_parts:
            self.deserialize()
        elif has_x509_cert_chain:
            self.deserialize()
        elif not self.n and not self.e:
            pass
        else:  # one of n or e but not both
            raise JWKESTException('Missing required parameter')

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

                if 'd' in numbers:
                    self.key = rsa_construct_private(numbers)
                else:
                    self.key = rsa_construct_public(numbers)
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
                    _x5t = self.x5t.encode('ascii')
                if _x5t != x5t_calculation(self.x5c[0]):
                    raise DeSerializationNotPossible(
                        "The thumbprint 'x5t' does not match the certificate.")

            if self.key:
                if not rsa_eq(self.key, _cert_chain[0].public_key()):
                    raise ValueError(
                        'key described by components and key in x5c not equal')
            else:
                self.key = _cert_chain[0].public_key()

            self._serialize(self.key)
            if len(self.x5c) > 1:  # verify chain
                pass

        if not self.key:
            raise DeSerializationNotPossible()

    def serialize(self, private=False):
        """
        Given a cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey or
        RSAPublicKey instance construct the JWK representation.

        :param private: Should I do the private part or not
        :return: A JWK as a dictionary
        """
        if not self.key:
            raise SerializationNotPossible()

        res = self.common()

        public_longs = list(set(self.public_members) & set(self.longs))
        for param in public_longs:
            item = getattr(self, param)
            if item:
                res[param] = item

        if private:
            for param in self.longs:
                if not private and param in ["d", "p", "q", "dp", "dq", "di",
                                             "qi"]:
                    continue
                item = getattr(self, param)
                if item:
                    res[param] = item
        if self.x5c:
            res['x5c'] = [x.decode('utf-8') for x in self.x5c]

        return res

    def _serialize(self, key):
        try:
            pn = key.private_numbers()
        except Exception as err:
            try:
                pn = key.public_numbers()
            except Exception as err:
                raise
            else:
                self.n = long_to_base64(pn.n)
                self.e = long_to_base64(pn.e)
        else:
            self.n = long_to_base64(pn.public_numbers.n)
            self.e = long_to_base64(pn.public_numbers.e)
            self.d = long_to_base64(pn.d)
            self.p = long_to_base64(pn.p)
            self.q = long_to_base64(pn.q)

    def load_key(self, key):
        """
        Load a RSA key. Try to serialize the key before binding it to this
        instance.

        :param key: An RSA key instance
        """

        self._serialize(key)
        self.key = key
        return self

    def load(self, filename):
        """
        Load a RSA key from a file. Once we have the key do a serialization.

        :param filename: File name
        """
        return self.load_key(rsa_load(filename))

    def encryption_key(self, **kwargs):
        """
        Make sure there is a key instance present that can be used for
        encrypting/signing.
        """
        if not self.key:
            self.deserialize()

        return self.key

    def __eq__(self, other):
        """
        Verify that this other key is the same as myself.

        :param other: The other key
        :return: True if equal otherwise False
        """
        if not isinstance(other, RSAKey):
            return False

        if not self.key:
            self.deserialize()

        if not other.key:
            other.deserialize()

        try:
            pn1 = self.key.private_numbers()
            pn2 = other.key.private_numbers()
        except Exception:
            try:
                cmp_public_numbers(self.key.public_numbers(),
                                   other.key.public_numbers())
            except Exception:
                return False
            else:
                return True
        else:
            return cmp_private_numbers(pn1, pn2)


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


class ECKey(Key):
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
    members = Key.members[:]
    # The elliptic curve specific attributes
    members.extend(["crv", "x", "y", "d"])
    longs = ['x', 'y', 'd']
    public_members = Key.public_members[:]
    public_members.extend(["kty", "alg", "use", "kid", "crv", "x", "y"])
    required = ['crv', 'key', 'x', 'y']

    def __init__(self, kty="EC", alg="", use="", kid="", key=None,
                 crv="", x="", y="", d="", **kwargs):
        Key.__init__(self, kty, alg, use, kid, key, **kwargs)
        self.crv = crv
        self.x = x
        self.y = y
        self.d = d

        # Initiated guess as to what state the key is in
        # To be usable for encryption/signing/.. it has to be deserialized
        if self.key:
            self.load_key(key)
        elif self.x and self.y and self.crv:
            self.verify()
            self.deserialize()
        elif any([self.x, self.y, self.crv]):
            raise JWKESTException('Missing required parameter')

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
                    self.key = ec_construct_private({'x': _x, 'y': _y,
                                                     'crv': self.crv, 'd': _d})
            except ValueError as err:
                raise DeSerializationNotPossible(str(err))
        else:
            self.key = ec_construct_public({'x': _x, 'y': _y, 'crv': self.crv})

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
        if not self.crv:
            raise SerializationNotPossible()

        res = self.common()

        self._serialize(self.key)

        res.update({
            #"crv": SEC2NIST[self.crv.name],
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
        self.key = key
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
        if isinstance(self.key, ec.EllipticCurvePublicKey):
            if isinstance(other.key, ec.EllipticCurvePublicKey):
                if self.key.curve != other.key.curve:
                    return False
                if self.key.key_size != other.key.key_size:
                    return False
                if self.key.public_numbers() != other.key.public_numbers():
                    return False
                return True

        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            if isinstance(other.key, ec.EllipticCurvePrivateKey):
                if self.key.curve != other.key.curve:
                    return False
                if self.key.key_size != other.key.key_size:
                    return False
                if self.key.private_numbers() != other.key.private_numbers():
                    return False
                return True

        return False


ALG2KEYLEN = {
    "A128KW": 16,
    "A192KW": 24,
    "A256KW": 32,
    "HS256": 32,
    "HS384": 48,
    "HS512": 64
}


class SYMKey(Key):
    """
    JSON Web key representation of a Symmetric key.
    According to RFC 7517 a JWK representation of a symmetric key can look like
    this::
        {
            "kty":"oct",
            "alg":"A128KW",
            "k":"GawgguFyGrWKav7AX4VKUg"
        }

    """
    members = Key.members[:]
    members.extend(["kty", "alg", "use", "kid", "k"])
    public_members = Key.public_members[:]
    required = ['k', 'kty']

    def __init__(self, kty="oct", alg="", use="", kid="", key=None,
                 x5c=None, x5t="", x5u="", k="", mtrl="", **kwargs):
        Key.__init__(self, kty, alg, use, kid, as_bytes(key), x5c, x5t, x5u,
                     **kwargs)
        self.k = k
        if not self.key and self.k:
            if isinstance(self.k, str):
                self.k = self.k.encode("utf-8")
            self.key = b64d(bytes(self.k))

    def deserialize(self):
        self.key = b64d(bytes(self.k))

    def serialize(self, private=True):
        res = self.common()
        res["k"] = as_unicode(b64e(bytes(self.key)))
        return res

    def get_key(self, **kwargs):
        if not self.key:
            self.deserialize()
        return self.key

    def encryption_key(self, alg, **kwargs):
        """
        Return an encryption key as per
        http://openid.net/specs/openid-connect-core-1_0.html#Encryption

        :param alg: encryption algorithm
        :param kwargs:
        :return: encryption key as byte string
        """
        if not self.key:
            self.deserialize()

        tsize = ALG2KEYLEN[alg]
        # _keylen = len(self.key)

        if tsize <= 32:
            # SHA256
            _enc_key = sha256_digest(self.key)[:tsize]
        elif tsize <= 48:
            # SHA384
            _enc_key = sha384_digest(self.key)[:tsize]
        elif tsize <= 64:
            # SHA512
            _enc_key = sha512_digest(self.key)[:tsize]
        else:
            raise JWKException("No support for symmetric keys > 512 bits")

        logger.debug('Symmetric encryption key: {}'.format(
            as_unicode(b64e(_enc_key))))

        return _enc_key

    def is_private_key(self):
        return True

    def is_public_key(self):
        return True


# -----------------------------------------------------------------------------


def keyitems2keyreps(keyitems):
    keys = []
    for key_type, _keys in list(keyitems.items()):
        if key_type.upper() == "RSA":
            keys.extend([RSAKey(key=k) for k in _keys])
        elif key_type.lower() == "oct":
            keys.extend([SYMKey(key=k) for k in _keys])
        elif key_type.upper() == "EC":
            keys.extend([ECKey(key=k) for k in _keys])
        else:
            keys.extend([Key(key=k) for k in _keys])
    return keys


def keyrep(kspec, enc="utf-8"):
    """
    Instantiate a Key given a set of key/word arguments

    :param kspec: Key specification, arguments to the Key initialization
    :param enc: The encoding of the strings. If it's JSON which is the default
     the encoding is utf-8.
    :return: Key instance
    """
    if enc:
        _kwargs = {}
        for key, val in kspec.items():
            if isinstance(val, str):
                _kwargs[key] = val.encode(enc)
            else:
                _kwargs[key] = val
    else:
        _kwargs = kspec

    if kspec["kty"] == "RSA":
        item = RSAKey(**_kwargs)
    elif kspec["kty"] == "oct":
        item = SYMKey(**_kwargs)
    elif kspec["kty"] == "EC":
        item = ECKey(**_kwargs)
    else:
        item = Key(**_kwargs)
    return item


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


class KEYS(object):
    def __init__(self):
        self._keys = []

    def load_dict(self, dikt):
        for kspec in dikt["keys"]:
            self._keys.append(keyrep(kspec))

    def load_jwks(self, jwks):
        """
        Load and create keys from a JWKS JSON representation

        Expects something on this form::

            {"keys":
                [
                    {"kty":"EC",
                     "crv":"P-256",
                     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                    "use":"enc",
                    "kid":"1"},

                    {"kty":"RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFb....."
                    "e":"AQAB",
                    "kid":"2011-04-29"}
                ]
            }

        :param jwks: The JWKS JSON string representation
        :return: list of 2-tuples containing key, type
        """
        self.load_dict(json.loads(jwks))
        return self

    def dump_jwks(self):
        """
        :return: A JWKS representation of the held keys
        """
        res = []
        for key in self._keys:
            res.append(bytes2str_conv(key.serialize()))

        return json.dumps({"keys": res})

    def load_from_url(self, url, verify=True):
        """
        Get and transform a JWKS into keys

        :param url: Where the JWKS can be found
        :param verify: SSL cert verification
        :return: list of keys
        """

        r = request("GET", url, allow_redirects=True, verify=verify)
        if r.status_code == 200:
            return self.load_jwks(r.text)
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)

    def __getitem__(self, item):
        """
        Get all keys of a specific key type

        :param item: Key type
        :return: list of keys
        """
        kty = item.lower()
        return [k for k in self._keys if k.kty.lower() == kty]

    def __iter__(self):
        for k in self._keys:
            yield k

    def __len__(self):
        return len(self._keys)

    def keys(self):
        return self._keys

    def key_types(self):
        """

        :return: A list of key types !!! not keys
        """
        return list(set([k.kty for k in self._keys]))

    def __repr__(self):
        return self.dump_jwks()

    def __str__(self):
        return self.__repr__()

    def kids(self):
        return [k.kid for k in self._keys if k.kid]

    def by_kid(self, kid):
        return [k for k in self._keys if kid == k.kid]

    def wrap_add(self, keyinst, use="", kid=''):
        self._keys.append(jwk_wrap(keyinst, use, kid))

    def as_dict(self):
        _res = {}
        for kty, k in [(k.kty, k) for k in self._keys]:
            if kty not in ["RSA", "EC", "oct"]:
                if kty in ["rsa", "ec"]:
                    kty = kty.upper()
                else:
                    kty = kty.lower()

            try:
                _res[kty].append(k)
            except KeyError:
                _res[kty] = [k]
        return _res

    def add(self, item, enc="utf-8"):
        self._keys.append(keyrep(item, enc))

    def append(self, key):
        self._keys.append(key)


def load_jwks_from_url(url, verify=True):
    return KEYS().load_from_url(url, verify=verify).keys()


def load_jwks(spec):
    return KEYS().load_jwks(spec).keys()


def make_public_copy(key):
    if not isinstance(key, Key):
        raise ValueError("Wrong type of class instance")

    c = key.__class__()
    for attr in key.public_members:
        try:
            v = getattr(key, attr)
        except AttributeError:
            pass
        else:
            setattr(c, attr, v)

    return c
