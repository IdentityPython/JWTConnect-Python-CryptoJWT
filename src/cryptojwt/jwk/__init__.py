import base64
import hashlib
import json
import ssl
from typing import List

from ..exception import UnsupportedAlgorithm
from ..utils import as_bytes
from ..utils import as_unicode
from ..utils import b64e
from ..utils import base64url_to_long
from .utils import DIGEST_HASH

USE = {"sign": "sig", "decrypt": "enc", "encrypt": "enc", "verify": "sig"}


class JWK(object):
    """
    Basic JSON Web key class. Jason Web keys are described in
    RFC 7517 (https://tools.ietf.org/html/rfc7517).
    The name of parameters used in this class are the same as
    specified in RFC 7518 (https://tools.ietf.org/html/rfc7518).

    """

    members = ["kty", "alg", "use", "kid", "x5c", "x5t", "x5u", "key_ops"]
    longs: List[str] = []
    public_members = ["kty", "alg", "use", "kid", "x5c", "x5t", "x5u", "key_ops"]
    required = ["kty"]

    def __init__(
        self, kty="", alg="", use="", kid="", x5c=None, x5t="", x5u="", key_ops=None, **kwargs
    ):

        self.extra_args = kwargs

        # want kty, alg, use and kid to be strings
        if isinstance(kty, str):
            self.kty = kty
        else:
            self.kty = as_unicode(kty)

        if alg:
            if not isinstance(alg, str):
                alg = as_unicode(alg)

            if use == "enc":
                if alg not in [
                    "RSA1_5",
                    "RSA-OAEP",
                    "RSA-OAEP-256",
                    "A128KW",
                    "A192KW",
                    "A256KW",
                    "ECDH-ES",
                    "ECDH-ES+A128KW",
                    "ECDH-ES+A192KW",
                    "ECDH-ES+A256KW",
                ]:
                    raise UnsupportedAlgorithm("Unknown algorithm: {}".format(alg))
            elif use == "sig":
                # The list comes from https://tools.ietf.org/html/rfc7518#page-6
                # Should map against SIGNER_ALGS in cryptojwt.jws.jws
                if alg not in [
                    "HS256",
                    "HS384",
                    "HS512",
                    "RS256",
                    "RS384",
                    "RS512",
                    "ES256",
                    "ES384",
                    "ES512",
                    "PS256",
                    "PS384",
                    "PS512",
                    "none",
                ]:
                    raise UnsupportedAlgorithm("Unknown algorithm: {}".format(alg))
            else:  # potentially used both for encryption and signing
                if alg not in [
                    "HS256",
                    "HS384",
                    "HS512",
                    "RS256",
                    "RS384",
                    "RS512",
                    "ES256",
                    "ES384",
                    "ES512",
                    "PS256",
                    "PS384",
                    "PS512",
                    "none",
                    "RSA1_5",
                    "RSA-OAEP",
                    "RSA-OAEP-256",
                    "A128KW",
                    "A192KW",
                    "A256KW",
                    "ECDH-ES",
                    "ECDH-ES+A128KW",
                    "ECDH-ES+A192KW",
                    "ECDH-ES+A256KW",
                ]:
                    raise UnsupportedAlgorithm("Unknown algorithm: {}".format(alg))
        self.alg = alg

        if isinstance(use, str):
            self.use = use
        else:
            self.use = as_unicode(use)

        if isinstance(kid, str):
            self.kid = kid
        else:
            self.kid = as_unicode(kid)

        if key_ops:
            self.key_ops: List[str] = []
            for ops in key_ops:
                if isinstance(ops, str):
                    self.key_ops.append(ops)
                else:
                    self.key_ops.append(as_unicode(key_ops))
        else:
            self.key_ops = []

        if self.use and self.key_ops:
            raise ValueError("Not allowed to specify use and key_ops")

        self.x5c = x5c or []
        self.x5t = x5t
        self.x5u = x5u
        self.inactive_since = kwargs.get("inactive_since", 0)

    def to_dict(self):
        """
        A wrapper for to_dict the makes sure that all the private information
        as well as extra arguments are included. This method should *not* be
        used for exporting information about the key.

        :return: A dictionary representation of the JSON Web key
        """
        res = self.serialize(private=True)
        res.update(self.extra_args)
        return res

    def common(self):
        """
        Return the set of parameters that are common to all types of keys.

        :return: Dictionary
        """
        res = {}
        for param in ["kty", "use", "kid", "alg", "key_ops"]:
            _val = getattr(self, param)
            if _val:
                res[param] = _val
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

        :param private: Private key requested. If false return a public key.
        :return: A key instance. This can be an RSA, EC or other
            type of key.
        """
        pass

    def verify(self):
        """
        Verify that the information gathered from the on-the-wire
        representation is of the right type.
        This is supposed to be run before the info is deserialized.

        :return: True/False
        """
        for param in self.longs:
            item = getattr(self, param)
            if not item or isinstance(item, str):
                continue

            if isinstance(item, bytes):
                item = item.decode("utf-8")
                setattr(self, param, item)

            try:
                _ = base64url_to_long(item)
            except Exception:
                return False
            else:
                if [e for e in ["+", "/", "="] if e in item]:
                    return False

        if self.kid:
            if not isinstance(self.kid, str):
                raise ValueError("kid of wrong value type")
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
            be included when computing the hash value. If members is undefined
            then all the required attributes are used.
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
        _json = "{{{}}}".format(",".join(_se))

        return b64e(DIGEST_HASH[hash_function](_json))

    def add_kid(self):
        """
        Construct a Key ID using the thumbprint method and add it to
        the key attributes.
        """
        self.kid = b64e(self.thumbprint("SHA-256")).decode("utf8")

    def appropriate_for(self, usage, **kwargs):
        """
        Make sure that key can be used for the specified usage.

        :return: True/False
        """
        if self.use:
            return self.use == USE[usage]
        elif self.key_ops:
            return usage in self.key_ops

    def update(self):
        pass


def pems_to_x5c(cert_chain):
    """
    Takes a list of PEM formated certificates and transforms them into a x5c attribute
    values as described in RFC 7517.

    :param cert_pem: List of PKIX certificates
    :return: List of strings
    """

    return [
        as_unicode(v)
        for v in [base64.b64encode(d) for d in [ssl.PEM_cert_to_DER_cert(c) for c in cert_chain]]
    ]


def x5c_to_pems(x5c):
    """
    Takes a x5c value from a JWK and converts it into a list of PEM formated certificates.

    :param x5c: List of strings
    :return:
    """

    return [
        ssl.DER_cert_to_PEM_cert(d)
        for d in [base64.b64decode(x) for x in [as_bytes(y) for y in x5c]]
    ]


def x5c_to_ders(x5c):
    """
    Takes a x5c value from a JWK and converts it into a list of PEM formated certificates.

    :param x5c: List of strings
    :return:
    """

    return [base64.b64decode(x) for x in [as_bytes(y) for y in x5c]]


def certificate_fingerprint(der, hash="sha256"):
    """

    :param der: DER encoded certificate
    :return:
    """
    if hash == "sha256":
        fp = hashlib.sha256(as_bytes(der)).hexdigest()
    elif hash == "sha1":
        fp = hashlib.sha1(as_bytes(der)).hexdigest()
    elif hash == "md5":
        fp = hashlib.md5(as_bytes(der)).hexdigest()
    else:
        raise UnsupportedAlgorithm(hash)

    return ":".join([fp[i : i + 2] for i in range(0, len(fp), 2)]).upper()


def calculate_x5t(der, hash="sha1"):
    val = certificate_fingerprint(der, hash)
    val = val.replace(":", "")
    return base64.b64encode(as_bytes(val))


def pem_hash(pem_file):
    with open(pem_file, "r") as fp:
        pem = fp.read()

    der = ssl.PEM_cert_to_DER_cert(pem)
    return hashlib.sha1(as_bytes(der)).hexdigest()
