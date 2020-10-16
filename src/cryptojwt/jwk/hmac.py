import logging
import os

from ..exception import JWKException
from ..exception import UnsupportedAlgorithm
from ..exception import WrongUsage
from ..utils import as_bytes
from ..utils import as_unicode
from ..utils import b64d
from ..utils import b64e
from . import JWK
from . import USE
from .utils import sha256_digest
from .utils import sha384_digest
from .utils import sha512_digest

logger = logging.getLogger(__name__)

ALG2KEYLEN = {
    "A128KW": 16,
    "A192KW": 24,
    "A256KW": 32,
    "HS256": 32,
    "HS384": 48,
    "HS512": 64,
}


class SYMKey(JWK):
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

    members = JWK.members[:]
    members.extend(["kty", "alg", "use", "kid", "k"])
    public_members = JWK.public_members[:]
    required = ["k", "kty"]

    def __init__(
        self, kty="oct", alg="", use="", kid="", x5c=None, x5t="", x5u="", k="", key="", **kwargs
    ):
        JWK.__init__(self, kty, alg, use, kid, x5c, x5t, x5u, **kwargs)
        self.k = k
        self.key = as_bytes(key)
        if not self.key and self.k:
            if isinstance(self.k, str):
                self.k = self.k.encode("utf-8")
            self.key = b64d(bytes(self.k))

        if len(self.key) < 16:
            raise UnsupportedAlgorithm("client_secret too short, it should be at least 16 digits")

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

    def appropriate_for(self, usage, alg="HS256"):
        """
        Make sure there is a key instance present that can be used for
        the specified usage.
        """
        try:
            _use = USE[usage]
        except:
            raise ValueError("Unknown key usage")
        else:
            if not self.use or self.use == _use:
                if _use == "sig":
                    return self.get_key()
                else:
                    return self.encryption_key(alg)

            raise WrongUsage("This key can't be used for {}".format(usage))

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

        try:
            tsize = ALG2KEYLEN[alg]
        except KeyError:
            raise UnsupportedAlgorithm(alg)

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

        logger.debug("Symmetric encryption key: {}".format(as_unicode(b64e(_enc_key))))

        return _enc_key

    def __eq__(self, other):
        """
        Compare 2 JWK instances to find out if they represent the same key

        :param other: The other JWK instance
        :return: True if they are the same otherwise False.
        """
        if self.__class__ != other.__class__:
            return False

        if set(self.__dict__.keys()) != set(other.__dict__.keys()):
            return False

        if self.key != other.key:
            return False

        for key in self.public_members:
            if getattr(other, key) != getattr(self, key):
                if key == "kid":
                    # if one has a value and the other not then assume they are the same
                    if getattr(self, key) == "" or getattr(other, key) == "":
                        return True
                return False

        return True


def new_sym_key(use="", bytes=24, kid=""):
    _key = SYMKey(use=use, kid=kid, key=as_unicode(os.urandom(bytes)))
    if not _key.kid:
        _key.add_kid()
    return _key
