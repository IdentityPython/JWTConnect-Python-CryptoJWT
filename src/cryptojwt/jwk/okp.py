from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519, x448, x25519

from cryptojwt.exception import KeyNotFound

from ..exception import DeSerializationNotPossible, JWKESTException, UnsupportedOKPCurve
from ..utils import b64d, b64e
from .asym import AsymmetricKey
from .x509 import (
    import_private_key_from_pem_file,
    import_public_key_from_pem_data,
    import_public_key_from_pem_file,
)

OKPPublicKey = Union[
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    x25519.X25519PublicKey,
    x448.X448PublicKey,
]
OKPPrivateKey = Union[
    ed25519.Ed25519PrivateKey,
    ed448.Ed448PrivateKey,
    x25519.X25519PrivateKey,
    x448.X448PrivateKey,
]

OKP_CRV2PUBLIC = {
    "Ed25519": ed25519.Ed25519PublicKey,
    "Ed448": ed448.Ed448PublicKey,
    "X25519": x25519.X25519PublicKey,
    "X448": x448.X448PublicKey,
}

OKP_CRV2PRIVATE = {
    "Ed25519": ed25519.Ed25519PrivateKey,
    "Ed448": ed448.Ed448PrivateKey,
    "X25519": x25519.X25519PrivateKey,
    "X448": x448.X448PrivateKey,
}

OKP_CRV_SIGN = ["Ed25519", "Ed448"]
OKP_CRV_ENCR = ["X25519", "X448"]


def is_private_key(key) -> bool:
    if isinstance(
        key,
        (
            ed25519.Ed25519PrivateKey,
            ed448.Ed448PrivateKey,
            x25519.X25519PrivateKey,
            x448.X448PrivateKey,
        ),
    ):
        return True
    elif isinstance(
        key,
        (
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
            ed448.Ed448PublicKey,
            x25519.X25519PublicKey,
            x448.X448PublicKey,
        ),
    ):
        return False
    raise TypeError


def deser(val):
    return b64d(val.encode()) if isinstance(val, str) else b64d(val)


class OKPKey(AsymmetricKey):
    """
    JSON Web key representation of an Octet Key Pair key.
    According to RFC 8037 a JWK representation of an OKP key can look like
    this::

        {
          "kty":"OKP",
          "crv":"Ed25519",
          "x":"XWxGtApfcqmKI7p0OKnF5JSEWMVoLsytFXLEP7xZ_l8",
        }

    Parameters according to https://tools.ietf.org/html/rfc8037
    """

    members = AsymmetricKey.members[:]
    # The elliptic curve specific attributes
    members.extend(["crv", "x", "d"])
    longs = ["x", "d"]
    public_members = AsymmetricKey.public_members[:]
    public_members.extend(["kty", "alg", "use", "kid", "crv", "x"])
    # required attributes
    required = ["kty", "crv", "x"]

    def __init__(self, kty="OKP", alg="", use="", kid="", crv="", x="", d="", **kwargs):
        AsymmetricKey.__init__(self, kty, alg, use, kid, **kwargs)
        self.crv = crv
        self.x = x
        self.d = d

        if not self.pub_key and not self.priv_key:
            if self.x and self.crv:
                self.verify()
                self.deserialize()
            elif any([self.x, self.crv]):
                raise JWKESTException("Missing required parameter")
        elif self.priv_key and not self.pub_key:
            self.pub_key = self.priv_key.public_key()
            self._serialize(self.priv_key)

    def deserialize(self):
        """
        Starting with information gathered from the on-the-wire representation
        of an OKP key (a JWK) initiate a OKPPublicKey or OKPPrivateKey instance.
        So we have to get from having::

            {
              "kty":"OKP",
              "crv":"Ed2559",
              "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
              "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
            }

        to having a key that can be used for signing/verifying and/or
        encrypting/decrypting.
        If 'd' has value then we're dealing with a private key otherwise
        a public key. 'x' MUST have a value.
        If self.pub_key or self.priv_key has a value beforehand this will
        be overwrite.

        x and d (if present) must be strings or bytes.
        """

        if isinstance(self.x, (str, bytes)):
            _x = deser(self.x)
        else:
            raise ValueError('"x" MUST be a string')

        if self.d:
            try:
                if isinstance(self.d, (str, bytes)):
                    try:
                        self.priv_key = OKP_CRV2PRIVATE[self.crv].from_private_bytes(deser(self.d))
                    except KeyError as exc:
                        raise UnsupportedOKPCurve(f"Unsupported OKP curve: {self.crv}") from exc
                    self.pub_key = self.priv_key.public_key()
            except ValueError as exc:
                raise DeSerializationNotPossible(str(exc)) from exc
        else:
            try:
                self.pub_key = OKP_CRV2PUBLIC[self.crv].from_public_bytes(_x)
            except KeyError as exc:
                raise UnsupportedOKPCurve(f"Unsupported OKP curve: {self.crv}") from exc

    def _serialize_public(self, key):
        self.x = b64e(
            key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

    def _serialize_private(self, key):
        self._serialize_public(key.public_key())
        self.d = b64e(
            key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode("ascii")

    def _serialize(self, key):
        if isinstance(key, ed25519.Ed25519PublicKey):
            self._serialize_public(key)
            self.crv = "Ed25519"
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            self._serialize_private(key)
            self.crv = "Ed25519"
        elif isinstance(key, x25519.X25519PublicKey):
            self._serialize_public(key)
            self.crv = "X25519"
        elif isinstance(key, x25519.X25519PrivateKey):
            self._serialize_private(key)
            self.crv = "X25519"
        elif isinstance(key, ed448.Ed448PublicKey):
            self._serialize_public(key)
            self.crv = "Ed448"
        elif isinstance(key, ed448.Ed448PrivateKey):
            self._serialize_private(key)
            self.crv = "Ed448"
        elif isinstance(key, x448.X448PublicKey):
            self._serialize_public(key)
            self.crv = "X448"
        elif isinstance(key, x448.X448PrivateKey):
            self._serialize_private(key)
            self.crv = "X448"

    def serialize(self, private=False):
        """
        Go from a OKPPrivateKey or OKPPublicKey instance to a JWK representation.

        :param private: Whether we should include the private attributes or not.
        :return: A JWK as a dictionary
        """
        if self.priv_key:
            self._serialize(self.priv_key)
        else:
            self._serialize(self.pub_key)

        res = self.common()

        res.update({"crv": self.crv, "x": self.x})

        if private and self.d:
            res["d"] = self.d

        return res

    def load_key(self, key):
        """
        Load an Octet Key Pair key

        :param key: An octet key pair key instance, private or public.
        :return: Reference to this instance
        """
        self._serialize(key)

        if is_private_key(key):
            self.priv_key = key
            self.pub_key = key.public_key()
        else:
            self.pub_key = key

        return self

    def load(self, filename):
        """
        Load an Octet Key Pair from a file.

        :param filename: File name
        """
        return self.load_key(import_private_okp_key_from_file(filename))

    def decryption_key(self):
        """
        Get a key appropriate for decrypting a message.

        :return: An OKPPrivateKey instance
        """
        return self.priv_key

    def encryption_key(self):
        """
        Get a key appropriate for encrypting a message.

        :return: An OKPPublicKey instance
        """
        return self.pub_key

    def __hash__(self) -> int:
        return super().__hash__()

    def __eq__(self, other):
        """
        Verify that the other key has the same properties as myself.

        :param other: The other key
        :return: True if the keys as the same otherwise False
        """

        if self.__class__ != other.__class__:
            return False

        _public_cls = OKP_CRV2PUBLIC[self.crv]
        _private_cls = OKP_CRV2PRIVATE[self.crv]
        if cmp_keys(self.pub_key, other.pub_key, _public_cls):
            if other.private_key():
                if cmp_keys(self.priv_key, other.priv_key, _private_cls):
                    return True
            else:
                return not self.private_key()

        return False

    def key_len(self):
        if self.priv_key:
            return self.priv_key.key_size
        elif self.pub_key:
            return self.pub_key.key_size
        else:
            raise KeyNotFound


def cmp_keys(a, b, key_type):
    if isinstance(a, key_type):
        if isinstance(b, key_type):
            if is_private_key(a):
                if a.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                ) != b.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                ):
                    return False
            else:
                if a.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ) != b.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ):
                    return False
            return True

    return False


def new_okp_key(crv, kid="", **kwargs):
    _key = OKP_CRV2PRIVATE[crv].generate()

    _rk = OKPKey(priv_key=_key, kid=kid, **kwargs)
    if not kid:
        _rk.add_kid()

    return _rk


def import_public_okp_key_from_file(filename):
    """
    Read a public Octet Key Pair key from a PEM file.

    :param filename: The name of the file
    :param passphrase: A pass phrase to use to unpack the PEM file.
    :return: A cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey instance
    """
    public_key = import_public_key_from_pem_file(filename)
    if not is_private_key(public_key):
        return public_key
    else:
        return ValueError("Not a Octet Key Pair key")


def import_private_okp_key_from_file(filename, passphrase=None):
    """
    Read a private Octet Key Pair key from a PEM file.

    :param filename: The name of the file
    :param passphrase: A pass phrase to use to unpack the PEM file.
    :return: A cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
        instance
    """
    private_key = import_private_key_from_pem_file(filename, passphrase)
    if is_private_key(private_key):
        return private_key
    else:
        return ValueError("Not a private Octet Key Pair key")


def import_okp_key(pem_data):
    """
    Extract an Octet Key Pair key from a PEM-encoded X.509 certificate

    :param pem_data: Elliptic Curve key encoded in standard form
    :return: ec.EllipticCurvePublicKey
    """
    public_key = import_public_key_from_pem_data(pem_data)
    if not is_private_key(public_key):
        return public_key
    else:
        return ValueError("Not a Octet Key Pair key")


def import_okp_key_from_cert_file(pem_file):
    with open(pem_file) as cert_file:
        return import_okp_key(cert_file.read())
