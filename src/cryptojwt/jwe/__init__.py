KEY_LEN = {
    "A128GCM": 128,
    "A192GCM": 192,
    "A256GCM": 256,
    "A128CBC-HS256": 256,
    "A192CBC-HS384": 384,
    "A256CBC-HS512": 512,
}

KEY_LEN_BYTES = dict([(s, int(n / 8)) for s, n in KEY_LEN.items()])

SUPPORTED = {
    "alg": [
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
    ],
    "enc": [
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
    ],
}


class Encrypter(object):
    """Abstract base class for encryption algorithms."""

    def __init__(self, with_digest=False):
        self.with_digest = with_digest

    def encrypt(self, msg, key, **kwargs):
        """Encrypt ``msg`` with ``key`` and return the encrypted message."""
        raise NotImplementedError

    def decrypt(self, msg, key, **kwargs):
        """Return decrypted message."""
        raise NotImplementedError
