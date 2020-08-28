import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from ..jwk.ec import NIST2SEC
from ..jwk.ec import ECKey
from ..utils import as_bytes
from ..utils import as_unicode
from ..utils import b64d
from ..utils import b64e
from . import KEY_LEN
from .jwekey import JWEKey
from .jwenc import JWEnc
from .utils import concat_sha256
from .utils import get_random_bytes


def ecdh_derive_key(key, epk, apu, apv, alg, dk_len):
    """
    ECDH key derivation, as defined by JWA

    :param key  : Elliptic curve private key
    :param epk  : Elliptic curve public key
    :param apu  : PartyUInfo
    :param apv  : PartyVInfo
    :param alg  : Algorithm identifier
    :param dk_len: Length of key to be derived, in bits
    :return: The derived key
    """
    # Compute shared secret
    shared_key = key.exchange(ec.ECDH(), epk)
    # Derive the key
    # AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
    otherInfo = (
        struct.pack("!I", len(alg))
        + bytes(alg)
        + struct.pack("!I", len(apu))
        + apu
        + struct.pack("!I", len(apv))
        + apv
        + struct.pack("!I", dk_len)
    )
    return concat_sha256(shared_key, dk_len, otherInfo)


class JWE_EC(JWEKey):
    args = JWEKey.args[:]
    args.append("enc")

    def __init__(self, msg=None, with_digest=False, **kwargs):
        JWEKey.__init__(self, msg, with_digest, **kwargs)
        self.msg_valid = False
        self.auth_data = b""

    def enc_setup(self, msg, key=None, auth_data=b"", **kwargs):
        """

        :param msg: Message to be encrypted
        :param auth_data:
        :param key: An EC key
        :param kwargs:
        :return:
        """
        encrypted_key = ""
        self.msg = msg
        self.auth_data = auth_data

        # Generate the input parameters
        try:
            apu = b64d(kwargs["apu"])
        except KeyError:
            apu = get_random_bytes(16)
        try:
            apv = b64d(kwargs["apv"])
        except KeyError:
            apv = get_random_bytes(16)

        # Handle Local Key and Ephemeral Public Key
        if not key or not isinstance(key, ECKey):
            raise ValueError("EC Key Required for ECDH-ES JWE Encryption Setup")

        # epk is either an Elliptic curve key instance or a JWK description of
        # one. This key belongs to the entity on the other side.
        try:
            _epk = kwargs["epk"]
        except KeyError:
            _epk = ec.generate_private_key(NIST2SEC[as_unicode(key.crv)], default_backend())
            epk = ECKey().load_key(_epk.public_key())
        else:
            if isinstance(_epk, ec.EllipticCurvePrivateKey):
                epk = ECKey().load_key(_epk)
            elif isinstance(_epk, ECKey):
                epk = _epk
                _epk = epk.private_key()
            else:
                raise ValueError("epk of a type I can't handle")

        params = {"apu": b64e(apu), "apv": b64e(apv), "epk": epk.serialize(False)}

        cek = iv = None
        if "cek" in kwargs and kwargs["cek"]:
            cek = kwargs["cek"]
        if "iv" in kwargs and kwargs["iv"]:
            iv = kwargs["iv"]

        iv = self._generate_iv(self.enc, iv=iv)

        if self.alg == "ECDH-ES":
            try:
                dk_len = KEY_LEN[self.enc]
            except KeyError:
                raise ValueError("Unknown key length for algorithm %s" % self.enc)

            cek = ecdh_derive_key(_epk, key.pub_key, apu, apv, str(self.enc).encode(), dk_len)
        elif self.alg in ["ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            _pre, _post = self.alg.split("+")
            klen = int(_post[1:4])
            kek = ecdh_derive_key(_epk, key.pub_key, apu, apv, str(_post).encode(), klen)
            cek = self._generate_key(self.enc, cek=cek)
            encrypted_key = aes_key_wrap(kek, cek, default_backend())
        else:
            raise Exception("Unsupported algorithm %s" % self.alg)

        return cek, encrypted_key, iv, params, epk

    def dec_setup(self, token, key=None, **kwargs):
        """

        :param token: signed JSON Web token
        :param key: Private Elliptic Curve Key
        :param kwargs:
        :return:
        """
        self.headers = token.headers
        self.iv = token.initialization_vector()
        self.ctxt = token.ciphertext()
        self.tag = token.authentication_tag()

        # Handle EPK / Curve
        if "epk" not in self.headers or "crv" not in self.headers["epk"]:
            raise Exception("Ephemeral Public Key Missing in ECDH-ES Computation")

        epubkey = ECKey(**self.headers["epk"])
        apu = apv = ""
        if "apu" in self.headers:
            apu = b64d(self.headers["apu"].encode())
        if "apv" in self.headers:
            apv = b64d(self.headers["apv"].encode())

        if self.headers["alg"] == "ECDH-ES":
            try:
                dk_len = KEY_LEN[self.headers["enc"]]
            except KeyError:
                raise Exception("Unknown key length for algorithm")

            self.cek = ecdh_derive_key(
                key,
                epubkey.pub_key,
                apu,
                apv,
                str(self.headers["enc"]).encode(),
                dk_len,
            )
        elif self.headers["alg"] in [
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW",
        ]:
            _pre, _post = self.headers["alg"].split("+")
            klen = int(_post[1:4])
            kek = ecdh_derive_key(key, epubkey.pub_key, apu, apv, str(_post).encode(), klen)
            self.cek = aes_key_unwrap(kek, token.encrypted_key(), default_backend())
        else:
            raise Exception("Unsupported algorithm %s" % self.headers["alg"])

        return self.cek

    def encrypt(self, key=None, iv="", cek="", **kwargs):
        """
        Produces a JWE as defined in RFC7516 using an Elliptic curve key

        :param key: *Not used*, only there to present the same API as JWE_RSA and JWE_SYM
        :param iv: Initialization vector
        :param cek: Content master key
        :param kwargs: Extra keyword arguments
        :return: An encrypted JWT
        """
        _msg = as_bytes(self.msg)

        _args = self._dict
        try:
            _args["kid"] = kwargs["kid"]
        except KeyError:
            pass

        if "params" in kwargs:
            if "apu" in kwargs["params"]:
                _args["apu"] = kwargs["params"]["apu"]
            if "apv" in kwargs["params"]:
                _args["apv"] = kwargs["params"]["apv"]
            if "epk" in kwargs["params"]:
                _args["epk"] = kwargs["params"]["epk"]

        jwe = JWEnc(**_args)
        ctxt, tag, cek = super(JWE_EC, self).enc_setup(
            self["enc"], _msg, auth_data=jwe.b64_encode_header(), key=cek, iv=iv
        )
        if "encrypted_key" in kwargs:
            return jwe.pack(parts=[kwargs["encrypted_key"], iv, ctxt, tag])
        return jwe.pack(parts=[iv, ctxt, tag])

    def decrypt(self, token=None, **kwargs):

        if isinstance(token, JWEnc):
            jwe = token
        else:
            jwe = JWEnc().unpack(token)

        if not self.cek:
            raise Exception("Content Encryption Key is Not Yet Set")

        msg = super(JWE_EC, self)._decrypt(
            self.headers["enc"],
            self.cek,
            self.ctxt,
            auth_data=jwe.b64part[0],
            iv=self.iv,
            tag=self.tag,
        )
        self.msg = msg
        self.msg_valid = True
        return msg
