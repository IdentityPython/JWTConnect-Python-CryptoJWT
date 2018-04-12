# from future import standard_library
import os
from struct import pack

try:
    from builtins import object
except ImportError:
    pass

import struct
import logging
import zlib

from math import ceil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.padding import PKCS7

from cryptojwt import as_bytes, b64encode_item
from cryptojwt import as_unicode
from cryptojwt import b64d
from cryptojwt import b64e
from cryptojwt import SimpleJWT
from cryptojwt.exception import WrongNumberOfParts, VerificationError
from cryptojwt.exception import JWKESTException
from cryptojwt.exception import MissingKey
from cryptojwt.jwk import ECKey
from cryptojwt.jwk import intarr2str
from cryptojwt.jwk import NIST2SEC
from cryptojwt.jws import JWx
from cryptojwt.jwk import SYMKey

logger = logging.getLogger(__name__)

__author__ = 'Roland Hedberg'

ENC = 1
DEC = 0


class JWEException(JWKESTException):
    pass


class CannotDecode(JWEException):
    pass


class NotSupportedAlgorithm(JWEException):
    pass


class MethodNotSupported(JWEException):
    pass


class ParameterError(JWEException):
    pass


class NoSuitableEncryptionKey(JWEException):
    pass


class NoSuitableDecryptionKey(JWEException):
    pass


class NoSuitableECDHKey(JWEException):
    pass


class DecryptionFailed(JWEException):
    pass


class WrongEncryptionAlgorithm(JWEException):
    pass


class UnsupportedBitLength(JWEException):
    pass


# ---------------------------------------------------------------------------
# Base class

KEY_LEN = {
    "A128GCM": 128,
    "A192GCM": 192,
    "A256GCM": 256,
    "A128CBC-HS256": 256,
    "A192CBC-HS384": 384,
    "A256CBC-HS512": 512
}

KEY_LEN_BYTES = dict([(s, int(n / 8)) for s, n in KEY_LEN.items()])

LENMET = {
    32: (16, SHA256),
    48: (24, SHA384),
    64: (32, SHA512)
}


def get_keys_seclen_dgst(key, iv):
    # Validate input
    if len(iv) != 16:
        raise Exception("IV for AES-CBC must be 16 octets long")

    # Select the digest to use based on key length
    try:
        seclen, hash_method = LENMET[len(key)]
    except KeyError:
        raise Exception("Invalid CBC+HMAC key length: %s bytes" % len(key))

    # Split the key
    ka = key[:seclen]
    ke = key[seclen:]

    return ka, ke, seclen, hash_method


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


class RSAEncrypter(Encrypter):
    def encrypt(self, msg, key, sign_padding="pkcs1_padding"):
        _chosen_hash = hashes.SHA1
        if sign_padding == "pkcs1_padding":
            _padding = padding.PKCS1v15
            return key.encrypt(msg, _padding())
        elif sign_padding == "pkcs1_oaep_padding":
            _padding = padding.OAEP
        elif sign_padding == "pkcs1_oaep_256_padding":
            _padding = padding.OAEP
            _chosen_hash = hashes.SHA256
        else:
            raise Exception("Unsupported padding")
        return key.encrypt(msg,
                           _padding(mgf=padding.MGF1(algorithm=_chosen_hash()),
                                    algorithm=_chosen_hash(), label=None))

    def decrypt(self, ciphertext, key, sign_padding="pkcs1_padding"):
        _chosen_hash = hashes.SHA1
        if sign_padding == "pkcs1_padding":
            _padding = padding.PKCS1v15
            return key.decrypt(ciphertext, _padding())
        elif sign_padding == "pkcs1_oaep_padding":
            _padding = padding.OAEP
        elif sign_padding == "pkcs1_oaep_256_padding":
            _padding = padding.OAEP
            _chosen_hash = hashes.SHA256
        else:
            raise Exception("Unsupported padding")

        try:
            text = key.decrypt(ciphertext,
                               _padding(
                                   mgf=padding.MGF1(algorithm=_chosen_hash()),
                                   algorithm=_chosen_hash(), label=None))
        except Exception:
            raise

        return text


class AES_CBCEncrypter(Encrypter):
    """
    """

    def __init__(self, key_len=32, key=None, msg_padding='PKCS7'):
        Encrypter.__init__(self)
        if key:
            self.key = key
        else:
            self.key = os.urandom(key_len)

        if msg_padding == 'PKCS7':
            self.padder = PKCS7(128).padder()
            self.unpadder = PKCS7(128).unpadder()

    def _mac(self, hash_key, hash_func, auth_data, iv, enc_msg, key_len):
        al = pack("!Q", 8 * len(auth_data))
        h = hmac.HMAC(hash_key, hash_func(), backend=default_backend())
        h.update(auth_data)
        h.update(iv)
        h.update(enc_msg)
        h.update(al)
        m = h.finalize()
        return m[:key_len]

    def encrypt(self, msg, iv='', auth_data=b''):
        if not iv:
            iv = os.urandom(16)

        hash_key, enc_key, key_len, hash_func = get_keys_seclen_dgst(self.key,
                                                                     iv)

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        pmsg = self.padder.update(msg)
        pmsg += self.padder.finalize()
        ct = encryptor.update(pmsg)
        ct += encryptor.finalize()
        tag = self._mac(hash_key, hash_func, auth_data, iv, ct, key_len)
        return ct, tag

    def decrypt(self, msg, iv='', auth_data=b'', tag=b'', key=None):
        if key is None:
            key = self.key

        hash_key, enc_key, key_len, hash_func = get_keys_seclen_dgst(key, iv)

        comp_tag = self._mac(hash_key, hash_func, auth_data, iv, msg, key_len)
        if comp_tag != tag:
            raise VerificationError('AES-CBC HMAC')

        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        ctext = decryptor.update(msg)
        ctext += decryptor.finalize()
        unpad = self.unpadder.update(ctext)
        unpad += self.unpadder.finalize()
        return unpad


class AES_GCMEncrypter(Encrypter):
    def __init__(self, bit_length=0, key=None):
        Encrypter.__init__(self)
        if key:
            self.key = AESGCM(key)
        elif bit_length:
            if bit_length not in [128, 192, 256]:
                raise UnsupportedBitLength(bit_length)

            self.key = AESGCM.generate_key(bit_length=bit_length)

    def encrypt(self, msg, iv='', auth_data=None):
        """
        Encrypts and authenticates the data provided as well as authenticating
        the associated_data.

        :param msg: The message to be encrypted
        :param iv: MUST be present, at least 96-bit long
        :param auth_data: Associated data
        :return: The ciphertext bytes with the 16 byte tag appended.
        """
        if not iv:
            raise ValueError('Missing Nonce')

        return self.key.encrypt(iv, msg, auth_data)

    def decrypt(self, cipher_text, iv='', auth_data=None, tag=b''):
        """
        Decrypts the data and authenticates the associated_data (if provided).

        :param cipher_text: The data to decrypt including tag
        :param iv: Initialization Vector
        :param auth_data: Associated data
        :param tag: Authentication tag
        :return: The original plaintext
        """
        if not iv:
            raise ValueError('Missing Nonce')

        return self.key.decrypt(iv, cipher_text+tag, auth_data)


# ---------------------------------------------------------------------------

def int2big_endian(n):
    return [ord(c) for c in struct.pack('>I', n)]


def party_value(pv):
    if pv:
        s = b64e(pv)
        r = int2big_endian(len(s))
        r.extend(s)
        return r
    else:
        return [0, 0, 0, 0]


def _hash_input(cmk, enc, label, rond=1, length=128, hashsize=256,
                epu="", epv=""):
    r = [0, 0, 0, rond]
    r.extend(cmk)
    r.extend([0, 0, 0, length])
    r.extend([ord(c) for c in enc])
    r.extend(party_value(epu))
    r.extend(party_value(epv))
    r.extend(label)
    return r


# ---------------------------------------------------------------------------


def keysize(spec):
    if spec.startswith("HS"):
        return int(spec[2:])
    elif spec.startswith("CS"):
        return int(spec[2:])
    elif spec.startswith("A"):
        return int(spec[1:4])
    return 0


ENC2ALG = {"A128CBC": "aes_128_cbc", "A192CBC": "aes_192_cbc",
           "A256CBC": "aes_256_cbc"}

SUPPORTED = {
    "alg": ["RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW",
            "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"],
    "enc": ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
            "A128GCM", "A192GCM", "A256GCM"],
}


def alg2keytype(alg):
    if alg.startswith("RSA"):
        return "RSA"
    elif alg.startswith("A"):
        return "oct"
    elif alg.startswith("ECDH"):
        return "EC"
    else:
        return None


# =============================================================================


class JWEnc(SimpleJWT):
    def b64_protected_header(self):
        return self.b64part[0]

    def b64_encrypted_key(self):
        return self.b64part[1]

    def b64_initialization_vector(self):
        return self.b64part[2]

    def b64_ciphertext(self):
        return self.b64part[3]

    def b64_authentication_tag(self):
        return self.b64part[4]

    def protected_header(self):
        return self.part[0]

    def encrypted_key(self):
        return self.part[1]

    def initialization_vector(self):
        return self.part[2]

    def ciphertext(self):
        return self.part[3]

    def authentication_tag(self):
        return self.part[4]

    def b64_encode_header(self):
        return b64encode_item(self.headers)

    def is_jwe(self):
        if "typ" in self.headers and self.headers["typ"].lower() == "jwe":
            return True

        if "alg" in self.headers and "enc" in self.headers:
            for typ in ["alg", "enc"]:
                if self.headers[typ] not in SUPPORTED[typ]:
                    logger.debug("Not supported %s algorithm: %s" % (
                        typ, self.headers[typ]))
                    return False
        else:
            return False
        return True

    def __len__(self):
        return len(self.part)


def split_ctx_and_tag(ctext):
    tag_length = 16
    tag = ctext[-tag_length:]
    ciphertext = ctext[:-tag_length]
    return ciphertext, tag


def get_random_bytes(len):
    return os.urandom(len)


class JWe(JWx):
    @staticmethod
    def _generate_iv(encalg, iv=""):
        if iv:
            return iv
        else:
            _iv = get_random_bytes(16)

        return _iv

    @staticmethod
    def _generate_key(encalg, cek=""):
        if cek:
            return cek

        try:
            _key = get_random_bytes(KEY_LEN_BYTES[encalg])
        except KeyError:
            try:
                _key = get_random_bytes(KEY_LEN_BYTES[encalg])
            except KeyError:
                raise Exception("Unsupported encryption algorithm %s" % encalg)

        return _key

    def alg2keytype(self, alg):
        return alg2keytype(alg)

    def enc_setup(self, enc_alg, msg, auth_data=b'', key=None, iv=""):
        """ Encrypt JWE content.

        :param enc_alg: The JWE "enc" value specifying the encryption algorithm
        :param msg: The plain text message
        :param auth_data: Additional authenticated data
        :param key: Key (CEK)
        :return: Tuple (ciphertext, tag), both as bytes
        """

        iv = self._generate_iv(enc_alg, iv)

        if enc_alg in ["A192GCM", "A128GCM", "A256GCM"]:
            aes = AES_GCMEncrypter(key=key)
            ctx, tag = split_ctx_and_tag(aes.encrypt(msg, iv, auth_data))
        elif enc_alg in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
            aes = AES_CBCEncrypter(key=key)
            ctx, tag = aes.encrypt(msg, iv, auth_data)
        else:
            raise NotSupportedAlgorithm(enc_alg)

        return ctx, tag, aes.key

    @staticmethod
    def _decrypt(enc, key, ctxt, iv, tag, auth_data=b''):
        """ Decrypt JWE content.

        :param enc: The JWE "enc" value specifying the encryption algorithm
        :param key: Key (CEK)
        :param iv : Initialization vector
        :param auth_data: Additional authenticated data (AAD)
        :param ctxt : Ciphertext
        :param tag: Authentication tag
        :return: plain text message or None if decryption failed
        """
        if enc in ["A128GCM", "A192GCM", "A256GCM"]:
            aes = AES_GCMEncrypter(key=key)
        elif enc in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
            aes = AES_CBCEncrypter(key=key)
        else:
            raise Exception("Unsupported encryption algorithm %s" % enc)

        try:
            return aes.decrypt(ctxt, iv=iv, auth_data=auth_data, tag=tag)
        except DecryptionFailed:
            raise


class JWE_SYM(JWe):
    args = JWe.args[:]
    args.append("enc")

    def encrypt(self, key, iv="", cek="", **kwargs):
        """

        :param key: Shared symmetric key
        :param iv: initialization vector
        :param cek:
        :param kwargs: Extra keyword arguments, just ignore for now.
        :return:
        """
        _msg = self.msg

        _args = self._dict
        try:
            _args["kid"] = kwargs["kid"]
        except KeyError:
            pass

        jwe = JWEnc(**_args)

        # If no iv and cek are given generate them
        iv = self._generate_iv(self["enc"], iv)
        cek = self._generate_key(self["enc"], cek)
        if isinstance(key, SYMKey):
            try:
                kek = key.key.encode('utf8')
            except AttributeError:
                kek = key.key
        elif isinstance(key, bytes):
            kek = key
        else:
            kek = intarr2str(key)

        # The iv for this function must be 64 bit
        # Which is certainly different from the one above
        jek = aes_key_wrap(kek, cek, default_backend())

        _enc = self["enc"]
        _auth_data = jwe.b64_encode_header()
        ctxt, tag, cek = self.enc_setup(_enc, _msg.encode(),
                                        auth_data=_auth_data, key=cek, iv=iv)
        return jwe.pack(parts=[jek, iv, ctxt, tag])

    def decrypt(self, token, key=None, cek=None):
        logger.debug('SYM decrypt')
        if not key and not cek:
            raise MissingKey("On of key or cek must be specified")

        if isinstance(token, JWEnc):
            jwe = token
        else:
            jwe = JWEnc().unpack(token)

        if len(jwe) != 5:
            raise WrongNumberOfParts(len(jwe))

        if not cek:
            jek = jwe.encrypted_key()
            if isinstance(key, SYMKey):
                try:
                    key = key.key.encode('utf8')
                except AttributeError:
                    key = key.key
            # The iv for this function must be 64 bit
            cek = aes_key_unwrap(key, jek, default_backend())

        auth_data = jwe.b64_protected_header()
        msg = self._decrypt(
            jwe.headers["enc"], cek, jwe.ciphertext(),
            auth_data=auth_data,
            iv=jwe.initialization_vector(), tag=jwe.authentication_tag())

        if "zip" in self and self["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg


class JWE_RSA(JWe):
    args = ["msg", "alg", "enc", "epk", "zip", "jku", "jwk", "x5u", "x5t",
            "x5c", "kid", "typ", "cty", "apu", "crit"]

    def encrypt(self, key, iv="", cek="", **kwargs):
        """
        Produces a JWE using RSA algorithms

        :param key: RSA key
        :param context:
        :param iv:
        :param cek:
        :return: A jwe
        """

        _msg = as_bytes(self.msg)
        if "zip" in self:
            if self["zip"] == "DEF":
                _msg = zlib.compress(_msg)
            else:
                raise ParameterError("Zip has unknown value: %s" % self["zip"])

        kwarg_cek = cek or None

        _enc = self["enc"]
        iv = self._generate_iv(_enc, iv)
        cek = self._generate_key(_enc, cek)
        self["cek"] = cek

        logger.debug("cek: %s, iv: %s" % ([c for c in cek], [c for c in iv]))

        _encrypt = RSAEncrypter(self.with_digest).encrypt

        _alg = self["alg"]
        if kwarg_cek:
            jwe_enc_key = ''
        elif _alg == "RSA-OAEP":
            jwe_enc_key = _encrypt(cek, key, 'pkcs1_oaep_padding')
        elif _alg == "RSA-OAEP-256":
            jwe_enc_key = _encrypt(cek, key, 'pkcs1_oaep_256_padding')
        elif _alg == "RSA1_5":
            jwe_enc_key = _encrypt(cek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        jwe = JWEnc(**self.headers())

        try:
            _auth_data = kwargs['auth_data']
        except KeyError:
            _auth_data = jwe.b64_encode_header()

        ctxt, tag, key = self.enc_setup(_enc, _msg, key=cek, iv=iv,
                                        auth_data=_auth_data)
        return jwe.pack(parts=[jwe_enc_key, iv, ctxt, tag])

    def decrypt(self, token, key, cek=None):
        """ Decrypts a JWT

        :param token: The JWT
        :param key: A key to use for decrypting
        :param cek: Ephemeral cipher key
        :return: The decrypted message
        """
        if not isinstance(token, JWEnc):
            jwe = JWEnc().unpack(token)
        else:
            jwe = token

        self.jwt = jwe.encrypted_key()
        jek = jwe.encrypted_key()

        _decrypt = RSAEncrypter(self.with_digest).decrypt

        _alg = jwe.headers["alg"]
        if cek:
            pass
        elif _alg == "RSA-OAEP":
            cek = _decrypt(jek, key, 'pkcs1_oaep_padding')
        elif _alg == "RSA-OAEP-256":
            cek = _decrypt(jek, key, 'pkcs1_oaep_256_padding')
        elif _alg == "RSA1_5":
            cek = _decrypt(jek, key)
        else:
            raise NotSupportedAlgorithm(_alg)

        self["cek"] = cek
        enc = jwe.headers["enc"]
        if enc not in SUPPORTED["enc"]:
            raise NotSupportedAlgorithm(enc)

        auth_data = jwe.b64_protected_header()

        msg = self._decrypt(enc, cek, jwe.ciphertext(),
                            auth_data=auth_data,
                            iv=jwe.initialization_vector(),
                            tag=jwe.authentication_tag())

        if "zip" in jwe.headers and jwe.headers["zip"] == "DEF":
            msg = zlib.decompress(msg)

        return msg


def concat_sha256(secret, dk_len, other_info):
    """
    The Concat KDF, using SHA256 as the hash function.

    Note: Does not validate that otherInfo meets the requirements of
    SP800-56A.

    :param secret: The shared secret value
    :param dk_len: Length of key to be derived, in bits
    :param other_info: Other info to be incorporated (see SP800-56A)
    :return: The derived key
    """
    dkm = b''
    dk_bytes = int(ceil(dk_len / 8.0))
    counter = 0
    while len(dkm) < dk_bytes:
        counter += 1
        counter_bytes = struct.pack("!I", counter)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(counter_bytes)
        digest.update(secret)
        digest.update(other_info)
        dkm += digest.finalize()
    return dkm[:dk_bytes]


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
    otherInfo = bytes(alg) + \
                struct.pack("!I", len(apu)) + apu + \
                struct.pack("!I", len(apv)) + apv + \
                struct.pack("!I", dk_len)
    return concat_sha256(shared_key, dk_len, otherInfo)


class JWE_EC(JWe):
    args = JWe.args[:]
    args.append("enc")

    def __init__(self, msg=None, with_digest=False, **kwargs):
        JWe.__init__(self, msg, with_digest, **kwargs)
        self.msg_valid = False
        self.auth_data = b''

    def enc_setup(self, msg, key=None, auth_data=b'', **kwargs):
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
        if not key:
            raise Exception("EC Key Required for ECDH-ES JWE Encryption Setup")

        # epk is either an Elliptic curve key instance or a JWK description of
        # one. This key belongs to the entity on the other side.
        try:
            _epk = kwargs['epk']
        except KeyError:
            _epk = ec.generate_private_key(NIST2SEC[as_unicode(key.crv)],
                                           default_backend())
            epk = ECKey().load_key(_epk.public_key())
        else:
            if isinstance(_epk, ec.EllipticCurvePublicKey):
                epk = ECKey().load_key(_epk)
            elif isinstance(_epk, ECKey):
                epk = _epk
            else:
                raise ValueError("epk of a type I can't handle")

        params = {
            "apu": b64e(apu),
            "apv": b64e(apv),
            "epk": epk.serialize(False)
        }

        cek = iv = None
        if 'cek' in kwargs and kwargs['cek']:
            cek = kwargs['cek']
        if 'iv' in kwargs and kwargs['iv']:
            iv = kwargs['iv']

        iv = self._generate_iv(self.enc, iv=iv)

        if self.alg == "ECDH-ES":
            try:
                dk_len = KEY_LEN[self.enc]
            except KeyError:
                raise Exception(
                    "Unknown key length for algorithm %s" % self.enc)

            cek = ecdh_derive_key(_epk, key.key, apu, apv,
                                  str(self.enc).encode(), dk_len)
        elif self.alg in ["ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
            _pre, _post = self.alg.split("+")
            klen = int(_post[1:4])
            kek = ecdh_derive_key(_epk, key.key, apu, apv,
                                  str(_post).encode(), klen)
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
            raise Exception(
                "Ephemeral Public Key Missing in ECDH-ES Computation")

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

            self.cek = ecdh_derive_key(key, epubkey.key, apu, apv,
                                       str(self.headers["enc"]).encode(),
                                       dk_len)
        elif self.headers["alg"] in ["ECDH-ES+A128KW", "ECDH-ES+A192KW",
                                     "ECDH-ES+A256KW"]:
            _pre, _post = self.headers['alg'].split("+")
            klen = int(_post[1:4])
            kek = ecdh_derive_key(key, epubkey.key, apu, apv,
                                  str(_post).encode(), klen)
            self.cek = aes_key_unwrap(kek, token.encrypted_key(),
                                      default_backend())
        else:
            raise Exception("Unsupported algorithm %s" % self.headers["alg"])

        return self.cek

    def encrypt(self, iv="", cek="", **kwargs):

        _msg = as_bytes(self.msg)
        _args = self._dict
        try:
            _args["kid"] = kwargs["kid"]
        except KeyError:
            pass

        if 'params' in kwargs:
            if 'apu' in kwargs['params']:
                _args['apu'] = kwargs['params']['apu']
            if 'apv' in kwargs['params']:
                _args['apv'] = kwargs['params']['apv']
            if 'epk' in kwargs['params']:
                _args['epk'] = kwargs['params']['epk']

        jwe = JWEnc(**_args)
        ctxt, tag, cek = super(JWE_EC, self).enc_setup(self["enc"], _msg,
                                                       auth_data=jwe.b64_encode_header(),
                                                       key=cek, iv=iv)
        if 'encrypted_key' in kwargs:
            return jwe.pack(parts=[kwargs['encrypted_key'], iv, ctxt, tag])
        return jwe.pack(parts=[iv, ctxt, tag])

    def decrypt(self, token=None, **kwargs):

        if isinstance(token, JWEnc):
            jwe = token
        else:
            jwe = JWEnc().unpack(token)

        if not self.cek:
            raise Exception("Content Encryption Key is Not Yet Set")

        msg = super(JWE_EC, self)._decrypt(self.headers["enc"], self.cek,
                                           self.ctxt,
                                           auth_data=jwe.b64part[0],
                                           iv=self.iv, tag=self.tag)
        self.msg = msg
        self.msg_valid = True
        return msg


KEY_ERR = "Could not find any suitable encryption key for alg='{}'"


class JWE(JWx):
    args = ["alg", "enc", "epk", "zip", "jku", "jwk", "x5u", "x5t",
            "x5c", "kid", "typ", "cty", "apu", "crit"]

    """
    :param msg: The message
    :param alg: Algorithm
    :param enc: Encryption Method
    :param epk: Ephemeral Public Key
    :param zip: Compression Algorithm
    :param jku: a URI that refers to a resource for a set of JSON-encoded
        public keys, one of which corresponds to the key used to digitally
        sign the JWS
    :param jwk: A JSON Web Key that corresponds to the key used to
        digitally sign the JWS
    :param x5u: a URI that refers to a resource for the X.509 public key
        certificate or certificate chain [RFC5280] corresponding to the key
        used to digitally sign the JWS.
    :param x5t: a base64url encoded SHA-1 thumbprint (a.k.a. digest) of the
        DER encoding of the X.509 certificate [RFC5280] corresponding to
        the key used to digitally sign the JWS.
    :param x5c: the X.509 public key certificate or certificate chain
        corresponding to the key used to digitally sign the JWS.
    :param kid: Key ID a hint indicating which key was used to secure the
        JWS.
    :param typ: the type of this object. 'JWS' == JWS Compact Serialization
        'JWS+JSON' == JWS JSON Serialization
    :param cty: Content Type
    :param apu: Agreement PartyUInfo
    :param crit: indicates which extensions that are being used and MUST
        be understood and processed.
    :return: A class instance
    """

    def encrypt(self, keys=None, cek="", iv="", **kwargs):
        """

        :param keys: A set of possibly usable keys
        :param context: If the other party's public or my private key should be
            used for encryption
        :param cek: Content master key
        :param iv: Initialization vector
        :param kwargs: Extra key word arguments
        :return: Encrypted message
        """

        _alg = self["alg"]

        # Find Usable Keys
        if keys:
            keys = self.pick_keys(keys, use="enc")
        else:
            keys = self.pick_keys(self._get_keys(), use="enc")

        if not keys:
            logger.error(KEY_ERR.format(_alg))
            raise NoSuitableEncryptionKey(_alg)

        # Determine Encryption Class by Algorithm
        if _alg in ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]:
            encrypter = JWE_RSA(self.msg, **self._dict)
        elif _alg.startswith("A") and _alg.endswith("KW"):
            encrypter = JWE_SYM(self.msg, **self._dict)
        elif _alg.startswith("ECDH-ES"):

            # ECDH-ES Requires the Server ECDH-ES Key to be set
            if not keys:
                raise NoSuitableECDHKey(_alg)

            encrypter = JWE_EC(**self._dict)
            cek, encrypted_key, iv, params, eprivk = encrypter.enc_setup(
                self.msg, key=keys[0], **self._dict)
            kwargs["encrypted_key"] = encrypted_key
            kwargs["params"] = params
        else:
            logger.error("'{}' is not a supported algorithm".format(_alg))
            raise NotSupportedAlgorithm

        if cek:
            kwargs["cek"] = cek

        if iv:
            kwargs["iv"] = iv

        for key in keys:
            _key = key.encryption_key(alg=_alg, private=False)

            if key.kid:
                encrypter["kid"] = key.kid

            try:
                token = encrypter.encrypt(key=_key, **kwargs)
                self["cek"] = encrypter.cek if 'cek' in encrypter else None
            except TypeError as err:
                raise err
            else:
                logger.debug(
                    "Encrypted message using key with kid={}".format(key.kid))
                return token

        logger.error("Could not find any suitable encryption key")
        raise NoSuitableEncryptionKey()

    def decrypt(self, token=None, keys=None, alg=None, cek=None):
        if token:
            _jwe = JWEnc().unpack(token)
            # header, ek, eiv, ctxt, tag = token.split(b".")
            # self.parse_header(header)
        elif self.jwt:
            _jwe = self.jwt
        else:
            raise ValueError('Nothing to decrypt')

        _alg = _jwe.headers["alg"]
        if alg and alg != _alg:
            raise WrongEncryptionAlgorithm()

        # Find appropriate keys
        if keys:
            keys = self.pick_keys(keys, use="enc", alg=_alg)
        else:
            keys = self.pick_keys(self._get_keys(), use="enc", alg=_alg)

        if not keys and not cek:
            raise NoSuitableDecryptionKey(_alg)

        if _alg in ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]:
            decrypter = JWE_RSA(**self._dict)
        elif _alg.startswith("A") and _alg.endswith("KW"):
            decrypter = JWE_SYM(self.msg, **self._dict)
        elif _alg.startswith("ECDH-ES"):

            # ECDH-ES Requires the Server ECDH-ES Key to be set
            if not keys:
                raise NoSuitableECDHKey(_alg)

            decrypter = JWE_EC(**self._dict)
            cek = decrypter.dec_setup(_jwe, key=keys[0].key)
        else:
            raise NotSupportedAlgorithm

        if cek:
            try:
                msg = decrypter.decrypt(_jwe, cek=cek)
                self["cek"] = decrypter.cek if 'cek' in decrypter else None
            except (KeyError, DecryptionFailed):
                pass
            else:
                logger.debug("Decrypted message using exiting CEK")
                return msg

        for key in keys:
            _key = key.encryption_key(alg=_alg, private=False)
            try:
                msg = decrypter.decrypt(_jwe, _key)
                self["cek"] = decrypter.cek if 'cek' in decrypter else None
            except (KeyError, DecryptionFailed):
                pass
            else:
                logger.debug(
                    "Decrypted message using key with kid=%s" % key.kid)
                return msg

        raise DecryptionFailed(
            "No available key that could decrypt the message")


def factory(token):
    _jwt = JWEnc().unpack(token)
    if _jwt.is_jwe():
        _jwe = JWE()
        _jwe.jwt = _jwt
        return _jwe
    else:
        return None
