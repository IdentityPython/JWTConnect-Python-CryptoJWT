# from __future__ import print_function
import array
import hashlib
import os
import random
import string
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from cryptojwt.exception import BadSyntax, HeaderError, MissingKey, Unsupported, VerificationError
from cryptojwt.jwe.aes import AES_CBCEncrypter, AES_GCMEncrypter
from cryptojwt.jwe.exception import (
    NoSuitableDecryptionKey,
    NoSuitableEncryptionKey,
    UnsupportedBitLength,
    WrongEncryptionAlgorithm,
)
from cryptojwt.jwe.fernet import FernetEncrypter
from cryptojwt.jwe.jwe import JWE, factory
from cryptojwt.jwe.jwe_ec import JWE_EC
from cryptojwt.jwe.jwe_hmac import JWE_SYM
from cryptojwt.jwe.jwe_rsa import JWE_RSA
from cryptojwt.jwe.utils import split_ctx_and_tag
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey, import_private_rsa_key_from_file
from cryptojwt.utils import as_bytes, b64e

__author__ = "rohe0002"

from cryptojwt.utils import is_jwe


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(size)])


def intarr2bytes(arr):
    return array.array("B", arr).tobytes()


def bytes2intarr(bts):
    return [b for b in bts]


def str2intarr(string):
    return array.array("B", string).tolist()


to_intarr = str2intarr if sys.version < "3" else bytes2intarr


def test_jwe_09_a1():
    # RSAES OAEP and AES GCM
    msg = b"The true sign of intelligence is not knowledge but imagination."

    # A.1.1
    header = b'{"alg":"RSA-OAEP","enc":"A256GCM"}'
    b64_header = b64e(header)

    # A.1.2
    assert b64_header == b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"

    # A.1.3
    cek = intarr2bytes(
        [
            177,
            161,
            244,
            128,
            84,
            143,
            225,
            115,
            63,
            180,
            3,
            255,
            107,
            154,
            212,
            246,
            138,
            7,
            110,
            91,
            112,
            46,
            34,
            105,
            47,
            130,
            203,
            46,
            122,
            234,
            64,
            252,
        ]
    )

    # A.1.4 Key Encryption
    # enc_key = [
    #     56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
    #     22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
    #     82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
    #     145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
    #     74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
    #     13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
    #     173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
    #     89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
    #     243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
    #     41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
    #     215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
    #     63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
    #     193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
    #     206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
    #     104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
    #     89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
    #     172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
    #     117, 114, 135, 206]

    b64_ejek = (
        b"ApfOLCaDbqs_JXPYy2I937v_xmrzj"
        b"-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH"
        b"-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw"
    )

    iv = intarr2bytes([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219])

    aadp = b64_header + b"." + b64_ejek

    gcm = AES_GCMEncrypter(key=cek)
    ctxt, tag = split_ctx_and_tag(gcm.encrypt(msg, iv, aadp))

    _va = to_intarr(ctxt)
    assert _va == [
        229,
        236,
        166,
        241,
        53,
        191,
        115,
        196,
        174,
        43,
        73,
        109,
        39,
        122,
        233,
        96,
        140,
        206,
        120,
        52,
        51,
        237,
        48,
        11,
        190,
        219,
        186,
        80,
        111,
        104,
        50,
        142,
        47,
        167,
        59,
        61,
        181,
        127,
        196,
        21,
        40,
        82,
        242,
        32,
        123,
        143,
        168,
        226,
        73,
        216,
        176,
        144,
        138,
        247,
        106,
        60,
        16,
        205,
        160,
        109,
        64,
        63,
        192,
    ]

    assert bytes2intarr(tag) == [
        130,
        17,
        32,
        198,
        120,
        167,
        144,
        113,
        0,
        50,
        158,
        49,
        102,
        208,
        118,
        152,
    ]

    # tag = long2hexseq(tag)
    # iv = long2hexseq(iv)
    res = b".".join([b64_header, b64_ejek, b64e(iv), b64e(ctxt), b64e(tag)])

    # print(res.split(b'.'))
    expected = b".".join(
        [
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ",
            b"ApfOLCaDbqs_JXPYy2I937v_xmrzj"
            b"-Iss1mG6NAHmeJViM6j2l0MHvfseIdHVyU2BIoGVu9ohvkkWiRq5DL2jYZTPA9TAdwq3FUIVyoH"
            b"-Pedf6elHIVFi2KGDEspYMtQARMMSBcS7pslx6flh1Cfh3GBKysztVMEhZ_maFkm4PYVCsJsvq6Ct3fg2CJPOs0X1DHuxZKoIGIqcbeK4XEO5a0h5TAuJObKdfO0dKwfNSSbpu5sFrpRFwV2FTTYoqF4zI46N9-_hMIznlEpftRXhScEJuZ9HG8C8CHB1WRZ_J48PleqdhF4o7fB5J1wFqUXBtbtuGJ_A2Xe6AEhrlzCOw",
            b"48V1_ALb6US04U3b",
            b"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A",
            b"ghEgxninkHEAMp4xZtB2mA",
        ]
    )

    assert res == expected


def sha256_digest(msg):
    return hashlib.sha256(msg).digest()


def test_aesgcm_bit_length():
    encrypter = AES_GCMEncrypter(bit_length=192)
    enc_msg = encrypter.encrypt(b"Murder must advertise.", b"Dorothy L. Sayers")
    ctx, tag = split_ctx_and_tag(enc_msg)
    _msg = encrypter.decrypt(ctx, iv=b"Dorothy L. Sayers", tag=tag)
    assert _msg == b"Murder must advertise."


def test_aesgcm_unsupported_bit_length():
    with pytest.raises(UnsupportedBitLength):
        AES_GCMEncrypter(bit_length=164)


def test_aesgcm_no_key_or_bit_length():
    with pytest.raises(ValueError):
        AES_GCMEncrypter()


def test_aesgcm_missing_iv_on_encrypt():
    encrypter = AES_GCMEncrypter(bit_length=192)
    with pytest.raises(ValueError):
        encrypter.encrypt(b"Murder must advertise.")


def test_aesgcm_missing_iv_on_decrypt():
    encrypter = AES_GCMEncrypter(bit_length=192)
    enc_msg = encrypter.encrypt(b"Murder must advertise.", b"Dorothy L. Sayers")
    ctx, tag = split_ctx_and_tag(enc_msg)
    with pytest.raises(ValueError):
        encrypter.decrypt(ctx, tag=tag)


def test_aes_cbc():
    encrypter = AES_CBCEncrypter()
    orig_msg = b"Murder must advertise."
    iv = b"Dorothy L Sayers"
    ctx, tag = encrypter.encrypt(orig_msg, iv)
    _msg = encrypter.decrypt(ctx, iv=iv, tag=tag)
    assert _msg == orig_msg


def test_aes_cbc_unsupported_padding():
    with pytest.raises(Unsupported):
        AES_CBCEncrypter(msg_padding="ABC")


def test_aes_cbc_no_iv():
    encrypter = AES_CBCEncrypter()
    orig_msg = b"Murder must advertise."
    ctx, tag = encrypter.encrypt(orig_msg)
    _msg = encrypter.decrypt(ctx, iv=encrypter.iv, tag=tag)
    assert _msg == orig_msg


def test_aes_cbc_wrong_tag():
    encrypter = AES_CBCEncrypter()
    orig_msg = b"Murder must advertise."
    ctx, tag = encrypter.encrypt(orig_msg)
    with pytest.raises(VerificationError):
        encrypter.decrypt(ctx, iv=encrypter.iv, tag=b"12346567890")


def test_aes_cbc_missing_decrypt_key():
    encrypter = AES_CBCEncrypter()
    orig_msg = b"Murder must advertise."
    ctx, tag = encrypter.encrypt(orig_msg)
    encrypter.key = None
    with pytest.raises(MissingKey):
        encrypter.decrypt(ctx, iv=encrypter.iv, tag=b"12346567890")


BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


KEY = full_path("rsa.key")

priv_key = import_private_rsa_key_from_file(KEY)
pub_key = priv_key.public_key()
plain = b"Now is the time for all good men to come to the aid of their country."


def test_cek_reuse_encryption_rsaes_rsa15():
    _rsa = JWE_RSA(plain, alg="RSA1_5", enc="A128CBC-HS256")
    jwt = _rsa.encrypt(pub_key)
    dec = JWE_RSA()
    msg = dec.decrypt(jwt, priv_key)

    assert msg == plain

    _rsa2 = JWE_RSA(plain, alg="RSA1_5", enc="A128CBC-HS256")
    jwt = _rsa2.encrypt(None, cek=dec["cek"])
    dec2 = JWE_RSA()
    msg = dec2.decrypt(jwt, None, cek=_rsa["cek"])

    assert msg == plain


def test_cek_reuse_encryption_rsaes_rsa_oaep():
    _rsa = JWE_RSA(plain, alg="RSA-OAEP", enc="A256GCM")
    jwt = _rsa.encrypt(pub_key)
    dec = JWE_RSA()
    msg = dec.decrypt(jwt, priv_key)

    assert msg == plain

    _rsa2 = JWE_RSA(plain, alg="RSA-OAEP", enc="A256GCM")
    jwt = _rsa2.encrypt(None, cek=dec["cek"])
    dec2 = JWE_RSA()
    msg = dec2.decrypt(jwt, None, cek=_rsa["cek"])

    assert msg == plain


def test_rsa_encrypt_decrypt_rsa_cbc():
    _rsa = JWE_RSA(plain, alg="RSA1_5", enc="A128CBC-HS256")
    jwt = _rsa.encrypt(pub_key)
    dec = JWE_RSA()
    msg = dec.decrypt(jwt, priv_key)

    assert msg == plain


def test_rsa_encrypt_decrypt_rsa_oaep_gcm():
    jwt = JWE_RSA(plain, alg="RSA-OAEP", enc="A256GCM").encrypt(pub_key)
    msg = JWE_RSA().decrypt(jwt, priv_key)

    assert msg == plain


def test_rsa_encrypt_decrypt_rsa_oaep_256_gcm():
    jwt = JWE_RSA(plain[:1], alg="RSA-OAEP-256", enc="A256GCM").encrypt(pub_key)
    msg = JWE_RSA().decrypt(jwt, priv_key)

    assert msg == plain[:1]


def test_encrypt_decrypt_rsa_cbc():
    _key = RSAKey(pub_key=pub_key)
    _jwe0 = JWE(plain, alg="RSA1_5", enc="A128CBC-HS256")

    jwt = _jwe0.encrypt([_key])

    _jwe1 = factory(jwt, alg="RSA1_5", enc="A128CBC-HS256")
    _dkey = RSAKey(priv_key=priv_key)
    msg = _jwe1.decrypt(jwt, [_dkey])

    assert msg == plain


def test_rsa_with_kid():
    encryption_keys = [RSAKey(use="enc", pub_key=pub_key, kid="some-key-id")]
    jwe = JWE("some content", alg="RSA-OAEP", enc="A256CBC-HS512")
    jwe.encrypt(keys=encryption_keys, kid="some-key-id")


if __name__ == "__main__":
    test_rsa_with_kid()

# Test ECDH-ES

alice = ec.generate_private_key(curve=ec.SECP256R1())
eck_alice = ECKey(priv_key=alice)
bob = ec.generate_private_key(curve=ec.SECP256R1())
eck_bob = ECKey(priv_key=bob)


def test_ecdh_encrypt_decrypt_direct_key():
    # Alice starts of
    jwenc = JWE_EC(plain, alg="ECDH-ES", enc="A128GCM")
    cek, encrypted_key, iv, params, ret_epk = jwenc.enc_setup(plain, key=eck_bob)

    kwargs = {"params": params, "cek": cek, "iv": iv, "encrypted_key": encrypted_key}

    assert "epk" in params
    assert not encrypted_key

    jwt = jwenc.encrypt(**kwargs)

    # Bob decrypts
    ret_jwe = factory(jwt, alg="ECDH-ES", enc="A128GCM")
    jwdec = JWE_EC()
    jwdec.dec_setup(ret_jwe.jwt, key=bob)
    msg = jwdec.decrypt(ret_jwe.jwt)

    assert msg == plain


def test_ecdh_encrypt_decrypt_direct_key_wo_apu_apv():
    # Alice starts of
    jwenc = JWE_EC(plain, alg="ECDH-ES", enc="A128GCM")

    # Don't supply agreement party information.
    cek, encrypted_key, iv, params, ret_epk = jwenc.enc_setup(plain, key=eck_bob, apu=b"", apv=b"")
    # Assert they are not randomized
    assert params["apv"] == b""
    assert params["apu"] == b""

    # Delete agreement party information
    del params["apv"]
    del params["apu"]

    kwargs = {"params": params, "cek": cek, "iv": iv, "encrypted_key": encrypted_key}
    jwt = jwenc.encrypt(**kwargs)

    # Bob decrypts
    ret_jwe = factory(jwt, alg="ECDH-ES", enc="A128GCM")
    jwdec = JWE_EC()
    jwdec.dec_setup(ret_jwe.jwt, key=bob)
    msg = jwdec.decrypt(ret_jwe.jwt)

    assert msg == plain


def test_ecdh_encrypt_decrypt_keywrapped_key():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A128GCM")
    cek, encrypted_key, iv, params, ret_epk = jwenc.enc_setup(plain, key=eck_bob)

    kwargs = {}
    kwargs["params"] = params
    kwargs["cek"] = cek
    kwargs["iv"] = iv
    kwargs["encrypted_key"] = encrypted_key

    assert "epk" in params
    assert encrypted_key

    jwt = jwenc.encrypt(**kwargs)

    ret_jwe = factory(jwt, alg="ECDH-ES+A128KW", enc="A128GCM")
    jwdec = JWE_EC()
    jwdec.dec_setup(ret_jwe.jwt, key=bob)
    msg = jwdec.decrypt(ret_jwe.jwt)

    assert msg == plain


def test_ecdh_enc_setup_wrong_key():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A128GCM")
    with pytest.raises(ValueError):
        jwenc.enc_setup(plain, key=priv_key)


def test_ecdh_enc_setup_enk():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A128GCM")
    assert jwenc.enc_setup(plain, key=eck_bob, epk=alice)


def test_ecdh_enc_setup_enk_eckey():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A128GCM")
    assert jwenc.enc_setup(plain, key=eck_bob, epk=eck_alice)


def test_ecdh_setup_iv():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A128GCM")
    iv0 = rndstr(16)
    cek, encrypted_key, iv, params, ret_epk = jwenc.enc_setup(plain, iv=iv0, key=eck_bob)
    assert iv == iv0


def test_ecdh_setup_cek():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A128GCM")
    cek0 = as_bytes(rndstr(16))
    cek, encrypted_key, iv, params, ret_epk = jwenc.enc_setup(plain, cek=cek0, key=eck_bob)
    assert cek == cek0


def test_ecdh_setup_unknown_alg():
    jwenc = JWE_EC(plain, alg="ECDH-ES+A128KW", enc="A384GCM")
    with pytest.raises(ValueError):
        jwenc.enc_setup(plain, key=eck_bob)


def test_ecdh_setup_unknown_alg_2():
    jwenc = JWE_EC(plain, alg="ECDH-ES", enc="A384GCM")
    with pytest.raises(ValueError):
        jwenc.enc_setup(plain, key=eck_bob)


def test_sym_encrypt_decrypt():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE_SYM("some content", alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(key=encryption_key, kid="some-key-id")
    jwdec = JWE_SYM()

    resp = jwdec.decrypt(_jwe, encryption_key)
    assert resp == b"some content"


def test_ecdh_no_setup_dynamic_epk():
    jwenc = JWE(plain, alg="ECDH-ES", enc="A128GCM")
    jwt = jwenc.encrypt([eck_bob])
    assert jwt
    ret_jwe = factory(jwt, alg="ECDH-ES", enc="A128GCM")
    res = ret_jwe.decrypt(jwt, [eck_bob])
    assert res == plain


def test_verify_headers():
    jwenc = JWE(plain, alg="ECDH-ES", enc="A128GCM")
    jwt = jwenc.encrypt([eck_bob])
    assert jwt
    decrypter = factory(jwt, alg="ECDH-ES", enc="A128GCM")
    assert decrypter.jwt.verify_headers(alg="ECDH-ES", enc="A128GCM")
    assert decrypter.jwt.verify_headers(alg="RS256") is False
    assert decrypter.jwt.verify_headers(kid="RS256") is False


def test_encrypt_no_keys():
    jwenc = JWE(plain, alg="ECDH-ES", enc="A128GCM")
    with pytest.raises(NoSuitableEncryptionKey):
        jwenc.encrypt()


def test_encrypt_jwk_key():
    # This is a weird case. Signing the JWT with a key that is
    # published in the JWT. Still it should be possible.
    jwenc = JWE(plain, alg="ECDH-ES", enc="A128GCM", jwk=eck_bob)
    _enc = jwenc.encrypt()
    assert _enc
    decrypter = factory(_enc, alg="ECDH-ES", enc="A128GCM")
    res = decrypter.decrypt()
    assert res == plain


def test_sym_encrypt_decrypt_jwe():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(keys=[encryption_key], kid="some-key-id")
    decrypter = factory(_jwe, alg="A128KW", enc="A128CBC-HS256")

    resp = decrypter.decrypt(_jwe, [encryption_key])
    assert resp == plain


def test_sym_jwenc():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(keys=[encryption_key], kid="some-key-id")
    decrypter = factory(_jwe, alg="A128KW", enc="A128CBC-HS256")

    _jwenc = decrypter.jwt
    assert _jwenc.b64_protected_header() == _jwenc.b64part[0]
    assert _jwenc.b64_encrypted_key() == _jwenc.b64part[1]
    assert _jwenc.b64_initialization_vector() == _jwenc.b64part[2]
    assert _jwenc.b64_ciphertext() == _jwenc.b64part[3]
    assert _jwenc.b64_authentication_tag() == _jwenc.b64part[4]

    assert _jwenc.protected_header() == _jwenc.part[0]
    assert _jwenc.encrypted_key() == _jwenc.part[1]
    assert _jwenc.initialization_vector() == _jwenc.part[2]
    assert _jwenc.ciphertext() == _jwenc.part[3]
    assert _jwenc.authentication_tag() == _jwenc.part[4]


def test_wrong_key_type():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwenc = JWE(plain, alg="ECDH-ES", enc="A128GCM")
    with pytest.raises(NoSuitableEncryptionKey):
        jwenc.encrypt([encryption_key])


def test_wrong_alg():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(keys=[encryption_key], kid="some-key-id")
    with pytest.raises(HeaderError):
        factory(_jwe, alg="A192KW", enc="A128CBC-HS256")


def test_wrong_alg_2():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(keys=[encryption_key], kid="some-key-id")
    decrypter = factory(_jwe, alg="A128KW", enc="A128CBC-HS256")
    with pytest.raises(WrongEncryptionAlgorithm):
        decrypter.decrypt(_jwe, [encryption_key], alg="A192KW")


def test_no_key():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(keys=[encryption_key], kid="some-key-id")
    decrypter = factory(_jwe, alg="A128KW", enc="A128CBC-HS256")
    with pytest.raises(NoSuitableDecryptionKey):
        decrypter.decrypt(_jwe, [])


def test_unknown_alg():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwenc = JWE(plain, alg="BCD", enc="A128GCM")
    with pytest.raises(ValueError):
        jwenc.encrypt([encryption_key])


def test_nothing():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")

    decrypter = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    with pytest.raises(ValueError):
        decrypter.decrypt(keys=[encryption_key])


def test_invalid():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")

    decrypter = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    with pytest.raises(BadSyntax):
        decrypter.decrypt("a.b.c.d.e", keys=[encryption_key])


def test_fernet_password():
    encrypter = FernetEncrypter(password="DukeofHazardpass")
    _token = encrypter.encrypt(plain)

    decrypter = encrypter
    resp = decrypter.decrypt(_token)
    assert resp == plain


def test_fernet_symkey():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")

    encrypter = FernetEncrypter(password=encryption_key.key)
    _token = encrypter.encrypt(plain)

    decrypter = encrypter
    resp = decrypter.decrypt(_token)
    assert resp == plain


def test_fernet_bad():
    with pytest.raises(TypeError):
        _ = FernetEncrypter(key="xyzzy")
    with pytest.raises(ValueError):
        _ = FernetEncrypter(key=os.urandom(16))


def test_fernet_bytes():
    key = os.urandom(32)

    encrypter = FernetEncrypter(key=key)
    _token = encrypter.encrypt(plain)

    decrypter = encrypter
    resp = decrypter.decrypt(_token)
    assert resp == plain


def test_fernet_default_key():
    encrypter = FernetEncrypter()
    _token = encrypter.encrypt(plain)

    decrypter = encrypter
    resp = decrypter.decrypt(_token)
    assert resp == plain


def test_fernet_sha512():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")

    encrypter = FernetEncrypter(password=encryption_key.key, hash_alg="SHA512")
    _token = encrypter.encrypt(plain)

    decrypter = encrypter
    resp = decrypter.decrypt(_token)
    assert resp == plain


def test_fernet_blake2s():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")

    encrypter = FernetEncrypter(
        password=encryption_key.key, hash_alg="BLAKE2s", digest_size=32, iterations=1000
    )
    _token = encrypter.encrypt(plain)

    decrypter = encrypter
    resp = decrypter.decrypt(_token)
    assert resp == plain


def test_is_jwe():
    encryption_key = SYMKey(use="enc", key="DukeofHazardpass", kid="some-key-id")
    jwe = JWE(plain, alg="A128KW", enc="A128CBC-HS256")
    _jwe = jwe.encrypt(keys=[encryption_key], kid="some-key-id")
    assert is_jwe(_jwe)
