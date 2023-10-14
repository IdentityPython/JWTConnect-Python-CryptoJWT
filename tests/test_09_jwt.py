import os

import pytest
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jwt import JWT
from cryptojwt.jwt import pick_key
from cryptojwt.jwt import utc_time_sans_frac
from cryptojwt.jwt import VerificationError
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import init_key_jar
from cryptojwt.key_jar import KeyJar

__author__ = "Roland Hedberg"

ALICE = "https://example.org/alice"
BOB = "https://example.com/bob"
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# k1 = import_private_rsa_key_from_file(full_path('rsa.key'))
# k2 = import_private_rsa_key_from_file(full_path('size2048.key'))

kb1 = KeyBundle(
    source="file://{}".format(full_path("rsa.key")),
    fileformat="der",
    keyusage="sig",
    kid="1",
)
kb2 = KeyBundle(
    source="file://{}".format(full_path("size2048.key")),
    fileformat="der",
    keyusage="enc",
    kid="2",
)

ALICE_KEY_JAR = KeyJar()
ALICE_KEY_JAR.add_kb(ALICE, kb1)
ALICE_KEY_JAR.add_kb(ALICE, kb2)

kb3 = KeyBundle(
    source="file://{}".format(full_path("server.key")),
    fileformat="der",
    keyusage="enc",
    kid="3",
)

BOB_KEY_JAR = KeyJar()
BOB_KEY_JAR.add_kb(BOB, kb3)

# Load the opponents keys
_jwks = ALICE_KEY_JAR.export_jwks_as_json(issuer_id=ALICE)
BOB_KEY_JAR.import_jwks_as_json(_jwks, ALICE)

_jwks = BOB_KEY_JAR.export_jwks_as_json(issuer_id=BOB)
ALICE_KEY_JAR.import_jwks_as_json(_jwks, BOB)


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_jwt_pack():
    _jwt = JWT(key_jar=ALICE_KEY_JAR, lifetime=3600, iss=ALICE).pack(aud=BOB)

    assert _jwt
    assert len(_jwt.split(".")) == 3


def test_jwt_pack_and_unpack():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256")
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"])
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {"iat", "iss", "sub"}


def test_jwt_pack_and_unpack_valid():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256")
    t = utc_time_sans_frac()
    payload = {"sub": "sub", "nbf": t, "exp": t + 3600}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"])
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {"iat", "iss", "sub", "nbf", "exp"}


def test_jwt_pack_and_unpack_not_yet_valid():
    lifetime = 3600
    skew = 15
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256", lifetime=lifetime)
    timestamp = utc_time_sans_frac()
    payload = {"sub": "sub", "nbf": timestamp}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"], skew=skew)
    _ = bob.unpack(_jwt, timestamp=timestamp - skew)
    with pytest.raises(VerificationError):
        _ = bob.unpack(_jwt, timestamp=timestamp - skew - 1)


def test_jwt_pack_and_unpack_expired():
    lifetime = 3600
    skew = 15
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256", lifetime=lifetime)
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"], skew=skew)
    iat = bob.unpack(_jwt)["iat"]
    _ = bob.unpack(_jwt, timestamp=iat + lifetime + skew - 1)
    with pytest.raises(VerificationError):
        _ = bob.unpack(_jwt, timestamp=iat + lifetime + skew)


def test_jwt_pack_and_unpack_max_lifetime_exceeded():
    lifetime = 3600
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256", lifetime=lifetime)
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(
        key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"], allowed_max_lifetime=lifetime - 1
    )
    with pytest.raises(VerificationError):
        _ = bob.unpack(_jwt)


def test_jwt_pack_and_unpack_timestamp():
    lifetime = 3600
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256", lifetime=lifetime)
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload, iat=42)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"])
    _ = bob.unpack(_jwt, timestamp=42)
    with pytest.raises(VerificationError):
        _ = bob.unpack(_jwt)


def test_jwt_pack_and_unpack_unknown_key():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS256")
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload)

    kj = KeyJar()
    kj.add_kb(ALICE, KeyBundle())
    bob = JWT(key_jar=kj, iss=BOB, allowed_sign_algs=["RS256"])
    with pytest.raises(NoSuitableSigningKeys):
        info = bob.unpack(_jwt)


def test_jwt_pack_and_unpack_with_lifetime():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, lifetime=600)
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {"iat", "iss", "sub", "exp"}


def test_jwt_pack_encrypt():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE)
    payload = {"sub": "sub", "aud": BOB}
    _jwt = alice.pack(payload=payload, encrypt=True, recv=BOB)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {"iat", "iss", "sub", "aud"}


def test_jwt_pack_unpack_sym():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, "hemligt ordsprak", usage=["sig"])
    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    payload = {"sub": "sub2"}
    _jwt = alice.pack(payload=payload)

    _kj = KeyJar()
    _kj.add_symmetric(ALICE, "hemligt ordsprak", usage=["sig"])
    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256")
    info = bob.unpack(_jwt)
    assert info


def test_jwt_pack_encrypt_no_sign():
    alice = JWT(sign=False, key_jar=ALICE_KEY_JAR, iss=ALICE)

    payload = {"sub": "sub", "aud": BOB}
    _jwt = alice.pack(payload=payload, encrypt=True, recv=BOB)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {"iat", "iss", "sub", "aud"}


def test_jwt_pack_and_unpack_with_alg():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg="RS384")
    payload = {"sub": "sub"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(BOB_KEY_JAR, sign_alg="RS384")
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {"iat", "iss", "sub"}


def test_extend_audience():
    _jwt = JWT()
    aud = _jwt.put_together_aud("abcdefgh")
    assert aud == ["abcdefgh"]
    aud = _jwt.put_together_aud("12345678", aud)
    assert set(aud) == {"abcdefgh", "12345678"}


def test_with_jti():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, "hemligt ordsprak", usage=["sig"])

    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    alice.with_jti = True
    payload = {"sub": "sub2"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256")
    info = bob.unpack(_jwt)
    assert "jti" in info


class DummyMsg(object):

    def __init__(self, **kwargs):
        for key, val in kwargs.items():
            setattr(self, key, val)
        self.jws_headers = {}

    def verify(self, **kwargs):
        return True


def test_msg_cls():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, "hemligt ordsprak", usage=["sig"])

    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    payload = {"sub": "sub2"}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256")
    bob.msg_cls = DummyMsg
    info = bob.unpack(_jwt)
    assert isinstance(info, DummyMsg)


KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256K", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
]

kj = init_key_jar(key_defs=KEY_DEFS)


def test_pick_key():
    keys = kj.get_issuer_keys("")

    _k = pick_key(keys, "sig", "RS256")
    assert len(_k) == 1

    _k = pick_key(keys, "sig", "ES256")
    assert len(_k) == 1

    _k = pick_key(keys, "sig", "ES384")
    assert len(_k) == 1

    _k = pick_key(keys, "sig", "ES256K")
    assert len(_k) == 1

    _k = pick_key(keys, "enc", "RSA-OAEP-256")
    assert len(_k) == 1

    _k = pick_key(keys, "enc", "ECDH-ES")
    assert len(_k) == 0


def test_eddsa_jwt():
    JWKS_DICT = {
        "keys": [
            {
                "kty": "OKP",
                "kid": "-1909572257",
                "crv": "Ed25519",
                "x": "XWxGtApfcqmKI7p0OKnF5JSEWMVoLsytFXLEP7xZ_l8",
            }
        ]
    }
    JWT_TEST = (
            "eyJraWQiOiItMTkwOTU3MjI1NyIsImFsZyI6IkVkRFNBIn0."
            + "eyJqdGkiOiIyMjkxNmYzYy05MDkzLTQ4MTMtODM5Ny1mMTBlNmI3MDRiNjgiLCJkZWxlZ2F0aW9uSWQiOiJiNGFlNDdhNy02MjVhLTQ2MzAtOTcyNy00NTc2NGE3MTJjY2UiLCJleHAiOjE2NTUyNzkxMDksIm5iZiI6MTY1NTI3ODgwOSwic2NvcGUiOiJyZWFkIG9wZW5pZCIsImlzcyI6Imh0dHBzOi8vaWRzdnIuZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VybmFtZSIsImF1ZCI6ImFwaS5leGFtcGxlLmNvbSIsImlhdCI6MTY1NTI3ODgwOSwicHVycG9zZSI6ImFjY2Vzc190b2tlbiJ9."
            + "rjeE8D_e4RYzgvpu-nOwwx7PWMiZyDZwkwO6RiHR5t8g4JqqVokUKQt-oST1s45wubacfeDSFogOrIhe3UHDAg"
    )
    ISSUER = "https://idsvr.example.com"
    kj = KeyJar()
    kj.add_kb(ISSUER, KeyBundle(JWKS_DICT))
    jwt = JWT(key_jar=kj)
    _ = jwt.unpack(JWT_TEST, timestamp=1655278809)


def test_extra_headers():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, "hemligt ordsprak", usage=["sig"])

    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    payload = {"sub": "sub2"}
    _jwt = alice.pack(payload=payload, jws_headers={"xtra": "header", "typ": "dummy"})

    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256", typ2msg_cls={"dummy": DummyMsg})
    info = bob.unpack(_jwt)
    assert isinstance(info, DummyMsg)
    assert set(info.jws_header.keys()) == {'xtra', 'typ', 'alg', 'kid'}
