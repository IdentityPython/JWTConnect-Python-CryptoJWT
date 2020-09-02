import os

import pytest

from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import init_key_jar

__author__ = "Roland Hedberg"

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_keys"))
RSAKEY = os.path.join(BASE_PATH, "cert.key")
RSA0 = os.path.join(BASE_PATH, "rsa.key")
EC0 = os.path.join(BASE_PATH, "ec.key")
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


JWK1 = {
    "keys": [
        {
            "n": "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8"
            "mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta"
            "-NvS-aG_jN5cstVbCGWE20H0vF"
            "VrJKNx0Zf-u-aA-syM4uX7wdWgQ"
            "-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1k"
            "leiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": "AQAB",
            "kty": "RSA",
            "kid": "rsa1",
        },
        {
            "k": "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct",
        },
    ]
}

KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


class TestVerifyJWTKeys(object):
    @pytest.fixture(autouse=True)
    def setup(self):
        mkey = [
            {"type": "RSA", "use": ["sig"]},
            {"type": "RSA", "use": ["sig"]},
            {"type": "RSA", "use": ["sig"]},
        ]

        skey = [{"type": "RSA", "use": ["sig"]}]

        # Alice has multiple keys
        self.alice_keyjar = build_keyjar(mkey)
        # Bob has one single keys
        self.bob_keyjar = build_keyjar(skey)
        self.alice_keyjar["Alice"] = self.alice_keyjar[""]
        self.bob_keyjar["Bob"] = self.bob_keyjar[""]

        # To Alice's keyjar add Bob's public keys
        self.alice_keyjar.import_jwks(self.bob_keyjar.export_jwks(issuer="Bob"), "Bob")

        # To Bob's keyjar add Alice's public keys
        self.bob_keyjar.import_jwks(self.alice_keyjar.export_jwks(issuer="Alice"), "Alice")

        _jws = JWS('{"aud": "Bob", "iss": "Alice"}', alg="RS256")
        sig_key = self.alice_keyjar.get_signing_key("rsa", owner="Alice")[0]
        self.sjwt_a = _jws.sign_compact([sig_key])

        _jws = JWS('{"aud": "Alice", "iss": "Bob"}', alg="RS256")
        sig_key = self.bob_keyjar.get_signing_key("rsa", owner="Bob")[0]
        self.sjwt_b = _jws.sign_compact([sig_key])

    def test_no_kid_multiple_keys_no_kid_issuer(self):
        a_kids = [k.kid for k in self.alice_keyjar.get_verify_key(owner="Alice", key_type="RSA")]
        no_kid_issuer = {"Alice": a_kids}
        _jwt = factory(self.sjwt_a)
        _jwt.jwt.headers["kid"] = ""
        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt, no_kid_issuer=no_kid_issuer)
        assert len(keys) == 3

    def test_aud(self):
        self.alice_keyjar.import_jwks(JWK1, issuer="D")
        self.bob_keyjar.import_jwks(JWK1, issuer="D")

        _jws = JWS('{"iss": "D", "aud": "A"}', alg="HS256")
        sig_key = self.alice_keyjar.get_signing_key("oct", owner="D")[0]
        _sjwt = _jws.sign_compact([sig_key])

        no_kid_issuer = {"D": []}

        _jwt = factory(_sjwt)

        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt, no_kid_issuer=no_kid_issuer)
        assert len(keys) == 1


PUBLIC_FILE = "{}/public_jwks.json".format(BASEDIR)
PRIVATE_FILE = "{}/private_jwks.json".format(BASEDIR)
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]
KEYSPEC_2 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
]


def test_init_key_jar_dump_private():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # New set of keys, JWKSs with keys and public written to file
    _keyjar = init_key_jar(private_path=PRIVATE_FILE, key_defs=KEYSPEC, owner="https://example.com")
    assert list(_keyjar.owners()) == ["https://example.com"]

    # JWKS will be read from disc, not created new
    _keyjar2 = init_key_jar(private_path=PRIVATE_FILE, key_defs=KEYSPEC)
    assert list(_keyjar2.owners()) == [""]


def test_init_key_jar_update():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # New set of keys, JWKSs with keys and public written to file
    _keyjar_1 = init_key_jar(
        private_path=PRIVATE_FILE,
        key_defs=KEYSPEC,
        owner="https://example.com",
        public_path=PUBLIC_FILE,
        read_only=False,
    )
    assert list(_keyjar_1.owners()) == ["https://example.com"]

    _keyjar_2 = init_key_jar(private_path=PRIVATE_FILE, key_defs=KEYSPEC_2, public_path=PUBLIC_FILE)

    # Both should contain the same RSA key
    rsa1 = _keyjar_1.get_signing_key("RSA", "https://example.com")
    rsa2 = _keyjar_2.get_signing_key("RSA", "")

    assert len(rsa1) == 1
    assert len(rsa2) == 1
    assert rsa1[0] == rsa2[0]

    # keyjar1 should only contain one EC key while keyjar2 should contain 2.

    ec1 = _keyjar_1.get_signing_key("EC", "https://example.com")
    ec2 = _keyjar_2.get_signing_key("EC", "")
    assert len(ec1) == 1
    assert len(ec2) == 2

    # The file on disc should not have changed
    _keyjar_3 = init_key_jar(private_path=PRIVATE_FILE)

    assert len(_keyjar_3.get_signing_key("RSA")) == 1
    assert len(_keyjar_3.get_signing_key("EC")) == 1

    _keyjar_4 = init_key_jar(
        private_path=PRIVATE_FILE,
        key_defs=KEYSPEC_2,
        public_path=PUBLIC_FILE,
        read_only=False,
    )

    # Now it should
    _keyjar_5 = init_key_jar(private_path=PRIVATE_FILE)

    assert len(_keyjar_5.get_signing_key("RSA")) == 1
    assert len(_keyjar_5.get_signing_key("EC")) == 2
