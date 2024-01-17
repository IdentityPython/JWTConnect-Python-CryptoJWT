import json
import os
import shutil
import time
import warnings

import pytest

from cryptojwt.exception import IssuerNotFound
from cryptojwt.exception import JWKESTException
from cryptojwt.jwe.jwenc import JWEnc
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_bundle import rsa_init
from cryptojwt.key_jar import KeyJar
from cryptojwt.key_jar import build_keyjar
from cryptojwt.key_jar import init_key_jar
from cryptojwt.key_jar import rotate_keys

__author__ = "Roland Hedberg"


BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_keys"))
RSAKEY = os.path.join(BASE_PATH, "cert.key")
RSA0 = os.path.join(BASE_PATH, "rsa.key")
EC0 = os.path.join(BASE_PATH, "ec.key")
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


JWK0 = {
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "abc",
            "n": "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5"
            "B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8",
        }
    ]
}

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

JWK2 = {
    "keys": [
        {
            "e": "AQAB",
            "kid": "R3NJRW1EVHRsaUcwSXVydi14cVVoTmxhaU4zckU1MlFPa05NWGNpUUZtcw",
            "kty": "RSA",
            "use": "sig",
            "n": "rp7aJD9FKKHQgLTeXLMyjB5TS51x_KqA15gBJHF2Ps-rrmcBujpMAi39D7w4"
            "SArr9X7DPgHekTPRV6-i46TyqnY1EXPGRb0nCg0rCmkyOAMysXhhuexu3vS7"
            "Fa2YPvX2zpl5svdkOOwLmHBplCTtvScz-L7N1xeknauOLF5Ct39C5Ipv-BWx"
            "bNrqD68uIPSOH9ZsoGKVArSI0MSmw5LB7B3i30D8FvmlJyxcEPZOFVahFCmS"
            "qqUXHuXV2Z0BpvgvDhzB5cSNO12clwD_fZ4CnbvuvfbBAgpVg774smz2z3ov"
            "6SsZ6ZD5Tc_9gE2ryLW6x0RS1y2KSME8EUI2sdJYZw",
            "x5c": [
                "MIIDOjCCAiKgAwIBAgIUJACZrVNr3gHJrde3OkQwy1lXL6owDQYJKoZIhvcN"
                "AQELBQAwSjELMAkGA1UEBhMCU0UxDjAMBgNVBAcMBVVtZcOlMRgwFgYDVQQK"
                "DA9JZGVudGl0eSBQeXRob24xETAPBgNVBAMMCGlkcHkub3JnMB4XDTIxMTEw"
                "MjA5MzIzOFoXDTIxMTExMjA5MzIzOFowSjELMAkGA1UEBhMCU0UxDjAMBgNV"
                "BAcMBVVtZcOlMRgwFgYDVQQKDA9JZGVudGl0eSBQeXRob24xETAPBgNVBAMM"
                "CGlkcHkub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArp7a"
                "JD9FKKHQgLTeXLMyjB5TS51x/KqA15gBJHF2Ps+rrmcBujpMAi39D7w4SArr"
                "9X7DPgHekTPRV6+i46TyqnY1EXPGRb0nCg0rCmkyOAMysXhhuexu3vS7Fa2Y"
                "PvX2zpl5svdkOOwLmHBplCTtvScz+L7N1xeknauOLF5Ct39C5Ipv+BWxbNrq"
                "D68uIPSOH9ZsoGKVArSI0MSmw5LB7B3i30D8FvmlJyxcEPZOFVahFCmSqqUX"
                "HuXV2Z0BpvgvDhzB5cSNO12clwD/fZ4CnbvuvfbBAgpVg774smz2z3ov6SsZ"
                "6ZD5Tc/9gE2ryLW6x0RS1y2KSME8EUI2sdJYZwIDAQABoxgwFjAUBgNVHREE"
                "DTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAARJIf6TZrhGjI/g"
                "QnvOybc6o3lv4nPCJojRoHjFtTd9uk9Eve4Ba7NG8goCs9l3Cq4tPUpqfW42"
                "iSr+1Vd9O+cozJAa6PVGwTCfHrtBvQWgM9gk+09lmP8kO73KBcmK9lcwYThJ"
                "NNVmZgEwV37hP6sUmyfmuAsxgePPSQqahCej1ORN9YGSH2aeXw+1rhyfTZ6c"
                "Kl791b+6So8bDEhfQcFmwNJ/75tr++dRnEdPfSLfid13PFT0W6uxQqeSpCh6"
                "TtRiqTb47SIKKnG4YPta2eVOnMNOvy2Lw4nl95V7RSvVw6VbPOx9XXYaONdm"
                "mSpbgK1tK1XMkhrp95sU3q1OS8I="
            ],
            "x5t": "ScM0uv4bxGMJ7bbrc1scc_uOyLI",
        },
        {
            "e": "AQAB",
            "kid": "d1Z6RTJHQmh0NnBaeHpfYVd0U1dIb25fUTQ1aVhjNXFhWHEyTE4wbVh5bw",
            "kty": "RSA",
            "use": "sig",
            "n": "zpQAmVzABLrRWV6HiBVbFeho_KhQhm8T_r6LvGP-Znnewpr6J7lBYD9gfVJo2_"
            "lOpCqitJvoMJoZxoULJ1xU_Am4padc-as8Sk9vb3FkvxoDrZFByNgmbrNTJCco"
            "wUBLTgb1wWde1CPNmr_U_-VBODOy17uTrt7DNEMqEwUi3Qb76J8duHVQT0ECcw"
            "crGXbsfV74jSaBAehHxlTt4tG4-LVC9I0IFs9bBykdZVh59uwtaKTlBNuC5frt"
            "kGyn_2TM1zCWSVparxqQ_T3e_g2NOr3v5fW_gjDsYZ2543DrE8ta_OCyrqw4wz"
            "fBEOb6raI6wCyqFQ5My1bz-qVTap-4hQ",
            "x5c": [
                "MIIDPjCCAiagAwIBAgIUB70yEjwKX+/dUw4YvP61BKpDHJQwDQYJKoZIhvcNAQ"
                "ELBQAwTDELMAkGA1UEBhMCVVMxEDAOBgNVBAcMB1NlYXR0bGUxGDAWBgNVBAoM"
                "D0lkZW50aXR5IFB5dGhvbjERMA8GA1UEAwwIaWRweS5vcmcwHhcNMjExMTAyMD"
                "kzMjM4WhcNMjExMTEyMDkzMjM4WjBMMQswCQYDVQQGEwJVUzEQMA4GA1UEBwwH"
                "U2VhdHRsZTEYMBYGA1UECgwPSWRlbnRpdHkgUHl0aG9uMREwDwYDVQQDDAhpZH"
                "B5Lm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6UAJlcwAS6"
                "0Vleh4gVWxXoaPyoUIZvE/6+i7xj/mZ53sKa+ie5QWA/YH1SaNv5TqQqorSb6D"
                "CaGcaFCydcVPwJuKWnXPmrPEpPb29xZL8aA62RQcjYJm6zUyQnKMFAS04G9cFn"
                "XtQjzZq/1P/lQTgzste7k67ewzRDKhMFIt0G++ifHbh1UE9BAnMHKxl27H1e+I"
                "0mgQHoR8ZU7eLRuPi1QvSNCBbPWwcpHWVYefbsLWik5QTbguX67ZBsp/9kzNcw"
                "lklaWq8akP093v4NjTq97+X1v4Iw7GGdueNw6xPLWvzgsq6sOMM3wRDm+q2iOs"
                "AsqhUOTMtW8/qlU2qfuIUCAwEAAaMYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0"
                "MA0GCSqGSIb3DQEBCwUAA4IBAQAyRDDxQcaNDP93SCmZaCnRgpQU8ZnrNk+QpF"
                "LPlzUM+CopC5KnJuqBX3C54/uQve54/YpNTbBGGYgqB07381L7z7hn9aNylyFf"
                "N9Ck51/lMnG2YYjdwDwhskfsekOA9H44N3GdxYhVuSrZDr+DuS8Sve26HRzh1Z"
                "r+1PqSanM7pTJngGFDor7Hn02mKwAYk2HduT7ulYXxzLBcDhgagGTT86P3Jmwm"
                "eM6PvsICMpP/6ewzRnsfJ+tmT/WXSS9IX1ZL/UxSEiNYPyJdls83stnjAxpS41"
                "IKNMtebp/78p/BGG5Tm+YUPES4h5YwBUsJi3ehhdzzQXjdqSF8xe2wjs6y"
            ],
            "x5t": "WlQYbhnE2ZQvZKF45tqK5Lwmt8k",
        },
    ]
}


def test_build_keyjar():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    keyjar = build_keyjar(keys)
    jwks = keyjar.export_jwks()
    for key in jwks["keys"]:
        assert "d" not in key  # the JWKS shouldn't contain the private part
        # of the keys

    assert len(keyjar[""]) == 3  # 3 keys
    assert len(keyjar.get_issuer_keys("")) == 3  # A total of 3 keys
    assert len(keyjar.get("sig")) == 2  # 2 for signing
    assert len(keyjar.get("enc")) == 1  # 1 for encryption


def test_build_keyjar_usage():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        {"type": "oct", "use": ["enc"]},
        {"type": "oct", "use": ["enc"]},
    ]

    keyjar = build_keyjar(keys)
    jwks_sig = keyjar.export_jwks(usage="sig")
    jwks_enc = keyjar.export_jwks(usage="enc")
    assert len(jwks_sig.get("keys")) == 2  # A total of 2 keys with use=sig
    assert len(jwks_enc.get("keys")) == 3  # A total of 3 keys with use=enc


def test_build_keyjar_missing(tmpdir):
    keys = [
        {
            "type": "RSA",
            "key": os.path.join(tmpdir.dirname, "missing_file"),
            "use": ["enc", "sig"],
        }
    ]

    key_jar = build_keyjar(keys)

    assert key_jar is None


def test_build_RSA_keyjar_from_file(tmpdir):
    keys = [{"type": "RSA", "key": RSA0, "use": ["enc", "sig"]}]

    key_jar = build_keyjar(keys)

    assert len(key_jar[""]) == 2


def test_build_EC_keyjar_missing(tmpdir):
    keys = [
        {
            "type": "EC",
            "key": os.path.join(tmpdir.dirname, "missing_file"),
            "use": ["enc", "sig"],
        }
    ]

    key_jar = build_keyjar(keys)

    assert key_jar is None


def test_build_EC_keyjar_from_file(tmpdir):
    keys = [{"type": "EC", "key": EC0, "use": ["enc", "sig"]}]

    key_jar = build_keyjar(keys)

    assert len(key_jar[""]) == 2


class TestKeyJar(object):
    def test_keyjar_add(self):
        kj = KeyJar()
        kb = keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"])
        kj.add_kb("https://issuer.example.com", kb)
        assert list(kj.owners()) == ["https://issuer.example.com"]

    def test_setitem(self):
        kj = KeyJar()
        kb = keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"])
        kj.add_kb("https://issuer.example.com", kb)
        assert list(kj.owners()) == ["https://issuer.example.com"]

    def test_add_symmetric(self):
        kj = KeyJar()
        kj.add_symmetric("", "abcdefghijklmnop", ["sig"])
        assert list(kj.owners()) == [""]
        assert len(kj.get_signing_key("oct", "")) == 1

    def test_items(self):
        ks = KeyJar()
        ks.add_kb(
            "",
            KeyBundle(
                [
                    {"kty": "oct", "key": "abcdefghijklmnop", "use": "sig"},
                    {"kty": "oct", "key": "ABCDEFGHIJKLMNOP", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org",
            KeyBundle(
                [
                    {"kty": "oct", "key": "0123456789012345", "use": "sig"},
                    {"kty": "oct", "key": "1234567890123456", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org",
            keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]),
        )

        assert len(ks.items()) == 2

    def test_issuer_extra_slash(self):
        ks = KeyJar()
        ks.add_kb(
            "",
            KeyBundle(
                [
                    {"kty": "oct", "key": "abcdefghijklmnop", "use": "sig"},
                    {"kty": "oct", "key": "ABCDEFGHIJKLMNOP", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org",
            KeyBundle(
                [
                    {"kty": "oct", "key": "0123456789012345", "use": "sig"},
                    {"kty": "oct", "key": "1234567890123456", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org",
            keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]),
        )

        assert ks.get("sig", "RSA", "http://www.example.org/")

    def test_issuer_missing_slash(self):
        ks = KeyJar()
        ks.add_kb(
            "",
            KeyBundle(
                [
                    {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "sig"},
                    {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org/",
            KeyBundle(
                [
                    {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "sig"},
                    {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org/",
            keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]),
        )

        assert ks.get("sig", "RSA", "http://www.example.org")

    def test_get_enc(self):
        ks = KeyJar()
        ks.add_kb(
            "",
            KeyBundle(
                [
                    {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "sig"},
                    {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org/",
            KeyBundle(
                [
                    {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "sig"},
                    {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org/",
            keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]),
        )

        assert ks.get("enc", "oct")

    def test_get_enc_not_mine(self):
        ks = KeyJar()
        ks.add_kb(
            "",
            KeyBundle(
                [
                    {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "sig"},
                    {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org/",
            KeyBundle(
                [
                    {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "sig"},
                    {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "enc"},
                ]
            ),
        )
        ks.add_kb(
            "http://www.example.org/",
            keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]),
        )

        assert ks.get("enc", "oct", "http://www.example.org/")

    def test_dump_issuer_keys(self):
        kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwks", ["sig"])
        assert len(kb) == 1
        kj = KeyJar()
        kj.add_kb("", kb)
        _jwks_dict = kj.export_jwks()

        _info = _jwks_dict["keys"][0]
        assert _info == {
            "use": "sig",
            "e": "AQAB",
            "kty": "RSA",
            "alg": "RS256",
            "n": "pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n"
            "-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE"
            "-Yopfu3B58Q"
            "lgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf"
            "-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JB"
            "qaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ"
            "-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9Rfz"
            "T87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw",
            "kid": "abc",
        }

    def test_no_use(self):
        kb = KeyBundle(JWK0["keys"])
        kj = KeyJar()
        kj.add_kb("abcdefgh", kb)
        enc_key = kj.get_encrypt_key("RSA", "abcdefgh")
        assert enc_key != []

    @pytest.mark.network
    @pytest.mark.skip("connect-op.herokuapp.com is broken")
    def test_provider(self):
        kj = KeyJar()
        _url = "https://connect-op.herokuapp.com/jwks.json"
        kj.load_keys(
            "https://connect-op.heroku.com",
            jwks_uri=_url,
        )
        iss_keys = kj.get_issuer_keys("https://connect-op.heroku.com")
        if not iss_keys:
            _msg = "{} is not available at this moment!".format(_url)
            warnings.warn(_msg)
        else:
            assert iss_keys[0].keys()


def test_import_jwks():
    kj = KeyJar()
    kj.import_jwks(JWK1, "")
    assert len(kj.get_issuer_keys("")) == 2


def test_get_signing_key_use_undefined():
    kj = KeyJar()
    kj.import_jwks(JWK1, "")
    keys = kj.get_signing_key(kid="rsa1")
    assert len(keys) == 1

    keys = kj.get_signing_key(key_type="rsa")
    assert len(keys) == 1

    keys = kj.get_signing_key(key_type="rsa", kid="rsa1")
    assert len(keys) == 1


KEYDEFS = [
    {"type": "RSA", "key": "", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]


def test_remove_after():
    # initial keyjar
    keyjar = build_keyjar(KEYDEFS)
    _old = [k.kid for k in keyjar.get_issuer_keys("") if k.kid]
    assert len(_old) == 2

    keyjar.remove_after = 1
    # rotate_keys = create new keys + make the old as inactive
    keyjar = rotate_keys(KEYDEFS, keyjar=keyjar)

    keyjar.remove_outdated(time.time() + 3600)

    _interm = [k.kid for k in keyjar.get_issuer_keys("") if k.kid]
    assert len(_interm) == 2

    # The remainder are the new keys
    _new = [k.kid for k in keyjar.get_issuer_keys("") if k.kid]
    assert len(_new) == 2

    # should not be any overlap between old and new
    assert set(_new).intersection(set(_old)) == set()


JWK_UK = {
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
            "kty": "buz",
        },
    ]
}


def test_load_unknown_keytype():
    kj = KeyJar()
    kj.import_jwks(JWK_UK, "")
    assert len(kj.get_issuer_keys("")) == 1


JWK_FP = {"keys": [{"e": "AQAB", "kty": "RSA", "kid": "rsa1"}]}


def test_load_missing_key_parameter():
    kj = KeyJar()
    with pytest.raises(JWKESTException):
        kj.import_jwks(JWK_FP, "")


JWKS_SPO = {
    "keys": [
        {
            "kid": "BfxfnahEtkRBG3Hojc9XGLGht_5rDBj49Wh3sBDVnzRpulMqYwMRmpizA0aSPT1fhCHYivTiaucWUqFu_GwTqA",
            "use": "sig",
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": "1XXUXq75gOPZ4bEj1o2Z5XKJWSs6LmL6fAOK3vyMzSc",
            "y": "ac1h_DwyuUxhkrD9oKMJ-b_KuiVvvSARIwT-XoEmDXs",
        },
        {
            "kid": "91pD1H81rXUvrfg9mkngIG-tXjnldykKUVbITDIU1SgJvq91b8clOcJuEHNAq61eIvg8owpEvWcWAtlbV2awyA",
            "use": "sig",
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": "2DfQoLpZS2j3hHEcHDkzV8ISx-RdLt6Opy8YZYVm4AQ",
            "y": "ycvkFMBIzgsowiaf6500YlG4vaMSK4OF7WVtQpUbEE0",
        },
        {
            "kid": "0sIEl3MUJiCxrqleEBBF-_bZq5uClE84xp-wpt8oOI"
            "-WIeNxBjSR4ak_OTOmLdndB0EfDLtC7X1JrnfZILJkxA",
            "use": "sig",
            "alg": "RS256",
            "kty": "RSA",
            "n": "yG9914Q1j63Os4jX5dBQbUfImGq4zsXJD4R59XNjGJlEt5ek6NoiDl0ucJO3_7_R9e5my2ONTSqZhtzFW6MImnIn8idWYzJzO2EhUPCHTvw_2oOGjeYTE2VltIyY_ogIxGwY66G0fVPRRH9tCxnkGOrIvmVgkhCCGkamqeXuWvx9MCHL_gJbZJVwogPSRN_SjA1gDlvsyCdA6__CkgAFcSt1sGgiZ_4cQheKexxf1-7l8R91ZYetz53drk2FS3SfuMZuwMM4KbXt6CifNhzh1Ye-5Tr_ZENXdAvuBRDzfy168xnk9m0JBtvul9GoVIqvCVECB4MPUb7zU6FTIcwRAw",
            "e": "AQAB",
        },
        {
            "kid": "zyDfdEU7pvH0xEROK156ik8G7vLO1MIL9TKyL631kSPtr9tnvs9XOIiq5jafK2hrGr2qqvJdejmoonlGqWWZRA",
            "use": "sig",
            "alg": "RS256",
            "kty": "RSA",
            "n": "68be-nJp46VLj4Ci1V36IrVGYqkuBfYNyjQTZD_7yRYcERZebowOnwr3w0DoIQpl8iL2X8OXUo7rUW_LMzLxKx2hEmdJfUn4LL2QqA3KPgjYz8hZJQPG92O14w9IZ-8bdDUgXrg9216H09yq6ZvJrn5Nwvap3MXgECEzsZ6zQLRKdb_R96KFFgCiI3bEiZKvZJRA7hM2ePyTm15D9En_Wzzfn_JLMYgE_DlVpoKR1MsTinfACOlwwdO9U5Dm-5elapovILTyVTgjN75i-wsPU2TqzdHFKA-4hJNiWGrYPiihlAFbA2eUSXuEYFkX43ahoQNpeaf0mc17Jt5kp7pM2w",
            "e": "AQAB",
        },
    ]
}

JWKS_EDDSA = {
    "keys": [
        {
            "kid": "q-H9y8iuh3BIKZBbK6S0mH_isBlJsk"
            "-u6VtZ5rAdBo5fCjjy3LnkrsoK_QWrlKB08j_PcvwpAMfTEDHw5spepw",
            "use": "sig",
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "FnbcUAXZ4ySvrmdXK1MrDuiqlqTXvGdAaE4RWZjmFIQ",
        },
        {
            "kid": "bL33HthM3fWaYkY2_pDzUd7a65FV2R2LHAKCOsye8eNmAPDgRgpHWPYpWFVmeaujUUEXRyDLHN"
            "-Up4QH_sFcmw",
            "use": "sig",
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "CS01DGXDBPV9cFmd8tgFu3E7eHn1UcP7N1UCgd_JgZo",
        },
        {
            "kid": "OF9xVk9NWE5iQ2N6OGhILTVGcXg4RE1FRk5NWVVsaXZLcFNRNUxCYk9vQQ",
            "use": "sig",
            "alg": "Ed25519",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "M_D8nslNSecjPwiP6DwuNhWRdrgqp02U7f5xo4GhdlY",
        },
        {
            "kid": "RUpoaXktM1JwT0hON3lzNWNfN0RUbVpiWExwbnJnNDRfYWhZY3htaTZ1Zw",
            "use": "sig",
            "alg": "Ed448",
            "kty": "OKP",
            "crv": "Ed448",
            "x": "C3y5YN00IxyadHXm4NApPGAzv5w8s9e-fbGu2svYrrCuJDYDDZe-uEOPSobII6psCZCEvo2howmA",
        },
    ]
}


def test_load_spomky_keys():
    kj = KeyJar()
    kj.import_jwks(JWKS_SPO, "")
    assert len(kj.get_issuer_keys("")) == 4


def test_get_ec():
    kj = KeyJar()
    kj.import_jwks(JWKS_SPO, "")
    k = kj.get("sig", "EC", alg="ES256")
    assert k


def test_get_ec_wrong_alg():
    kj = KeyJar()
    kj.import_jwks(JWKS_SPO, "")
    k = kj.get("sig", "EC", alg="ES512")
    assert k == []


def test_get_eddsa():
    kj = KeyJar()
    kj.import_jwks(JWKS_EDDSA, "")
    assert len(kj.get_issuer_keys("")) == 4
    k = kj.get("sig", "OKP", alg="Ed25519")
    assert k
    k = kj.get("sig", "OKP", alg="Ed448")
    assert k


def test_keyjar_eq():
    kj1 = KeyJar()
    kj1.import_jwks(JWKS_SPO, "")

    kj2 = KeyJar()
    kj2.import_jwks(JWKS_SPO, "")

    assert kj1 == kj2


def test_keys_by_alg_and_usage():
    kj = KeyJar()
    kj.import_jwks(JWKS_SPO, "")
    k = kj.keys_by_alg_and_usage("", "RS256", "sig")
    assert len(k) == 2


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
        self.alice_keyjar.import_jwks(
            self.alice_keyjar.export_jwks(private=True, issuer_id=""), "Alice"
        )
        self.bob_keyjar.import_jwks(self.bob_keyjar.export_jwks(private=True, issuer_id=""), "Bob")

        # To Alice's keyjar add Bob's public keys
        self.alice_keyjar.import_jwks(self.bob_keyjar.export_jwks(issuer_id="Bob"), "Bob")

        # To Bob's keyjar add Alice's public keys
        self.bob_keyjar.import_jwks(self.alice_keyjar.export_jwks(issuer_id="Alice"), "Alice")

        _jws = JWS('{"aud": "Bob", "iss": "Alice"}', alg="RS256")
        sig_key = self.alice_keyjar.get_signing_key("rsa", issuer_id="Alice")[0]
        self.sjwt_a = _jws.sign_compact([sig_key])

        _jws = JWS('{"aud": "Alice", "iss": "Bob"}', alg="RS256")
        sig_key = self.bob_keyjar.get_signing_key("rsa", issuer_id="Bob")[0]
        self.sjwt_b = _jws.sign_compact([sig_key])

    def test_no_kid_multiple_keys(self):
        """This is extremely strict"""
        _jwt = factory(self.sjwt_a)
        # remove kid reference
        _jwt.jwt.headers["kid"] = ""
        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt)
        assert len(keys) == 0
        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt, allow_missing_kid=True)
        assert len(keys) == 3

    def test_no_kid_single_key(self):
        _jwt = factory(self.sjwt_b)
        _jwt.jwt.headers["kid"] = ""
        keys = self.alice_keyjar.get_jwt_verify_keys(_jwt.jwt)
        assert len(keys) == 1

    def test_no_kid_multiple_keys_no_kid_issuer(self):
        a_kids = [
            k.kid for k in self.alice_keyjar.get_verify_key(issuer_id="Alice", key_type="RSA")
        ]
        no_kid_issuer = {"Alice": a_kids}
        _jwt = factory(self.sjwt_a)
        _jwt.jwt.headers["kid"] = ""
        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt, no_kid_issuer=no_kid_issuer)
        assert len(keys) == 3

    def test_no_kid_multiple_keys_no_kid_issuer_lim(self):
        no_kid_issuer = {"Alice": []}
        _jwt = factory(self.sjwt_a)
        _jwt.jwt.headers["kid"] = ""
        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt, no_kid_issuer=no_kid_issuer)
        assert len(keys) == 3

    def test_matching_kid(self):
        _jwt = factory(self.sjwt_b)
        keys = self.alice_keyjar.get_jwt_verify_keys(_jwt.jwt)
        assert len(keys) == 1

    def test_no_matching_kid(self):
        _jwt = factory(self.sjwt_b)
        _jwt.jwt.headers["kid"] = "abcdef"
        keys = self.alice_keyjar.get_jwt_verify_keys(_jwt.jwt)
        assert keys == []

    def test_aud(self):
        self.alice_keyjar.import_jwks(JWK1, issuer_id="D")
        self.bob_keyjar.import_jwks(JWK1, issuer_id="D")

        _jws = JWS('{"iss": "D", "aud": "A"}', alg="HS256")
        sig_key = self.alice_keyjar.get_signing_key("oct", issuer_id="D")[0]
        _sjwt = _jws.sign_compact([sig_key])

        no_kid_issuer = {"D": []}

        _jwt = factory(_sjwt)

        keys = self.bob_keyjar.get_jwt_verify_keys(_jwt.jwt, no_kid_issuer=no_kid_issuer)
        assert len(keys) == 1

    def test_inactive_verify_key(self):
        _jwt = factory(self.sjwt_b)
        self.alice_keyjar.return_issuer("Bob")[0].mark_all_as_inactive()
        keys = self.alice_keyjar.get_jwt_verify_keys(_jwt.jwt)
        assert len(keys) == 0


def test_copy():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))

    kjc = kj.copy()

    assert set(kjc.owners()) == {"Alice", "Bob", "C"}

    assert len(kjc.get("sig", "oct", "Alice")) == 0
    assert len(kjc.get("sig", "rsa", "Alice")) == 1

    assert len(kjc.get("sig", "oct", "Bob")) == 1
    assert len(kjc.get("sig", "rsa", "Bob")) == 1

    assert len(kjc.get("sig", "oct", "C")) == 0
    assert len(kjc.get("sig", "rsa", "C")) == 2


def test_repr():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))
    txt = kj.__repr__()
    assert "<KeyJar(issuers=[" in txt
    _d = eval(txt[16:-2])
    assert set(_d) == {"Alice", "Bob", "C"}


def test_get_wrong_owner():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))
    assert kj.get("sig", "rsa", "https://delphi.example.com/") == []
    assert kj.get("sig", "rsa", "https://delphi.example.com") == []
    assert kj.get("sig", "rsa") == []

    assert "https://delphi.example.com" not in kj
    with pytest.raises(KeyError):
        kj["https://delphi.example.com"]


def test_match_owner():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("https://delphi.example.com/path", KeyBundle(JWK2["keys"]))
    a = kj.match_owner("https://delphi.example.com")
    assert a == "https://delphi.example.com/path"

    with pytest.raises(KeyError):
        kj.match_owner("https://example.com")


def test_str():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))

    desc = "{}".format(kj)
    _cont = json.loads(desc)
    assert set(_cont.keys()) == {"Alice"}


def test_load_keys():
    kj = KeyJar()
    kj.load_keys("Alice", jwks=JWK1)

    assert kj.owners() == ["Alice"]


def test_find():
    _path = full_path("jwk_private_key.json")
    kb = KeyBundle(source="file://{}".format(_path))
    kj = KeyJar()
    kj.add_kb("Alice", kb)

    assert kj.find("{}".format(_path), "Alice")
    assert kj.find("https://example.com", "Alice") == []
    assert kj.find("{}".format(_path), "Bob") is None


def test_get_decrypt_keys():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))

    kb = rsa_init({"use": ["enc", "sig"], "size": 1024, "name": "rsa", "path": "keys"})
    kj.add_kb("", kb)

    jwt = JWEnc()
    jwt.headers = {"alg": "RS256"}
    jwt.part = [{"alg": "RS256"}, '{"aud": "Bob", "iss": "Alice"}', "aksjdhaksjbd"]

    keys = kj.get_jwt_decrypt_keys(jwt)
    assert keys

    jwt.part = [{"alg": "RS256"}, '{"iss": "Alice"}', "aksjdhaksjbd"]

    keys = kj.get_jwt_decrypt_keys(jwt)
    assert keys

    with pytest.raises(IssuerNotFound):
        keys = kj.get_jwt_decrypt_keys(jwt, aud="Bob")


def test_update_keyjar():
    _path = full_path("jwk_private_key.json")
    kb = KeyBundle(source="file://{}".format(_path))
    kj = KeyJar()
    kj.add_kb("Alice", kb)

    kj.update()


def test_key_summary():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))

    out = kj.key_summary("Alice")
    assert out == "RSA::abc"


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
KEYSPEC_3 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
    {"type": "EC", "crv": "P-521", "use": ["sig"]},
]
KEYSPEC_4 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
]
KEYSPEC_5 = [
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
]


def test_init_key_jar():
    # Nothing written to file
    _keyjar = init_key_jar(key_defs=KEYSPEC)
    assert list(_keyjar.owners()) == [""]
    assert len(_keyjar.get_issuer_keys("")) == 2


def test_init_key_jar_dump_public():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # JWKS with public keys written to file
    _keyjar = init_key_jar(public_path=PUBLIC_FILE, key_defs=KEYSPEC)
    assert list(_keyjar.owners()) == [""]

    # JWKS will be read from disc, not created new
    _keyjar2 = init_key_jar(public_path=PUBLIC_FILE, key_defs=KEYSPEC)
    assert list(_keyjar2.owners()) == [""]

    # verify that the 2 Key jars contains the same keys


def test_init_key_jar_dump_private():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # New set of keys, JWKSs with keys and public written to file
    _keyjar = init_key_jar(
        private_path=PRIVATE_FILE, key_defs=KEYSPEC, issuer_id="https://example.com"
    )
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
        issuer_id="https://example.com",
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


OIDC_KEYS = {
    "private_path": "{}/priv/jwks.json".format(BASEDIR),
    "key_defs": KEYSPEC,
    "public_path": "{}/public/jwks.json".format(BASEDIR),
}


def test_init_key_jar_create_directories():
    # make sure the directories are gone
    for _dir in ["priv", "public"]:
        if os.path.isdir("{}/{}".format(BASEDIR, _dir)):
            shutil.rmtree("{}/{}".format(BASEDIR, _dir))

    _keyjar = init_key_jar(**OIDC_KEYS)
    assert len(_keyjar.get_signing_key("RSA")) == 1
    assert len(_keyjar.get_signing_key("EC")) == 1


def test_dump():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))

    res = kj.dump()

    nkj = KeyJar().load(res)
    assert set(nkj.owners()) == {"Alice", "Bob", "C"}
    assert nkj.get_signing_key("rsa", "Alice", kid="abc")
    assert nkj.get_signing_key(
        "rsa", "C", kid="R3NJRW1EVHRsaUcwSXVydi14cVVoTmxhaU4zckU1MlFPa05NWGNpUUZtcw"
    )


def test_dump_json():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))

    res = kj.dump()
    assert json.dumps(res)


def test_contains():
    kj = KeyJar()
    kj.add_kb("Alice", KeyBundle(JWK0["keys"]))
    kj.add_kb("Bob", KeyBundle(JWK1["keys"]))
    kj.add_kb("C", KeyBundle(JWK2["keys"]))

    assert "Bob" in kj
    assert "David" not in kj


def test_similar():
    ISSUER = "xyzzy"

    kj = KeyJar()
    kb = KeyBundle(JWK2)
    kj.add_kb(issuer_id=ISSUER, kb=kb)

    keys1 = kj.get_issuer_keys(ISSUER)
    keys2 = kj[ISSUER].all_keys()
    assert keys1 == keys2
