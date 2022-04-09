# pylint: disable=missing-docstring,no-self-use
import json
import os
import shutil
import time
from pathlib import Path

import pytest
import requests
import responses
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptojwt.exception import UnknownKeyType
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_rsa_key_from_cert_file
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_bundle import UpdateFailed
from cryptojwt.key_bundle import build_key_bundle
from cryptojwt.key_bundle import dump_jwks
from cryptojwt.key_bundle import init_key
from cryptojwt.key_bundle import key_diff
from cryptojwt.key_bundle import key_gen
from cryptojwt.key_bundle import key_rollover
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_bundle import rsa_init
from cryptojwt.key_bundle import unique_keys
from cryptojwt.key_bundle import update_key_bundle

__author__ = "Roland Hedberg"

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_keys"))

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


RSAKEY = os.path.join(BASE_PATH, "cert.key")
RSA0 = os.path.join(BASE_PATH, "rsa.key")
EC0 = os.path.join(BASE_PATH, "ec.key")
CERT = full_path("cert.pem")

JWK0 = {
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "abc",
            "n": "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY"
            "2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfK"
            "qoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8",
        }
    ]
}

JWK1 = {
    "keys": [
        {
            "n": "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S"
            "_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFY"
            "Inq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVb"
            "CGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znan"
            "LwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MX"
            "sGxBHf3AKT5w",
            "e": "AQAB",
            "kty": "RSA",
            "kid": "rsa1",
        },
        {
            "k": "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNT" "Y0NzMzYjE",
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

if os.path.isdir("keys"):
    shutil.rmtree("keys")


def test_with_sym_key():
    kc = KeyBundle({"kty": "oct", "key": "highestsupersecret", "use": "sig"})
    assert len(kc.get("oct")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None


def test_with_2_sym_key():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    assert len(kb.get("oct")) == 2
    assert len(kb) == 2

    assert kb.get_key_with_kid("kid") is None
    assert len(kb.kids()) == 2


def test_remove_sym():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    assert len(kb) == 2
    keys = kb.get("oct")
    kb.remove(keys[0])
    assert len(kb) == 1


def test_remove_key_sym():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    assert len(kb) == 2
    keys = kb.get("oct")
    kb.remove(keys[0])
    assert len(kb) == 1

    # This should not work
    kb.remove_keys_by_type("rsa")
    # should still be one
    assert len(kb) == 1


def test_rsa_init():
    kb = rsa_init({"use": ["enc", "sig"], "size": 1024, "name": "rsa", "path": "keys"})
    assert kb
    assert len(kb) == 2
    assert len(kb.get("rsa")) == 2


def test_rsa_init_under_spec():
    kb = rsa_init({"use": ["enc", "sig"], "size": 1024})
    assert kb
    assert len(kb) == 2
    assert len(kb.get("rsa")) == 2


def test_unknown_source():
    with pytest.raises(ImportError):
        KeyBundle(source="foobar")


def test_ignore_unknown_types():
    kb = KeyBundle(
        {
            "kid": "q-H9y8iuh3BIKZBbK6S0mH_isBlJsk"
            "-u6VtZ5rAdBo5fCjjy3LnkrsoK_QWrlKB08j_PcvwpAMfTEDHw5spepw",
            "use": "sig",
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "FnbcUAXZ4ySvrmdXK1MrDuiqlqTXvGdAaE4RWZjmFIQ",
        }
    )

    assert len(kb) == 0


def test_remove_rsa():
    kb = rsa_init({"use": ["enc", "sig"], "size": 1024, "name": "rsa", "path": "keys"})
    assert len(kb) == 2
    keys = kb.get("rsa")
    assert len(keys) == 2
    kb.remove(keys[0])
    assert len(kb) == 1


def test_key_mix():
    kb = rsa_init({"use": ["enc", "sig"], "size": 1024, "name": "rsa", "path": "keys"})
    _sym = SYMKey(**{"kty": "oct", "key": "highestsupersecret", "use": "enc"})
    kb.append(_sym)
    assert len(kb) == 3
    assert len(kb.get("rsa")) == 2
    assert len(kb.get("oct")) == 1

    kb.remove(_sym)

    assert len(kb) == 2
    assert len(kb.get("rsa")) == 2
    assert len(kb.get("oct")) == 0


def test_get_all():
    kb = rsa_init({"use": ["enc", "sig"], "size": 1024, "name": "rsa", "path": "keys"})
    _sym = SYMKey(**{"kty": "oct", "key": "highestsupersecret", "use": "enc"})
    kb.append(_sym)
    assert len(kb.get()) == 3

    _k = kb.keys()
    assert len(_k) == 3


def test_keybundle_from_local_der():
    kb = keybundle_from_local_file("{}".format(RSA0), "der", ["enc"])
    assert len(kb) == 1
    keys = kb.get("rsa")
    assert len(keys) == 1
    _key = keys[0]
    assert isinstance(_key, RSAKey)
    assert _key.kid


def test_ec_keybundle_from_local_der():
    kb = keybundle_from_local_file("{}".format(EC0), "der", ["enc"], keytype="EC")
    assert len(kb) == 1
    keys = kb.get("ec")
    assert len(keys) == 1
    _key = keys[0]
    assert _key.kid
    assert isinstance(_key, ECKey)


def test_keybundle_from_local_der_update():
    kb = keybundle_from_local_file("file://{}".format(RSA0), "der", ["enc"])
    assert len(kb) == 1
    keys = kb.get("rsa")
    assert len(keys) == 1
    _key = keys[0]
    assert _key.kid
    assert isinstance(_key, RSAKey)

    kb.update()

    # Nothing should change
    assert len(kb) == 1
    keys = kb.get("rsa")
    assert len(keys) == 1
    _key = keys[0]
    assert _key.kid
    assert isinstance(_key, RSAKey)


def test_creat_jwks_sym():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([a])
    _jwks = kb.jwks()
    _loc = json.loads(_jwks)
    assert list(_loc.keys()) == ["keys"]
    assert set(_loc["keys"][0].keys()) == {"kty", "use", "k", "kid"}


def test_keybundle_from_local_jwks_file():
    kb = keybundle_from_local_file(
        "file://{}".format(os.path.join(BASE_PATH, "jwk.json")), "jwks", ["sig"]
    )
    assert len(kb) == 1


def test_keybundle_from_local_jwks():
    kb = keybundle_from_local_file(
        "{}".format(os.path.join(BASE_PATH, "jwk.json")), "jwks", ["sig"]
    )
    assert len(kb) == 1


def test_update():
    kc = KeyBundle([{"kty": "oct", "key": "highestsupersecret", "use": "sig"}])
    assert len(kc.get("oct")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None

    kc.update()  # Nothing should happen
    assert len(kc.get("oct")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None


def test_update_RSA():
    kc = keybundle_from_local_file(RSAKEY, "der", ["sig"])
    assert kc.remote is False
    assert len(kc.get("oct")) == 0
    assert len(kc.get("RSA")) == 1

    key = kc.get("RSA")[0]
    assert isinstance(key, RSAKey)

    kc.update()
    assert kc.remote is False
    assert len(kc.get("oct")) == 0
    assert len(kc.get("RSA")) == 1

    key = kc.get("RSA")[0]
    assert isinstance(key, RSAKey)


def test_outdated():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    keys = kb.keys()
    now = time.time()
    keys[0].inactive_since = now - 60
    kb.remove_outdated(30)
    assert len(kb) == 1


def test_dump_jwks():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb2 = KeyBundle([a, b])

    kb1 = rsa_init({"use": ["enc", "sig"], "size": 1024, "name": "rsa", "path": "keys"})

    # Will not dump symmetric keys
    dump_jwks([kb1, kb2], "jwks_combo")

    # Now read it

    nkb = KeyBundle(source="file://jwks_combo", fileformat="jwks")

    assert len(nkb) == 2
    # both RSA keys
    assert len(nkb.get("rsa")) == 2

    # Will dump symmetric keys
    dump_jwks([kb1, kb2], "jwks_combo", symmetric_too=True)

    # Now read it
    nkb = KeyBundle(source="file://jwks_combo", fileformat="jwks")

    assert len(nkb) == 4
    # two RSA keys
    assert len(nkb.get("rsa")) == 2
    # two symmetric keys
    assert len(nkb.get("oct")) == 2


def test_mark_as_inactive():
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([desc])
    assert len(kb.keys()) == 1
    for k in kb.keys():
        kb.mark_as_inactive(k.kid)
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb.add_jwk_dicts([desc])
    assert len(kb.keys()) == 2
    assert len(kb.active_keys()) == 1


def test_copy():
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([desc])
    assert len(kb.keys()) == 1
    for k in kb.keys():
        kb.mark_as_inactive(k.kid)
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb.add_jwk_dicts([desc])

    kbc = kb.copy()
    assert len(kbc.keys()) == 2
    assert len(kbc.active_keys()) == 1


def test_local_jwk():
    _path = full_path("jwk_private_key.json")
    kb = KeyBundle(source="file://{}".format(_path))
    assert kb


def test_local_jwk_update():
    cache_time = 0.1
    _path = full_path("jwk_private_key.json")
    kb = KeyBundle(source="file://{}".format(_path), cache_time=cache_time)
    assert kb
    _ = kb.keys()
    last1 = kb.last_local
    _ = kb.keys()
    last2 = kb.last_local
    assert last1 == last2  # file not changed
    time.sleep(cache_time + 0.1)
    Path(_path).touch()
    _ = kb.keys()
    last3 = kb.last_local
    assert last2 != last3  # file changed


def test_local_jwk_copy():
    _path = full_path("jwk_private_key.json")
    kb = KeyBundle(source="file://{}".format(_path))
    kb2 = kb.copy()
    assert kb2.source == kb.source


# def test_remote(httpserver):
#     httpserver.serve_content(json.dumps(JWK1))
#     kb = KeyBundle(source=httpserver.url)
#     assert len(kb.keys())
#     assert len(kb.get('rsa')) == 1
#     assert len(kb.get('oct')) == 1


@pytest.fixture()
def mocked_jwks_response():
    with responses.RequestsMock() as rsps:
        yield rsps


def test_httpc_params_1():
    source = "https://login.salesforce.com/id/keys"  # From test_jwks_url()
    # Mock response
    with responses.RequestsMock() as rsps:
        rsps.add(method=responses.GET, url=source, json=JWKS_DICT, status=200)
        httpc_params = {"timeout": (2, 2)}  # connect, read timeouts in seconds
        kb = KeyBundle(source=source, httpc=requests.request, httpc_params=httpc_params)
        updated, _ = kb._do_remote()
        assert updated == True


@pytest.mark.network
def test_httpc_params_2():
    httpc_params = {"timeout": 0}
    kb = KeyBundle(
        source="https://login.salesforce.com/id/keys",
        httpc=requests.request,
        httpc_params=httpc_params,
    )
    # Will always fail to fetch the JWKS because the timeout cannot be set
    # to 0s
    assert not kb.update()


def test_update_2():
    rsa_key = new_rsa_key()
    _jwks = {"keys": [rsa_key.serialize()]}
    fname = "tmp_jwks.json"
    with open(fname, "w") as fp:
        fp.write(json.dumps(_jwks))

    kb = KeyBundle(source="file://{}".format(fname), fileformat="jwks")
    assert len(kb) == 1

    # Added one more key
    ec_key = new_ec_key(crv="P-256", key_ops=["sign"])
    _jwks = {"keys": [rsa_key.serialize(), ec_key.serialize()]}

    time.sleep(0.5)
    with open(fname, "w") as fp:
        fp.write(json.dumps(_jwks))

    kb.update()
    assert len(kb) == 2


def test_update_mark_inactive():
    rsa_key = new_rsa_key()
    _jwks = {"keys": [rsa_key.serialize()]}
    fname = "tmp_jwks.json"
    with open(fname, "w") as fp:
        fp.write(json.dumps(_jwks))

    kb = KeyBundle(source="file://{}".format(fname), fileformat="jwks")
    assert len(kb) == 1

    # new set of keys
    rsa_key = new_rsa_key(alg="RS256")
    ec_key = new_ec_key(crv="P-256")
    _jwks = {"keys": [rsa_key.serialize(), ec_key.serialize()]}

    with open(fname, "w") as fp:
        fp.write(json.dumps(_jwks))

    kb.update()
    # 2 active and 1 inactive
    assert len(kb) == 3
    assert len(kb.active_keys()) == 2

    assert len(kb.get("rsa")) == 1
    assert len(kb.get("rsa", only_active=False)) == 2


def test_loads_0():
    kb = KeyBundle(JWK0)
    assert len(kb) == 1
    key = kb.get("rsa")[0]
    assert key.kid == "abc"
    assert key.kty == "RSA"


def test_loads_1():
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "e": "AQAB",
                "n": "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8",
                "kid": "1",
            },
            {
                "kty": "RSA",
                "use": "enc",
                "e": "AQAB",
                "n": "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8",
                "kid": "2",
            },
        ]
    }

    kb = KeyBundle(jwks)

    assert len(kb) == 2
    assert set(kb.kids()) == {"1", "2"}


def test_dump_jwk():
    kb = KeyBundle()
    kb.append(RSAKey(pub_key=import_rsa_key_from_cert_file(CERT)))
    jwks = kb.jwks()

    _wk = json.loads(jwks)
    assert list(_wk.keys()) == ["keys"]
    assert len(_wk["keys"]) == 1
    assert set(_wk["keys"][0].keys()) == {"kty", "e", "n"}

    kb2 = KeyBundle(_wk)

    assert len(kb2) == 1
    key = kb2.get("rsa")[0]
    assert key.kty == "RSA"
    assert isinstance(key.public_key(), rsa.RSAPublicKey)


JWKS_DICT = {
    "keys": [
        {
            "n": "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": "AQAB",
            "kty": "RSA",
            "kid": "5-VBFv40P8D4I-7SFz7hMugTbPs",
            "use": "enc",
        },
        {
            "k": "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct",
            "use": "enc",
        },
        {
            "kty": "EC",
            "kid": "7snis",
            "use": "sig",
            "x": "q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po",
            "y": "GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E",
            "crv": "P-256",
        },
    ]
}


def test_keys():
    kb = KeyBundle(JWKS_DICT)

    assert len(kb) == 3

    assert len(kb.get("rsa")) == 1
    assert len(kb.get("oct")) == 1
    assert len(kb.get("ec")) == 1


EXPECTED = [
    b"iA7PvG_DfJIeeqQcuXFmvUGjqBkda8In_uMpZrcodVA",
    b"akXzyGlXg8yLhsCczKb_r8VERLx7-iZBUMIVgg2K7p4",
    b"kLsuyGef1kfw5-t-N9CJLIHx_dpZ79-KemwqjwdrvTI",
]


def test_thumbprint():
    kb = KeyBundle(JWKS_DICT)
    for key in kb:
        txt = key.thumbprint("SHA-256")
        assert txt in EXPECTED


@pytest.mark.network
def test_jwks_url():
    keys = KeyBundle(source="https://login.salesforce.com/id/keys")
    # Forces read from the network
    keys.update()
    assert len(keys)


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

KEYSPEC_6 = [
    {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "code"},
    {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "token"},
    {"type": "oct", "bytes": "24", "use": ["enc"], "kid": "refresh_token"},
]


def test_key_diff_none():
    _kb = build_key_bundle(key_conf=KEYSPEC)

    diff = key_diff(_kb, KEYSPEC)
    assert not diff


def test_key_diff_add_one_ec():
    _kb = build_key_bundle(key_conf=KEYSPEC)

    diff = key_diff(_kb, KEYSPEC_2)
    assert diff
    assert set(diff.keys()) == {"add"}
    assert len(diff["add"]) == 1
    assert diff["add"][0].kty == "EC"


def test_key_diff_add_two_ec():
    _kb = build_key_bundle(key_conf=KEYSPEC)

    diff = key_diff(_kb, KEYSPEC_3)
    assert diff
    assert set(diff.keys()) == {"add"}
    assert len(diff["add"]) == 2
    assert diff["add"][0].kty == "EC"


def test_key_diff_add_ec_and_rsa():
    _kb = build_key_bundle(key_conf=KEYSPEC)

    diff = key_diff(_kb, KEYSPEC_4)
    assert diff
    assert set(diff.keys()) == {"add"}
    assert len(diff["add"]) == 2
    assert set([k.kty for k in diff["add"]]) == {"EC", "RSA"}


def test_key_diff_add_ec_del_rsa():
    _kb = build_key_bundle(key_conf=KEYSPEC)

    diff = key_diff(_kb, KEYSPEC_5)
    assert diff
    assert set(diff.keys()) == {"add", "del"}
    assert len(diff["add"]) == 1
    assert len(diff["del"]) == 1
    assert diff["add"][0].kty == "EC"
    assert diff["del"][0].kty == "RSA"


def test_key_bundle_update_1():
    _kb = build_key_bundle(key_conf=KEYSPEC)
    diff = key_diff(_kb, KEYSPEC_2)
    update_key_bundle(_kb, diff)

    # There should be 3 keys
    assert len(_kb) == 3

    # one RSA
    assert len(_kb.get("RSA")) == 1

    # 2 EC
    assert len(_kb.get("EC")) == 2


def test_key_bundle_update_2():
    _kb = build_key_bundle(key_conf=KEYSPEC)
    diff = key_diff(_kb, KEYSPEC_4)
    update_key_bundle(_kb, diff)

    # There should be 3 keys
    assert len(_kb) == 4

    # one RSA
    assert len(_kb.get("RSA")) == 2

    # 2 EC
    assert len(_kb.get("EC")) == 2


def test_key_bundle_update_3():
    _kb = build_key_bundle(key_conf=KEYSPEC)
    diff = key_diff(_kb, KEYSPEC_5)
    update_key_bundle(_kb, diff)

    # There should be 3 keys
    assert len(_kb) == 3

    # One inactive. Only active is implicit
    assert len(_kb.get()) == 2

    # one inactive RSA
    assert len(_kb.get("RSA", only_active=False)) == 1
    assert len(_kb.get("RSA")) == 0

    # 2 EC
    assert len(_kb.get("EC")) == 2
    assert len(_kb.get("EC", only_active=False)) == 2


def test_key_rollover():
    kb_0 = build_key_bundle(key_conf=KEYSPEC)
    assert len(kb_0.get(only_active=False)) == 2
    assert len(kb_0.get()) == 2

    kb_1 = key_rollover(kb_0)

    assert len(kb_1.get(only_active=False)) == 4
    assert len(kb_1.get()) == 2


def test_build_key_bundle_sym():
    _kb = build_key_bundle(key_conf=KEYSPEC_6)
    assert len(_kb) == 3

    assert len(_kb.get("RSA")) == 0
    assert len(_kb.get("EC")) == 0
    assert len(_kb.get("oct")) == 3


def test_key_bundle_difference_none():
    _kb0 = build_key_bundle(key_conf=KEYSPEC_6)
    _kb1 = KeyBundle()
    _kb1.extend(_kb0.keys())

    assert _kb0.difference(_kb1) == []


def test_key_bundle_difference():
    _kb0 = build_key_bundle(key_conf=KEYSPEC_6)
    _kb1 = build_key_bundle(key_conf=KEYSPEC_2)

    assert _kb0.difference(_kb1) == _kb0.keys()
    assert _kb1.difference(_kb0) == _kb1.keys()


def test_unique_keys_1():
    _kb0 = build_key_bundle(key_conf=KEYSPEC_6)
    _kb1 = build_key_bundle(key_conf=KEYSPEC_6)

    keys = _kb0.keys()
    keys.extend(_kb1.keys())

    # All of them
    assert len(unique_keys(keys)) == 6


def test_unique_keys_2():
    _kb0 = build_key_bundle(key_conf=KEYSPEC_6)
    _kb1 = KeyBundle()
    _kb1.extend(_kb0.keys())

    keys = _kb0.keys()
    keys.extend(_kb1.keys())

    # 3 of 6
    assert len(unique_keys(keys)) == 3


def test_key_gen_rsa():
    _jwk = key_gen("RSA", kid="kid1")
    assert _jwk
    assert _jwk.kty == "RSA"
    assert _jwk.kid == "kid1"

    assert isinstance(_jwk, RSAKey)


def test_init_key():
    spec = {"type": "RSA", "kid": "one"}

    filename = full_path("tmp_jwk.json")
    if os.path.isfile(filename):
        os.unlink(filename)

    _key = init_key(filename, **spec)
    assert _key.kty == "RSA"
    assert _key.kid == "one"

    assert os.path.isfile(filename)

    # Should not lead to any change
    _jwk2 = init_key(filename, **spec)
    assert _key == _jwk2

    _jwk3 = init_key(filename, "RSA", "two")
    assert _key != _jwk3

    # Now _jwk3 is stored in the file
    _jwk4 = init_key(filename, "RSA")
    assert _jwk4 == _jwk3


def test_export_inactive():
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([desc])
    assert len(kb.keys()) == 1
    for k in kb.keys():
        kb.mark_as_inactive(k.kid)
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb.add_jwk_dicts([desc])
    res = kb.dump()
    assert set(res.keys()) == {
        "cache_time",
        "etag",
        "fileformat",
        "httpc_params",
        "ignore_errors_until",
        "ignore_errors_period",
        "ignore_invalid_keys",
        "imp_jwks",
        "keys",
        "keytype",
        "keyusage",
        "last_updated",
        "last_remote",
        "last_local",
        "remote",
        "local",
        "source",
        "time_out",
    }

    kb2 = KeyBundle().load(res)
    assert len(kb2.keys()) == 2
    assert len(kb2.active_keys()) == 1


def test_remote():
    source = "https://example.com/test_remote/keys.json"
    # Mock response
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=source, json=JWKS_DICT, status=200)
        httpc_params = {"timeout": (2, 2)}  # connect, read timeouts in seconds
        kb = KeyBundle(source=source, httpc=requests.request, httpc_params=httpc_params)
        kb._do_remote()

    exp = kb.dump()
    kb2 = KeyBundle().load(exp)
    assert kb2.source == source
    assert len(kb2.keys()) == 3
    assert len(kb2.get("rsa")) == 1
    assert len(kb2.get("oct")) == 1
    assert len(kb2.get("ec")) == 1
    assert kb2.httpc_params == {"timeout": (2, 2)}
    assert kb2.imp_jwks
    assert kb2.last_updated


def test_remote_not_modified():
    source = "https://example.com/test_remote_not_modified/keys.json"
    headers = {
        "Date": "Fri, 15 Mar 2019 10:14:25 GMT",
        "Last-Modified": "Fri, 1 Jan 1970 00:00:00 GMT",
    }
    headers = {}

    # Mock response
    httpc_params = {"timeout": (2, 2)}  # connect, read timeouts in seconds
    kb = KeyBundle(source=source, httpc=requests.request, httpc_params=httpc_params)

    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=source, json=JWKS_DICT, status=200, headers=headers)
        updated, _ = kb._do_remote()
        assert updated == True
        assert kb.last_remote == headers.get("Last-Modified")
        timeout1 = kb.time_out

    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=source, status=304, headers=headers)
        updated, _ = kb._do_remote()
        assert not updated
        assert kb.last_remote == headers.get("Last-Modified")
        timeout2 = kb.time_out

    assert timeout1 != timeout2

    exp = kb.dump()
    kb2 = KeyBundle().load(exp)
    assert kb2.source == source
    assert len(kb2.keys()) == 3
    assert len(kb2.active_keys()) == 3
    assert len(kb2.get("rsa")) == 1
    assert len(kb2.get("oct")) == 1
    assert len(kb2.get("ec")) == 1
    assert kb2.httpc_params == {"timeout": (2, 2)}
    assert kb2.imp_jwks
    assert kb2.last_updated


def test_ignore_errors_period():
    source_good = "https://example.com/test_ignore_errors_period/keys.json"
    source_bad = "https://example.com/test_ignore_errors_period/keys-bad.json"
    ignore_errors_period = 1
    # Mock response
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=source_good, json=JWKS_DICT, status=200)
        rsps.add(method="GET", url=source_bad, json=JWKS_DICT, status=500)
        httpc_params = {"timeout": (2, 2)}  # connect, read timeouts in seconds
        kb = KeyBundle(
            source=source_good,
            httpc=requests.request,
            httpc_params=httpc_params,
            ignore_errors_period=ignore_errors_period,
        )
        res, _ = kb._do_remote()
        assert res == True
        assert kb.ignore_errors_until is None

        # refetch, but fail by using a bad source
        kb.source = source_bad
        try:
            res, _ = kb._do_remote()
        except UpdateFailed:
            pass

        # retry should fail silently as we're in holddown
        res, _ = kb._do_remote()
        assert kb.ignore_errors_until is not None
        assert res == False

        # wait until holddown
        time.sleep(ignore_errors_period + 1)

        # try again
        kb.source = source_good
        res, _ = kb._do_remote()
        assert res == True


def test_ignore_invalid_keys():
    rsa_key_dict = new_rsa_key().serialize()
    rsa_key_dict["kty"] = "b0rken"

    kb = KeyBundle(keys={"keys": [rsa_key_dict]}, ignore_invalid_keys=True)
    assert len(kb) == 0

    with pytest.raises(UnknownKeyType):
        KeyBundle(keys={"keys": [rsa_key_dict]}, ignore_invalid_keys=False)


def test_exclude_attributes():
    source = "https://example.com/test_exclude_attributes/keys.json"
    # Mock response
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=source, json=JWKS_DICT, status=200)
        httpc_params = {"timeout": (2, 2)}  # connect, read timeouts in seconds
        kb = KeyBundle(source=source, httpc=requests.request, httpc_params=httpc_params)
        kb._do_remote()

    exp = kb.dump(exclude_attributes=["cache_time", "ignore_invalid_keys"])
    kb2 = KeyBundle(cache_time=600, ignore_invalid_keys=False).load(exp)
    assert kb2.cache_time == 600
    assert kb2.ignore_invalid_keys is False


def test_remote_dump_json():
    source = "https://example.com/keys.json"
    # Mock response
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=source, json=JWKS_DICT, status=200)
        httpc_params = {"timeout": (2, 2)}  # connect, read timeouts in seconds
        kb = KeyBundle(source=source, httpc=requests.request, httpc_params=httpc_params)
        kb._do_remote()

    exp = kb.dump()
    assert json.dumps(exp)
