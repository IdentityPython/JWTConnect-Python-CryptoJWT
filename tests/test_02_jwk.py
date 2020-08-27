#!/usr/bin/env python3
from __future__ import print_function

import base64
import json
import os.path
import struct
from collections import Counter

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptojwt.exception import DeSerializationNotPossible
from cryptojwt.exception import UnsupportedAlgorithm
from cryptojwt.exception import WrongUsage
from cryptojwt.jwk import JWK
from cryptojwt.jwk import calculate_x5t
from cryptojwt.jwk import certificate_fingerprint
from cryptojwt.jwk import pem_hash
from cryptojwt.jwk import pems_to_x5c
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.hmac import new_sym_key
from cryptojwt.jwk.hmac import sha256_digest
from cryptojwt.jwk.jwk import dump_jwk
from cryptojwt.jwk.jwk import import_jwk
from cryptojwt.jwk.jwk import jwk_wrap
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.jwk.rsa import import_public_rsa_key_from_file
from cryptojwt.jwk.rsa import import_rsa_key_from_cert_file
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwk.x509 import import_public_key_from_pem_file
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64e
from cryptojwt.utils import base64_to_long
from cryptojwt.utils import base64url_to_long
from cryptojwt.utils import long2intarr

__author__ = "Roland Hedberg"
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


CERT = full_path("cert.pem")
KEY = full_path("server.key")

N = (
    "wf-wiusGhA"
    "-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8"
)
E = "AQAB"

JWK_0 = {"keys": [{"kty": "RSA", "use": "foo", "e": E, "kid": "abc", "n": N}]}


def _eq(l1, l2):
    return Counter(l1) == Counter(l2)


def test_urlsafe_base64decode():
    l = base64_to_long(N)
    # convert it to base64
    bys = long2intarr(l)
    data = struct.pack("%sB" % len(bys), *bys)
    if not len(data):
        data = "\x00"
    s0 = base64.b64encode(data)
    # try to convert it back to long, should throw an exception if the strict
    # function is used
    with pytest.raises(ValueError):
        base64url_to_long(s0)

    # Not else, should not raise exception
    l = base64_to_long(s0)
    assert l


def test_import_rsa_key_from_cert_file():
    _ckey = import_rsa_key_from_cert_file(CERT)
    assert isinstance(_ckey, rsa.RSAPublicKey)


def test_extract_rsa_from_cert_2():
    _ckey = import_rsa_key_from_cert_file(CERT)
    _key = RSAKey()
    _key.load_key(_ckey)

    assert _ckey.public_numbers().n == base64_to_long(_key.n)


def test_kspec():
    _ckey = import_rsa_key_from_cert_file(CERT)
    _key = RSAKey()
    _key.load_key(_ckey)

    jwk = _key.serialize()
    assert jwk["kty"] == "RSA"
    assert jwk["e"] == JWK_0["keys"][0]["e"]
    assert jwk["n"] == JWK_0["keys"][0]["n"]

    assert not _key.has_private_key()


def test_dumps():
    _ckey = import_rsa_key_from_cert_file(CERT)
    jwk = jwk_wrap(_ckey).serialize()
    assert _eq(list(jwk.keys()), ["kty", "e", "n", "kid"])


def test_import_rsa_key():
    _ckey = import_private_rsa_key_from_file(full_path(KEY))
    assert isinstance(_ckey, rsa.RSAPrivateKey)
    djwk = jwk_wrap(_ckey).to_dict()

    assert _eq(djwk.keys(), ["kty", "e", "n", "p", "q", "d", "kid"])
    assert (
        djwk["n"] == "5zbNbHIYIkGGJ3RGdRKkYmF4gOorv5eDuUKTVtuu3VvxrpOWvwnFV"
        "-NY0LgqkQSMMyVzodJE3SUuwQTUHPXXY5784vnkFqzPRx6bHgPxKz7XfwQjEBTafQTMmOeYI8wFIOIHY5i0RWR-gxDbh_D5TXuUqScOOqR47vSpIbUH-nc"
    )
    assert djwk["e"] == "AQAB"


def test_serialize_rsa_pub_key():
    rsakey = RSAKey(pub_key=import_public_rsa_key_from_file(full_path("rsa.pub")))
    assert rsakey.d == ""

    d_rsakey = rsakey.serialize(private=True)
    restored_key = RSAKey(**d_rsakey)

    assert restored_key == rsakey


def test_serialize_rsa_priv_key():
    rsakey = RSAKey(priv_key=import_private_rsa_key_from_file(full_path("rsa.key")))
    assert rsakey.d

    d_rsakey = rsakey.serialize(private=True)
    restored_key = RSAKey(**d_rsakey)

    assert restored_key == rsakey
    assert rsakey.has_private_key()
    assert restored_key.has_private_key()


ECKEY = {
    "crv": "P-521",
    "x": u"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
    "y": u"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th"
    u"-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
    "d": u"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C",
}


def test_verify_2():
    _key = RSAKey()
    _key.load_key(import_rsa_key_from_cert_file(CERT))
    assert _key.verify()


def test_cmp_rsa():
    _key1 = RSAKey()
    _key1.load_key(import_rsa_key_from_cert_file(CERT))

    _key2 = RSAKey()
    _key2.load_key(import_rsa_key_from_cert_file(CERT))

    assert _key1 == _key2


def test_cmp_rsa_ec():
    _key1 = RSAKey()
    _key1.load_key(import_rsa_key_from_cert_file(CERT))

    _key2 = ECKey(**ECKEY)

    assert _key1 != _key2


def test_import_export_eckey():
    _key = ECKey(**ECKEY)
    _key.deserialize()
    assert _eq(list(_key.keys()), ["y", "x", "d", "crv", "kty"])


def test_new_ec_key():
    ec_key = new_ec_key("P-256")
    assert isinstance(ec_key, ECKey)


def test_create_eckey():
    ec = new_ec_key("P-256")
    exp_key = ec.serialize()
    assert _eq(list(exp_key.keys()), ["y", "x", "crv", "kty", "kid"])


def test_cmp_neq_ec():
    ec_key = new_ec_key("P-256")
    _key1 = ECKey(priv_key=ec_key.priv_key)
    _key2 = ECKey(**ECKEY)

    assert _key1 != _key2


def test_cmp_eq_ec():
    ec_key = new_ec_key("P-256")
    _key1 = ECKey(priv_key=ec_key.priv_key)
    _key2 = ECKey(priv_key=ec_key.priv_key)

    assert _key1 == _key2


def test_get_key():
    ec_key = new_ec_key("P-256")
    asym_private_key = ECKey(priv_key=ec_key.priv_key)
    asym_public_key = ECKey(pub_key=asym_private_key.pub_key)
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy")

    assert asym_private_key.private_key()
    assert asym_private_key.public_key()

    assert asym_public_key.private_key() is None
    assert asym_private_key.public_key()

    assert key.key


def test_private_rsa_key_from_jwk():
    keys = []

    kspec = json.loads(open(full_path("jwk_private_key.json")).read())
    keys.append(key_from_jwk_dict(kspec))

    key = keys[0]

    assert isinstance(key.n, (bytes, str))
    assert isinstance(key.e, (bytes, str))
    assert isinstance(key.d, (bytes, str))
    assert isinstance(key.p, (bytes, str))
    assert isinstance(key.q, (bytes, str))
    assert isinstance(key.dp, (bytes, str))
    assert isinstance(key.dq, (bytes, str))
    assert isinstance(key.qi, (bytes, str))

    _d = key.to_dict()

    assert _eq(
        list(_d.keys()),
        ["n", "alg", "dq", "e", "q", "p", "dp", "d", "ext", "key_ops", "kty", "qi"],
    )
    assert _eq(list(_d.keys()), kspec.keys())


def test_public_key_from_jwk():
    keys = []

    kspec = json.loads(open(full_path("jwk_private_key.json")).read())
    keys.append(key_from_jwk_dict(kspec, private=False))

    key = keys[0]

    assert isinstance(key.n, (bytes, str))
    assert isinstance(key.e, (bytes, str))

    _d = key.to_dict()

    assert _eq(list(_d.keys()), ["n", "alg", "e", "ext", "key_ops", "kty"])


def test_ec_private_key_from_jwk():
    keys = []

    kspec = json.loads(open(full_path("jwk_private_ec_key.json")).read())
    keys.append(key_from_jwk_dict(kspec))

    key = keys[0]

    assert isinstance(key.x, (bytes, str))
    assert isinstance(key.y, (bytes, str))
    assert isinstance(key.d, (bytes, str))

    _d = key.to_dict()

    assert _eq(list(_d.keys()), ["alg", "kty", "crv", "x", "y", "d"])
    assert _eq(list(_d.keys()), kspec.keys())


def test_ec_public_key_from_jwk():
    keys = []

    kspec = json.loads(open(full_path("jwk_private_ec_key.json")).read())
    keys.append(key_from_jwk_dict(kspec, private=False))

    key = keys[0]

    assert isinstance(key.x, (bytes, str))
    assert isinstance(key.y, (bytes, str))

    _d = key.to_dict()

    assert _eq(list(_d.keys()), ["x", "y", "alg", "crv", "kty"])


def test_rsa_pubkey_from_x509_cert_chain():
    cert = (
        "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDAOBgNVBAgTB0JhdmF"
        "yaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZXJ0aWZpY2F0aW9uIE"
        "F1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNMTUwNDE1MTQ1NjM4W"
        "hcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21iSDE7MDkGA1UEAxMy"
        "QmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb"
        "3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99bdzUUIhDZG34PQqcH"
        "89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3Xje8fu55Csh0JXNfo"
        "y29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisIVqur9aujYwdCoAZU"
        "8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT/7vdgS/IYXFniPuU"
        "fblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQYDVR0OBBYEFOfg3f"
        "/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpMAsGA1UdDwQEAwIDi"
        "DATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0549hEHRQArJXs1im"
        "7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3rDywi2a9GKzOFgrW"
        "pVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA2sW5AhPiCr9dVnMn"
        "/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqWSfPRBZV8htRIf0vT"
        "lGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="
    )
    rsa_key = RSAKey(x5c=[cert])
    assert rsa_key.pub_key


def test_rsa_pubkey_verify_x509_thumbprint():
    cert = (
        "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDAOBgNVBAgTB0JhdmF"
        "yaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZXJ0aWZpY2F0aW9uIE"
        "F1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNMTUwNDE1MTQ1NjM4W"
        "hcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21iSDE7MDkGA1UEAxMy"
        "QmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb"
        "3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99bdzUUIhDZG34PQqcH"
        "89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3Xje8fu55Csh0JXNfo"
        "y29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisIVqur9aujYwdCoAZU"
        "8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT/7vdgS/IYXFniPuU"
        "fblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQYDVR0OBBYEFOfg3f"
        "/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpMAsGA1UdDwQEAwIDi"
        "DATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0549hEHRQArJXs1im"
        "7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3rDywi2a9GKzOFgrW"
        "pVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA2sW5AhPiCr9dVnMn"
        "/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqWSfPRBZV8htRIf0vT"
        "lGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="
    )
    rsa_key = RSAKey(x5c=[cert], x5t="KvHXVspLmjWC6cPDIIVMHlJjN-c")
    assert rsa_key.pub_key

    with pytest.raises(DeSerializationNotPossible):
        RSAKey(x5c=[cert], x5t="abcdefgh")  # incorrect thumbprint


def test_thumbprint_7638_example():
    key = RSAKey(
        n="0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        e="AQAB",
        alg="RS256",
        kid="2011-04-29",
    )
    thumbprint = key.thumbprint("SHA-256")
    assert thumbprint == b"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_encryption_key():
    sk = SYMKey(key="df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b")
    _enc = sk.encryption_key(alg="A128KW")
    _v = as_unicode(b64e(_enc))
    assert _v == "xCo9VhtommCTGMWi-RyWBw"

    sk = SYMKey(key="df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b")
    _enc = sk.encryption_key(alg="A192KW")
    _v = as_unicode(b64e(_enc))
    assert _v == "xCo9VhtommCTGMWi-RyWB14GQqHAGC86"

    sk = SYMKey(key="df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b")
    _enc = sk.encryption_key(alg="A256KW")
    _v = as_unicode(b64e(_enc))
    assert _v == "xCo9VhtommCTGMWi-RyWB14GQqHAGC86vweU_Pi62X8"

    ek = sha256_digest(
        "YzE0MjgzNmRlODI5Yzg2MGYyZTRjNGE0NTZlMzBkZDRiNzJkNDA5MzUzNjM0ODkzM2E2MDk3ZWY"
    )[:16]
    assert as_unicode(b64e(ek)) == "yf_UUkAFZ8Pn_prxPPgu9w"

    sk = SYMKey(key="YzE0MjgzNmRlODI5Yzg2MGYyZTRjNGE0NTZlMzBkZDRiNzJkNDA5MzUzNjM0ODkzM2E2MDk3ZWY")
    _enc = sk.encryption_key(alg="A128KW")
    _v = as_unicode(b64e(_enc))
    assert _v == as_unicode(b64e(ek))


RSA1 = RSAKey(
    alg="RS256",
    e="AQAB",
    kty="RSA",
    n="wkpyitec6TgFC5G41RF6jBOZghGVyaHL79CzSjjS9VCkWjpGo2hajOsiJ1RnSoat9XDmQAqiqn18rWx4xa4ErdWVqug88pLxMVmnV9tF10uJNgIi_RSsIQz40J9aKrxOotN6Mnq454BpanAxbrbC5hLlp-PIGgmWzUDNwCSfnWBjd0yGwdYKVB6d-SGNfLvdMUhFiYIX0POUnJDNl_j3kLYQ0peYRbunyQzST5nLPOItePCuZ12G5e0Eo1meSF1Md3IkuY8paqKk-vsWrT22X7CUV3HZow06ogRcFMMzvooE7yDqS53I_onsUrqgQ2aUnoo8OaD0eLlEWdaTyeNAIw",
    use="sig",
)

RSA2 = RSAKey(
    n="pKXuY5tuT9ibmEcq4B6VRx3MafdSsajrOndAk5FjJFedlA6qSpdqDUr9wWUkNeO8h_efdLfg43CHXk3mH6Fp1t2gbHzBQ4-SzT3_X5tsdG2PPqvngem7f5NHO6Kefhq11Zk5q4-FyTL9FUQQW6ZANbrU7GifSAs82Ck20ciIvFdv7cPCphk_THMVv14aW5w0eKEXumgx4Bc7HrQFXQUHSze3dVAKg8hKHDIQOGUU0fkolEFmOC4Gb-G57RpBJryZxXqgdUdEG66xl1f37tqpYgaLViFDWDiI8S7BMVHEbGHN4-f_MD9f6gMduaxrL6a6SfyIW1So2VqtvlAyanesTw",
    kid="gtH4v3Yr2QqLreBSz0ByQQ8vkf8eFo1KIit3s-3Bbww",
    use="enc",
    e="AQAB",
    kty="RSA",
)

RSA3 = RSAKey(
    n="pKXuY5tuT9ibmEcq4B6VRx3MafdSsajrOndAk5FjJFedlA6qSpdqDUr9wWUkNeO8h_efdLfg43CHXk3mH6Fp1t2gbHzBQ4-SzT3_X5tsdG2PPqvngem7f5NHO6Kefhq11Zk5q4-FyTL9FUQQW6ZANbrU7GifSAs82Ck20ciIvFdv7cPCphk_THMVv14aW5w0eKEXumgx4Bc7HrQFXQUHSze3dVAKg8hKHDIQOGUU0fkolEFmOC4Gb-G57RpBJryZxXqgdUdEG66xl1f37tqpYgaLViFDWDiI8S7BMVHEbGHN4-f_MD9f6gMduaxrL6a6SfyIW1So2VqtvlAyanesTw",
    use="enc",
    e="AQAB",
    kty="RSA",
)


def test_equal():
    assert RSA1 == RSA1
    assert RSA1 != RSA2  # different keys altogether
    assert RSA2 != RSA3  # different kid


def test_get_asym_key_for_verify():
    assert RSA1.appropriate_for("verify")


def test_get_asym_key_for_encrypt():
    assert RSA2.appropriate_for("encrypt")


def test_get_asym_key_all():
    # When not marked for a special usage this key can be use for everything
    rsakey = RSAKey(priv_key=import_private_rsa_key_from_file(full_path("rsa.key")))
    assert rsakey.appropriate_for("sign")
    assert rsakey.appropriate_for("verify")
    assert rsakey.appropriate_for("encrypt")
    assert rsakey.appropriate_for("decrypt")

    rsakey.use = "sig"
    # Now it can only be used for signing and signature verification
    assert rsakey.appropriate_for("sign")
    assert rsakey.appropriate_for("verify")
    for usage in ["encrypt", "decrypt"]:
        assert rsakey.appropriate_for(usage) is None

    rsakey.use = "enc"
    # Now it can only be used for encrypting and decrypting
    assert rsakey.appropriate_for("encrypt")
    assert rsakey.appropriate_for("decrypt")
    for usage in ["sign", "verify"]:
        assert rsakey.appropriate_for(usage) is None


def test_get_asym_key_for_unknown_usage():
    with pytest.raises(ValueError):
        RSA1.appropriate_for("binding")


def test_get_hmac_key_for_verify():
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy", use="sig")
    assert key.appropriate_for("verify")


def test_get_hmac_key_for_encrypt():
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy", use="enc")
    assert key.appropriate_for("encrypt")


def test_get_hmac_key_for_verify_fail():
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy", use="enc")
    with pytest.raises(WrongUsage):
        key.appropriate_for("verify")


def test_get_hmac_key_for_encrypt_fail():
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy", use="sig")
    with pytest.raises(WrongUsage):
        key.appropriate_for("encrypt")


def test_get_hmac_key_for_encrypt_HS384():
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy", use="enc")
    assert key.appropriate_for("encrypt", "HS384")


def test_get_hmac_key_for_encrypt_HS512():
    key = SYMKey(key="mekmitasdigoatfo", kid="xyzzy", use="enc")
    assert key.appropriate_for("encrypt", "HS512")


def test_new_rsa_key():
    key = new_rsa_key()
    assert isinstance(key, RSAKey)
    assert key.priv_key


def test_load_pem_file_rsa():
    key = RSAKey().load(full_path("server.key"))
    assert key.has_private_key()


def test_load_pem_file_ec():
    key = ECKey().load(full_path("570-ec-sect571r1-keypair.pem"))
    assert key.has_private_key()


def test_key_from_jwk_dict_rsa():
    rsa_key = new_rsa_key()
    jwk = rsa_key.serialize(private=True)
    _key = key_from_jwk_dict(jwk)
    assert isinstance(_key, RSAKey)
    assert _key.has_private_key()
    _key2 = RSAKey(**jwk)
    assert isinstance(_key2, RSAKey)
    assert _key2.has_private_key()


def test_key_from_jwk_dict_ec():
    key = ECKey().load(full_path("570-ec-sect571r1-keypair.pem"))
    assert key.has_private_key()
    jwk = key.serialize(private=True)
    _key = key_from_jwk_dict(jwk)
    assert isinstance(_key, ECKey)
    assert _key.has_private_key()


def test_key_from_jwk_dict_sym():
    jwk = {"kty": "oct", "key": "abcdefghijklmnopq"}
    _key = key_from_jwk_dict(jwk)
    assert isinstance(_key, SYMKey)
    jwk = _key.serialize()
    assert jwk == {"kty": "oct", "k": "YWJjZGVmZ2hpamtsbW5vcHE"}


def test_jwk_wrong_alg():
    with pytest.raises(UnsupportedAlgorithm):
        _j = JWK(alg="xyz")


def test_jwk_conversion():
    _j = JWK(use=b"sig", kid=b"1", alg=b"RS512")
    assert _j.use == "sig"
    args = _j.common()
    assert set(args.keys()) == {"use", "kid", "alg"}


def test_str():
    _j = RSAKey(alg="RS512", use="sig", n=N, e=E)
    s = "{}".format(_j)
    assert s.startswith("{") and s.endswith("}")
    sp = s.replace("'", '"')
    _d = json.loads(sp)
    assert set(_d.keys()) == {"alg", "use", "n", "e", "kty"}


def test_verify():
    _j = RSAKey(alg=b"RS512", use=b"sig", n=as_bytes(N), e=E)
    assert _j.verify()


def test_verify_wrong_kid():
    _j = RSAKey(alg=b"RS512", use=b"sig", n=as_bytes(N), e=E, kid=1)
    with pytest.raises(ValueError):
        _j.verify()


def test_cmp():
    _j1 = RSAKey(alg="RS256", use="sig", n=N, e=E)
    _j2 = RSAKey(alg="RS256", use="sig", n=N, e=E)
    assert _j1 == _j2


def test_cmp_jwk():
    _j1 = JWK(use="sig", kid="1", alg="RS512")
    _j2 = JWK(use="sig", kid="1", alg="RS512")

    assert _j1 == _j2


def test_appropriate():
    _j1 = JWK(use="sig", kid="1", alg="RS512")

    assert _j1.appropriate_for("sign")
    assert _j1.appropriate_for("encrypt") is False


def test_thumbprint_ec():
    jwk = key_from_jwk_dict(
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "MJ05vpfkWoIce1MwUpZYAyotenxp4yYVHJuc6lN_J0o",
            "y": "Kfzs5wbqnEWUlFElN8ErWEL5YL2WQ1yowxzHejlzlZ0",
        }
    )
    thumbprint = "RCWR9g8NPt9iZeq-lh-qXbiFxXcU0_o1YLitDj3kpg0"
    assert (jwk.thumbprint("SHA-256").decode()) == thumbprint


def test_thumbprint_rsa():
    jwk = key_from_jwk_dict(
        {
            "kty": "RSA",
            "e": "AQAB",
            "n": "3xIyjRLL1LYi2FULhN6koVwtsaixgXa5TBOMcq2EMsk_Fq"
            "-tSXmxA8ATYcUnuSGX3PGJ5pHwIF42eesIzQV5ypYklF0sLAkmkXow_TMDX0qoc4rdfc2prq"
            "-mzPWwGcYoRsjDKiSUFOUSKB41zQ6sMY2k4BWZVo1bEL0CVpVct1DDhqSME6uUKex9T2AbwWNvwFacrwJaWyKixBhiPSwVBn7dUWDnJiM39_4Lnw6JnriXcli-aJlPuXm5F_qspXL4Pfn9nR5Z9j9Qf7NFif7nVRyg8cx7OYTbbsoIbMYYG-boVPLL7ebEBZVIUysqH_WkNJlkl5m7gAs5DB_KfMx18Q",
        }
    )
    thumbprint = "Q1wZMrouq_iCnG7mr2y03Zxf7iE9mie-y_Mfh9-Cgk0"
    assert (jwk.thumbprint("SHA-256").decode()) == thumbprint


def test_mint_new_sym_key():
    key = new_sym_key(bytes=24, use="sig", kid="one")
    assert key
    assert key.use == "sig"
    assert key.kid == "one"
    assert len(key.key) == 24


def test_dump_load():
    _ckey = import_rsa_key_from_cert_file(CERT)
    _key = jwk_wrap(_ckey, "sig", "kid1")
    _filename = full_path("tmp_jwk.json")

    dump_jwk(_filename, _key)
    key = import_jwk(_filename)
    assert isinstance(key, RSAKey)
    assert key.kid == "kid1"
    assert key.use == "sig"


def test_key_ops():
    sk = SYMKey(
        key="df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b",
        alg="HS256",
        key_ops=["sign", "verify"],
    )

    _jwk = sk.serialize(private=True)
    assert set(_jwk.keys()) == {"kty", "alg", "key_ops", "k"}


def test_key_ops_and_use():
    with pytest.raises(ValueError):
        SYMKey(
            key="df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b",
            alg="HS256",
            key_ops=["sign", "verify"],
            use="sig",
        )


def test_pem_to_x5c():
    with open(full_path("cert.pem")) as fp:
        cert_chain = fp.read()

    x5c = pems_to_x5c([cert_chain])
    assert len(x5c) == 1
    assert (
        x5c[0]
        == "MIIB2jCCAUOgAwIBAgIBATANBgkqhkiG9w0BAQUFADA0MRgwFgYDVQQDEw9UaGUgY29kZSB0ZXN0ZXIxGDAWBgNVBAoTD1VtZWEgVW5pdmVyc2l0eTAeFw0xMjEwMDQwMDIzMDNaFw0xMzEwMDQwMDIzMDNaMDIxCzAJBgNVBAYTAlNFMSMwIQYDVQQDExpPcGVuSUQgQ29ubmVjdCBUZXN0IFNlcnZlcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwf+wiusGhA+gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB/87ds3dy3Rfym/GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8CAwEAATANBgkqhkiG9w0BAQUFAAOBgQCsTntG4dfW5kO/Qle6uBhIhZU+3IreIPmbwzpXoCbcgjRa01z6WiBLwDC1RLAL7ucaF/EVlUq4e0cNXKt4ESGNc1xHISOMLetwvS1SN5tKWA9HNua/SaqRtiShxLUjPjmrtpUgotLNDRvUYnTdTT1vhZar7TSPr1yObirjvz/qLw=="
    )


def test_pem_hash():
    _hash = pem_hash(full_path("cert.pem"))
    assert _hash


def test_certificate_fingerprint():
    with open(full_path("cert.der"), "rb") as cert_file:
        der = cert_file.read()

    res = certificate_fingerprint(der)
    assert (
        res == "01:DF:F1:D4:5F:21:7B:2E:3A:A2:D8:CA:13:4C:41:66:03:A1:EF:3E:7B:5E:8B:69:04:5E"
        ":80:8B:55:49:F1:48"
    )

    res = certificate_fingerprint(der, "sha1")
    assert res == "CA:CF:21:9E:72:00:CD:1C:CA:FD:4F:6D:84:6B:9E:E8:74:80:47:64"

    res = certificate_fingerprint(der, "md5")
    assert res == "1B:2B:3B:F8:49:EE:2A:2C:C1:C7:6C:88:86:AB:C6:EE"

    with pytest.raises(UnsupportedAlgorithm):
        certificate_fingerprint(der, "foo")


def test_x5t_calculation():
    with open(full_path("cert.der"), "rb") as cert_file:
        der = cert_file.read()

    x5t = calculate_x5t(der)
    assert x5t == b"Q0FDRjIxOUU3MjAwQ0QxQ0NBRkQ0RjZEODQ2QjlFRTg3NDgwNDc2NA=="

    x5t_s256 = calculate_x5t(der, "sha256")
    assert (
        x5t_s256
        == b"MDFERkYxRDQ1RjIxN0IyRTNBQTJEOENBMTM0QzQxNjYwM0ExRUYzRTdCNUU4QjY5MDQ1RTgwOEI1NTQ5RjE0OA=="
    )


@pytest.mark.parametrize(
    "filename,key_type",
    [
        ("ec-public.pem", ec.EllipticCurvePublicKey),
        ("rsa-public.pem", rsa.RSAPublicKey),
    ],
)
def test_import_public_key_from_pem_file(filename, key_type):
    _file = full_path(filename)
    pub_key = import_public_key_from_pem_file(_file)
    assert isinstance(pub_key, key_type)
