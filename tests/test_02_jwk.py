#!/usr/bin/env python3

from __future__ import print_function
import base64
import json
import struct
import pytest

from collections import Counter

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key

import os.path

from cryptojwt.exception import DeSerializationNotPossible, WrongUsage

from cryptojwt.utils import as_unicode
from cryptojwt.utils import b64e
from cryptojwt.utils import long2intarr
from cryptojwt.utils import base64url_to_long
from cryptojwt.utils import deser
from cryptojwt.utils import base64_to_long
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.jwk.rsa import import_public_rsa_key_from_file
from cryptojwt.jwk.rsa import import_rsa_key_from_cert_file
from cryptojwt.jwk.rsa import load_x509_cert
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwk.jwk import jwk_wrap
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.jwks import JWKS
from cryptojwt.jwk.jwks import load_jwks
from cryptojwt.jwk.ec import NIST2SEC
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.hmac import sha256_digest
from cryptojwt.jwk.hmac import SYMKey

__author__ = 'Roland Hedberg'
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


CERT = full_path("cert.pem")
KEY = full_path("server.key")

N = 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'
E = 'AQAB'

JWK = {"keys": [
    {'kty': 'RSA', 'use': 'foo', 'e': E, 'kid': "abc",
     'n': N}
]}


def _eq(l1, l2):
    return Counter(l1) == Counter(l2)


def test_urlsafe_base64decode():
    l = base64_to_long(N)
    # convert it to base64
    bys = long2intarr(l)
    data = struct.pack('%sB' % len(bys), *bys)
    if not len(data):
        data = '\x00'
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
    assert jwk["e"] == JWK["keys"][0]["e"]
    assert jwk["n"] == JWK["keys"][0]["n"]

    assert not _key.has_private_key()


def test_loads_0():
    keys = JWKS()
    keys.load_dict(JWK)
    assert len(keys) == 1
    key = keys["rsa"][0]
    assert key.kid == 'abc'
    assert key.kty == 'RSA'

    _ckey = import_rsa_key_from_cert_file(CERT)
    pn = _ckey.public_numbers()
    assert deser(key.n) == pn.n
    assert deser(key.e) == pn.e


def test_loads_1():
    jwk = {
        "keys": [
            {
                'kty': 'RSA',
                'use': 'foo',
                'e': 'AQAB',
                "n": 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8',
                'kid': "1"
            }, {
                'kty': 'RSA',
                'use': 'bar',
                'e': 'AQAB',
                "n": 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8',
                'kid': "2"
            }
        ]
    }

    keys = JWKS()
    keys.load_dict(jwk)

    assert len(keys) == 2
    assert _eq(keys.kids(), ['1', '2'])


def test_dumps():
    _ckey = import_rsa_key_from_cert_file(CERT)
    jwk = jwk_wrap(_ckey).serialize()
    assert _eq(list(jwk.keys()), ["kty", "e", "n"])


def test_dump_jwk():
    keylist0 = JWKS()
    keylist0.wrap_add(import_rsa_key_from_cert_file(CERT))
    jwk = keylist0.dump_jwks()

    _wk = json.loads(jwk)
    assert list(_wk.keys()) == ["keys"]
    assert len(_wk["keys"]) == 1
    assert _eq(list(_wk["keys"][0].keys()), ["kty", "e", "n"])


def test_load_jwk():
    keylist0 = JWKS()
    keylist0.wrap_add(import_rsa_key_from_cert_file(CERT))
    jwk = keylist0.dump_jwks()

    keylist1 = JWKS()
    keylist1.load_jwks(jwk)

    assert len(keylist1) == 1
    key = keylist1["rsa"][0]
    assert key.kty == 'RSA'
    assert isinstance(key.public_key(), rsa.RSAPublicKey)


def test_import_rsa_key():
    _ckey = import_private_rsa_key_from_file(full_path(KEY))
    assert isinstance(_ckey, rsa.RSAPrivateKey)
    djwk = jwk_wrap(_ckey).to_dict()

    assert _eq(djwk.keys(), ["kty", "e", "n", "p", "q", "d"])
    assert djwk[
               "n"] == '5zbNbHIYIkGGJ3RGdRKkYmF4gOorv5eDuUKTVtuu3VvxrpOWvwnFV-NY0LgqkQSMMyVzodJE3SUuwQTUHPXXY5784vnkFqzPRx6bHgPxKz7XfwQjEBTafQTMmOeYI8wFIOIHY5i0RWR-gxDbh_D5TXuUqScOOqR47vSpIbUH-nc'
    assert djwk['e'] == 'AQAB'


def test_serialize_rsa_pub_key():
    rsakey = RSAKey(pub_key=import_public_rsa_key_from_file(
        full_path("rsa.pub")))
    assert rsakey.d == ''

    d_rsakey = rsakey.serialize(private=True)
    restored_key = RSAKey(**d_rsakey)

    assert restored_key == rsakey


def test_serialize_rsa_priv_key():
    rsakey = RSAKey(priv_key=import_private_rsa_key_from_file(
        full_path("rsa.key")))
    assert rsakey.d

    d_rsakey = rsakey.serialize(private=True)
    restored_key = RSAKey(**d_rsakey)

    assert restored_key == rsakey
    assert rsakey.has_private_key()
    assert restored_key.has_private_key()


ECKEY = {
    "crv": "P-521",
    "x": u'AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk',
    "y": u'ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2',
    "d": u'AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C'
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


def test_create_eckey():
    ec_key = generate_private_key(NIST2SEC['P-256'], default_backend())
    ec = ECKey(priv_key=ec_key)
    exp_key = ec.serialize()
    assert _eq(list(exp_key.keys()), ["y", "x", "crv", "kty"])


def test_cmp_neq_ec():
    ec_key = generate_private_key(NIST2SEC['P-256'], default_backend())
    _key1 = ECKey(priv_key=ec_key)
    _key2 = ECKey(**ECKEY)

    assert _key1 != _key2


JWKS_DICT = {"keys": [
    {
        "n": u"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": u"AQAB",
        "kty": "RSA",
        "kid": "5-VBFv40P8D4I-7SFz7hMugTbPs",
        "use": "enc"
    },
    {
        "k": u"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "enc"
    },
    {
        "kty": "EC",
        "kid": "7snis",
        "use": "sig",
        "x": u'q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po',
        "y": u'GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E',
        "crv": "P-256"
    }
]}


def test_keys():
    keyl = JWKS()
    keyl.load_dict(JWKS_DICT)

    assert len(keyl) == 3

    assert _eq(keyl.key_types(), ['RSA', 'oct', 'EC'])
    assert len(keyl['rsa']) == 1
    assert len(keyl['oct']) == 1
    assert len(keyl['ec']) == 1


def test_get_key():
    ec_key = generate_private_key(NIST2SEC['P-256'], default_backend())
    asym_private_key = ECKey(priv_key=ec_key)
    asym_public_key = ECKey(pub_key=asym_private_key.pub_key)
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy')

    assert asym_private_key.private_key()
    assert asym_private_key.public_key()

    assert asym_public_key.private_key() is None
    assert asym_private_key.public_key()

    assert key.key


def test_private_key_from_jwk():
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

    assert _eq(list(_d.keys()),
               ['n', 'alg', 'dq', 'e', 'q', 'p', 'dp', 'd', 'ext', 'key_ops',
                'kty', 'qi'])
    assert _eq(list(_d.keys()), kspec.keys())


def test_rsa_pubkey_from_x509_cert_chain():
    cert = "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDAOBgNVBAgTB0JhdmF" \
           "yaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZXJ0aWZpY2F0aW9uIE" \
           "F1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNMTUwNDE1MTQ1NjM4W" \
           "hcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21iSDE7MDkGA1UEAxMy" \
           "QmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb" \
           "3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99bdzUUIhDZG34PQqcH" \
           "89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3Xje8fu55Csh0JXNfo" \
           "y29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisIVqur9aujYwdCoAZU" \
           "8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT/7vdgS/IYXFniPuU" \
           "fblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQYDVR0OBBYEFOfg3f" \
           "/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpMAsGA1UdDwQEAwIDi" \
           "DATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0549hEHRQArJXs1im" \
           "7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3rDywi2a9GKzOFgrW" \
           "pVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA2sW5AhPiCr9dVnMn" \
           "/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqWSfPRBZV8htRIf0vT" \
           "lGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="
    rsa_key = RSAKey(x5c=[cert])
    assert rsa_key.pub_key


def test_rsa_pubkey_verify_x509_thumbprint():
    cert = "MIID0jCCArqgAwIBAgIBSTANBgkqhkiG9w0BAQQFADCBiDELMAkGA1UEBhMCREUxEDAOBgNVBAgTB0JhdmF" \
           "yaWExEzARBgNVBAoTCkJpb0lEIEdtYkgxLzAtBgNVBAMTJkJpb0lEIENsaWVudCBDZXJ0aWZpY2F0aW9uIE" \
           "F1dGhvcml0eSAyMSEwHwYJKoZIhvcNAQkBFhJzZWN1cml0eUBiaW9pZC5jb20wHhcNMTUwNDE1MTQ1NjM4W" \
           "hcNMTYwNDE0MTQ1NjM4WjBfMQswCQYDVQQGEwJERTETMBEGA1UEChMKQmlvSUQgR21iSDE7MDkGA1UEAxMy" \
           "QmlvSUQgT3BlbklEIENvbm5lY3QgSWRlbnRpdHkgUHJvdmlkZXIgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb" \
           "3DQEBAQUAA4IBDwAwggEKAoIBAQC9aFETmU6kDfMBPKM2OfI5eedO3XP12Ci0hDC99bdzUUIhDZG34PQqcH" \
           "89gVWGthJv5w3kqpdSrxfPCFMsBdnyk1VCuXmLgXS8s4oBtt1c9iM0J8X6Z+5subS3Xje8fu55Csh0JXNfo" \
           "y29rCY/O6y0fNignegg0KS4PHv5T+agFmaG4rxCQV9/kd8tlo/HTyVPsuSPDgsXxisIVqur9aujYwdCoAZU" \
           "8OU+5ccMLNIhpWJn+xNjgDRr4L9nxAYKc9vy+f7EoH3LT24B71zazZsQ78vpocz98UT/7vdgS/IYXFniPuU" \
           "fblja7cq31bUoySDx6FYrtfCSUxNhaZSX8mppAgMBAAGjbzBtMAkGA1UdEwQCMAAwHQYDVR0OBBYEFOfg3f" \
           "/ewBLK5SkcBEXusD62OlzaMB8GA1UdIwQYMBaAFCQmdD+nVcVLaKt3vu73XyNgpPEpMAsGA1UdDwQEAwIDi" \
           "DATBgNVHSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQQFAAOCAQEAKQjhcL/iGhy0549hEHRQArJXs1im" \
           "7W244yE+TSChdMWKe2eWvEhc9wX1aVV2mNJM1ZNeYSgfoK6jjuXaHiSaIJEUcW1wVM3rDywi2a9GKzOFgrW" \
           "pVbpXQ05LSE7qEEWRmSpIMyKTitUalNpNA6cOML5hiuUTfZbw7OvPwbnbSYYL674gEA2sW5AhPiCr9dVnMn" \
           "/UK2II40802zdXUOvIxWeXpcsCxxZMjp/Ir2jIZWOEjlAXQVGr2oBfL/be/o5WXpaqWSfPRBZV8htRIf0vT" \
           "lGx7xR8FPWDYmcj4o/tKoNC1AchjOnCwwE/mj4hgtoAsHNmYXF0oZXk7cozqYDqKQ=="
    rsa_key = RSAKey(x5c=[cert], x5t="KvHXVspLmjWC6cPDIIVMHlJjN-c")
    assert rsa_key.pub_key

    with pytest.raises(DeSerializationNotPossible):
        RSAKey(x5c=[cert], x5t="abcdefgh")  # incorrect thumbprint


EXPECTED = [
    b'iA7PvG_DfJIeeqQcuXFmvUGjqBkda8In_uMpZrcodVA',
    b'kLsuyGef1kfw5-t-N9CJLIHx_dpZ79-KemwqjwdrvTI',
    b'8w34j9PLyCVC7VOZZb1tFVf0MOa2KZoy87lICMeD5w8',
    b'nKzalL5pJOtVAdCtBAU8giNRNimE-XbylWZ4vq6ZlF8'
]


def test_thumbprint():
    keyl = JWKS()
    keyl.load_dict(JWKS_DICT)
    for key in keyl:
        txt = key.thumbprint('SHA-256')
        assert txt in EXPECTED


def test_thumbprint_7638_example():
    key = RSAKey(
        n='0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
        e='AQAB', alg='RS256', kid='2011-04-29')
    thumbprint = key.thumbprint('SHA-256')
    assert thumbprint == b'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'


def test_load_jwks():
    keysl = load_jwks(json.dumps(JWKS_DICT))
    assert len(keysl) == 3


def test_encryption_key():
    sk = SYMKey(
        key='df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b')
    _enc = sk.encryption_key(alg='A128KW')
    _v = as_unicode(b64e(_enc))
    assert _v == 'xCo9VhtommCTGMWi-RyWBw'

    sk = SYMKey(
        key='df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b')
    _enc = sk.encryption_key(alg='A192KW')
    _v = as_unicode(b64e(_enc))
    assert _v == 'xCo9VhtommCTGMWi-RyWB14GQqHAGC86'

    sk = SYMKey(
        key='df34db91c16613deba460752522d28f6ebc8a73d0d9185836270c26b')
    _enc = sk.encryption_key(alg='A256KW')
    _v = as_unicode(b64e(_enc))
    assert _v == 'xCo9VhtommCTGMWi-RyWB14GQqHAGC86vweU_Pi62X8'

    ek = sha256_digest(
    'YzE0MjgzNmRlODI5Yzg2MGYyZTRjNGE0NTZlMzBkZDRiNzJkNDA5MzUzNjM0ODkzM2E2MDk3ZWY')[:16]
    assert as_unicode(b64e(ek)) == 'yf_UUkAFZ8Pn_prxPPgu9w'

    sk = SYMKey(
        key='YzE0MjgzNmRlODI5Yzg2MGYyZTRjNGE0NTZlMzBkZDRiNzJkNDA5MzUzNjM0ODkzM2E2MDk3ZWY')
    _enc = sk.encryption_key(alg='A128KW')
    _v = as_unicode(b64e(_enc))
    assert _v == as_unicode(b64e(ek))


RSA1 = RSAKey(
    alg="RS256",
    e="AQAB",
    kty="RSA",
    n="wkpyitec6TgFC5G41RF6jBOZghGVyaHL79CzSjjS9VCkWjpGo2hajOsiJ1RnSoat9XDmQAqiqn18rWx4xa4ErdWVqug88pLxMVmnV9tF10uJNgIi_RSsIQz40J9aKrxOotN6Mnq454BpanAxbrbC5hLlp-PIGgmWzUDNwCSfnWBjd0yGwdYKVB6d-SGNfLvdMUhFiYIX0POUnJDNl_j3kLYQ0peYRbunyQzST5nLPOItePCuZ12G5e0Eo1meSF1Md3IkuY8paqKk-vsWrT22X7CUV3HZow06ogRcFMMzvooE7yDqS53I_onsUrqgQ2aUnoo8OaD0eLlEWdaTyeNAIw",
    use="sig"
)

RSA2 = RSAKey(
    n="pKXuY5tuT9ibmEcq4B6VRx3MafdSsajrOndAk5FjJFedlA6qSpdqDUr9wWUkNeO8h_efdLfg43CHXk3mH6Fp1t2gbHzBQ4-SzT3_X5tsdG2PPqvngem7f5NHO6Kefhq11Zk5q4-FyTL9FUQQW6ZANbrU7GifSAs82Ck20ciIvFdv7cPCphk_THMVv14aW5w0eKEXumgx4Bc7HrQFXQUHSze3dVAKg8hKHDIQOGUU0fkolEFmOC4Gb-G57RpBJryZxXqgdUdEG66xl1f37tqpYgaLViFDWDiI8S7BMVHEbGHN4-f_MD9f6gMduaxrL6a6SfyIW1So2VqtvlAyanesTw",
    kid="gtH4v3Yr2QqLreBSz0ByQQ8vkf8eFo1KIit3s-3Bbww",
    use="enc",
    e="AQAB",
    kty="RSA"
)

RSA3 = RSAKey(
    n="pKXuY5tuT9ibmEcq4B6VRx3MafdSsajrOndAk5FjJFedlA6qSpdqDUr9wWUkNeO8h_efdLfg43CHXk3mH6Fp1t2gbHzBQ4-SzT3_X5tsdG2PPqvngem7f5NHO6Kefhq11Zk5q4-FyTL9FUQQW6ZANbrU7GifSAs82Ck20ciIvFdv7cPCphk_THMVv14aW5w0eKEXumgx4Bc7HrQFXQUHSze3dVAKg8hKHDIQOGUU0fkolEFmOC4Gb-G57RpBJryZxXqgdUdEG66xl1f37tqpYgaLViFDWDiI8S7BMVHEbGHN4-f_MD9f6gMduaxrL6a6SfyIW1So2VqtvlAyanesTw",
    use="enc",
    e="AQAB",
    kty="RSA"
)


def test_equal():
    assert RSA1 == RSA1
    assert RSA1 != RSA2
    assert RSA2 == RSA3


def test_get_asym_key_for_verify():
    assert RSA1.appropriate_for('verify')


def test_get_asym_key_for_encrypt():
    assert RSA2.appropriate_for('encrypt')


def test_get_asym_key_all():
    # When not marked for a special usage this key can be use for everything
    rsakey = RSAKey(
        priv_key=import_private_rsa_key_from_file(full_path("rsa.key")))
    assert rsakey.appropriate_for('sign')
    assert rsakey.appropriate_for('verify')
    assert rsakey.appropriate_for('encrypt')
    assert rsakey.appropriate_for('decrypt')

    rsakey.use = 'sig'
    # Now it can only be used for signing and signature verification
    assert rsakey.appropriate_for('sign')
    assert rsakey.appropriate_for('verify')
    for usage in ['encrypt','decrypt']:
        assert rsakey.appropriate_for(usage) is None

    rsakey.use = 'enc'
    # Now it can only be used for encrypting and decrypting
    assert rsakey.appropriate_for('encrypt')
    assert rsakey.appropriate_for('decrypt')
    for usage in ['sign','verify']:
        assert rsakey.appropriate_for(usage) is None


def test_get_asym_key_for_unknown_usage():
    with pytest.raises(ValueError):
        RSA1.appropriate_for('binding')


def test_get_hmac_key_for_verify():
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy', use='sig')
    assert key.appropriate_for('verify')


def test_get_hmac_key_for_encrypt():
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy', use='enc')
    assert key.appropriate_for('encrypt')


def test_get_hmac_key_for_verify_fail():
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy', use='enc')
    with pytest.raises(WrongUsage):
        key.appropriate_for('verify')


def test_get_hmac_key_for_encrypt_fail():
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy', use='sig')
    with pytest.raises(WrongUsage):
        key.appropriate_for('encrypt')


def test_get_hmac_key_for_encrypt_HS384():
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy', use='enc')
    assert key.appropriate_for('encrypt', 'HS384')


def test_get_hmac_key_for_encrypt_HS512():
    key = SYMKey(key='mekmitasdigoatfo', kid='xyzzy', use='enc')
    assert key.appropriate_for('encrypt', 'HS512')


@pytest.mark.network
def test_jwks_url():
    keys = JWKS(httpc=requests.request)
    keys.load_from_url('https://login.salesforce.com/id/keys')
    assert len(keys)


def test_load_x509_cert(httpserver):
    _cert = open(CERT).read()
    httpserver.serve_content(_cert)
    key_spec = load_x509_cert(httpserver.url, requests.request, {})
    assert set(key_spec.keys()) == {'rsa'}


def test_new_rsa_key():
    key = new_rsa_key()
    assert isinstance(key, RSAKey)
    assert key.priv_key


def test_load_pem_file_rsa():
    key = RSAKey().load(full_path('server.key'))
    assert key.has_private_key()


def test_load_pem_file_ec():
    key = ECKey().load(full_path('570-ec-sect571r1-keypair.pem'))
    assert key.has_private_key()


def test_key_from_jwk_dict():
    rsa_key = new_rsa_key()
    jwk = rsa_key.serialize(private=True)
    _key = key_from_jwk_dict(jwk)
    assert isinstance(_key, RSAKey)
    assert _key.has_private_key()
