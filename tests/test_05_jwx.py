import json
import os

import pytest

from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwx import JWx

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


JSON_RSA_PUB_KEY = r"""
  {
    "kty":"RSA",
    "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    "e":"AQAB",
    "alg":"RS256"
  }"""


def test_jwx_set_jwk():
    jwx = JWx(jwk=JSON_RSA_PUB_KEY)
    keys = jwx._get_keys()
    assert len(keys)
    assert isinstance(keys[0], RSAKey)


def test_jwx_set_json_jwk():
    jwx = JWx(jwk=json.loads(JSON_RSA_PUB_KEY))
    keys = jwx._get_keys()
    assert len(keys)
    assert isinstance(keys[0], RSAKey)


def test_jwx_set_jwk_error():
    with pytest.raises(ValueError):
        JWx(jwk=[RSAKey()])


@pytest.mark.network
def test_jws_set_jku():
    jwx = JWx(jku='https://login.salesforce.com/id/keys')
    keys = jwx._get_keys()
    # I know there will be keys, how many and what type may change
    assert len(keys)


def test_jwx_set_x5c():
    jwx = JWx(x5c=open(full_path('cert.pem')).read())
    keys = jwx._get_keys()
    assert len(keys)
    assert isinstance(keys[0], RSAKey)


def test_jwx_get_set():
    jwx = JWx()
    if 'alg' not in jwx:
        jwx['alg'] = 'RS256'

    assert jwx['alg'] == 'RS256'
    assert jwx.alg == 'RS256'
    assert list(jwx.keys()) == ['alg']


def test_jwx_get_non_existent_attribute():
    jwx = JWx()
    with pytest.raises(AttributeError):
        _ = jwx.alg


def test_get_headers():
    jwx = JWx(jwk=JSON_RSA_PUB_KEY, alg='RS256')
    _headers = jwx.headers()
    assert set(_headers.keys()) == {'jwk', 'alg'}

    _headers = jwx.headers(kid='123')
    assert set(_headers.keys()) == {'jwk', 'alg', 'kid'}


@pytest.mark.network
def test_headers_jku():
    jwx = JWx(jku='https://login.salesforce.com/id/keys')
    _headers = jwx.headers()
    assert set(_headers.keys()) == {'jku'}


def test_decode():
    jwx = JWx(cty='JWT')
    _msg = jwx._decode('eyJmb28iOiJiYXIifQ')
    assert _msg == {'foo': 'bar'}


def test_extra_headers():
    jwx = JWx()
    headers = jwx.headers(jwk=JSON_RSA_PUB_KEY, alg="RS256")
    assert set(headers.keys()) == {'jwk', 'alg'}
