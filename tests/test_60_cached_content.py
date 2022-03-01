import functools
import json
import os

import pytest

from cryptojwt.cached_content import CachedContent
from cryptojwt.cached_content import CachedContentFile
from cryptojwt.cached_content import CachedContentHTTP
from cryptojwt.exception import UpdateFailed
from cryptojwt.jwk import JWK
from cryptojwt.jwk.deserializer import der_private_deserializer
from cryptojwt.jwk.deserializer import jwks_deserializer
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.rsa import RSAKey

BASEDIR = os.path.abspath(os.path.dirname(__file__))

JWKS_FILE = "test_keys/jwk.json"

RSA_PEM_FILE = "test_keys/rsa-2048-private.pem"
EC_PEM_FILE = "test_keys/ec-p256-private.pem"

JWKS_URL = "https://raw.githubusercontent.com/IdentityPython/JWTConnect-Python-CryptoJWT/main/tests/test_keys/jwk.json"
BAD_URL = "https://httpstat.us/404"


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


def test_local_text():
    deserializer = lambda x: x.decode()
    cc = CachedContent.from_source(source=full_path(JWKS_FILE), deserializer=deserializer)
    assert isinstance(cc, CachedContentFile)
    assert cc.last_update is None
    content = cc.get()
    assert isinstance(content, str)
    assert cc.last_update is not None
    first_update = cc.last_update
    for _ in range(0, 10):
        content = cc.get(update=True)
        assert isinstance(content, str)
        assert cc.last_update == first_update
    cc.get(force=True)
    assert cc.last_update != first_update


def test_local_json():
    deserializer = json.loads
    cc = CachedContent.from_source(source=full_path(JWKS_FILE), deserializer=deserializer)
    assert isinstance(cc, CachedContentFile)
    content = cc.get()
    assert isinstance(content, dict)


def test_remote_text():
    deserializer = lambda x: x.decode()
    cc = CachedContent.from_source(source=JWKS_URL, deserializer=deserializer)
    assert isinstance(cc, CachedContentHTTP)
    assert cc.last_update is None
    content = cc.get()
    assert isinstance(content, str)
    assert cc.last_update is not None
    first_update = cc.last_update
    for _ in range(0, 10):
        content = cc.get(update=True)
        assert isinstance(content, str)
        assert cc.last_update == first_update
    cc.get(force=True)
    assert cc.last_update != first_update


def test_remote_json():
    deserializer = json.loads
    cc = CachedContent.from_source(source=JWKS_URL, deserializer=deserializer)
    assert isinstance(cc, CachedContentHTTP)
    content = cc.get()
    assert isinstance(content, dict)


def test_local_jwks():
    cc = CachedContent.from_source(source=full_path(JWKS_FILE), deserializer=jwks_deserializer)
    assert isinstance(cc, CachedContentFile)
    keys = cc.get()
    assert isinstance(keys, list)
    for key in keys:
        assert isinstance(key, JWK)


def test_local_pem_rsa_private():
    deserializer = functools.partial(der_private_deserializer, keytype="rsa")
    cc = CachedContent.from_source(source=full_path(RSA_PEM_FILE), deserializer=deserializer)
    assert isinstance(cc, CachedContentFile)
    keys = cc.get()
    assert isinstance(keys, list)
    for key in keys:
        assert isinstance(key, RSAKey)


def test_local_pem_ec():
    deserializer = functools.partial(der_private_deserializer, keytype="ec")
    cc = CachedContent.from_source(source=full_path(EC_PEM_FILE), deserializer=deserializer)
    assert isinstance(cc, CachedContentFile)
    keys = cc.get()
    assert isinstance(keys, list)
    for key in keys:
        assert isinstance(key, ECKey)


def test_remote_jwks():
    cc = CachedContent.from_source(source=JWKS_URL, deserializer=jwks_deserializer)
    assert isinstance(cc, CachedContentHTTP)
    keys = cc.get()
    assert isinstance(keys, list)
    for key in keys:
        assert isinstance(key, JWK)


def test_remote_bad():
    cc = CachedContent.from_source(source=BAD_URL, ignore_errors_period=10)
    assert isinstance(cc, CachedContentHTTP)
    assert cc.last_update is None
    with pytest.raises(UpdateFailed):
        content = cc.get(fatal=True)
    content = cc.get()
    assert content is None
    content = cc.get(fatal=True)
    assert content is None
