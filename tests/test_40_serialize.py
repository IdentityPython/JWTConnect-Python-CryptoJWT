import os

from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_rsa_key_from_cert_file
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_bundle import rsa_init
from cryptojwt.key_issuer import KeyIssuer
from cryptojwt.serialize import item
from cryptojwt.serialize.item import JWK
from cryptojwt.serialize.item import KeyBundle


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


BASEDIR = os.path.abspath(os.path.dirname(__file__))
BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         "test_keys"))
CERT = full_path("cert.pem")


def test_jwks():
    _key = RSAKey()
    _key.load_key(import_rsa_key_from_cert_file(CERT))

    _item = JWK().serialize(_key)
    _nkey = JWK().deserialize(_item)
    assert _key == _nkey


def test_key_bundle():
    kb = rsa_init({'use': ['enc', 'sig'], 'size': 1024, 'name': 'rsa', 'path': 'keys'})
    _sym = SYMKey(**{"kty": "oct", "key": "highestsupersecret", "use": "enc"})
    kb.append(_sym)
    _item = KeyBundle().serialize(kb)
    _nkb = KeyBundle().deserialize(_item)
    assert len(kb) == 3
    assert len(kb.get('rsa')) == 2
    assert len(kb.get('oct')) == 1


def test_key_issuer():
    kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwks", ["sig"])
    assert len(kb) == 1
    issuer = KeyIssuer()
    issuer.add(kb)

    _item = item.KeyIssuer().serialize(issuer)
    _iss = item.KeyIssuer().deserialize(_item)

    assert len(_iss) == 1  # 1 key
    assert len(_iss.get('sig', 'rsa')) == 1  # 1 RSA key
    _kb = _iss[0]
    assert kb.difference(_kb) == []  # no difference
