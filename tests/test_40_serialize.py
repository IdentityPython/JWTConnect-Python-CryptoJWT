import os

from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey, import_rsa_key_from_cert_file
from cryptojwt.key_bundle import keybundle_from_local_file, rsa_init
from cryptojwt.key_issuer import KeyIssuer
from cryptojwt.serialize import item


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


BASEDIR = os.path.abspath(os.path.dirname(__file__))
BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_keys"))
CERT = full_path("cert.pem")


def test_key_issuer():
    kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwks", ["sig"])
    assert len(kb) == 1
    issuer = KeyIssuer()
    issuer.add(kb)

    _item = item.KeyIssuer().serialize(issuer)
    _iss = item.KeyIssuer().deserialize(_item)

    assert len(_iss) == 1  # 1 key
    assert len(_iss.get("sig", "rsa")) == 1  # 1 RSA key
    _kb = _iss[0]
    assert kb.difference(_kb) == []  # no difference
