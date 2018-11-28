import os

from cryptojwt.jwt import JWT, pick_key
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar, init_key_jar

__author__ = 'Roland Hedberg'

ALICE = 'https://example.org/alice'
BOB = 'https://example.com/bob'
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


# k1 = import_private_rsa_key_from_file(full_path('rsa.key'))
# k2 = import_private_rsa_key_from_file(full_path('size2048.key'))

kb1 = KeyBundle(source='file://{}'.format(full_path('rsa.key')),
                fileformat='der', keyusage='sig',kid='1')
kb2 = KeyBundle(source='file://{}'.format(full_path('size2048.key')),
                fileformat='der', keyusage='enc', kid='2')

ALICE_KEY_JAR = KeyJar()
ALICE_KEY_JAR.add_kb(ALICE, kb1)
ALICE_KEY_JAR.add_kb(ALICE, kb2)

kb3 = KeyBundle(source='file://{}'.format(full_path('server.key')),
                fileformat='der', keyusage='enc', kid='3')

BOB_KEY_JAR = KeyJar()
BOB_KEY_JAR.add_kb(BOB, kb3)

# Load the opponents keys
_jwks = ALICE_KEY_JAR.export_jwks_as_json(issuer=ALICE)
BOB_KEY_JAR.import_jwks_as_json(_jwks, ALICE)

_jwks = BOB_KEY_JAR.export_jwks_as_json(issuer=BOB)
ALICE_KEY_JAR.import_jwks_as_json(_jwks, BOB)

def _eq(l1, l2):
    return set(l1) == set(l2)


def test_jwt_pack():
    _jwt = JWT(key_jar=ALICE_KEY_JAR, lifetime=3600, iss=ALICE).pack(aud=BOB)

    assert _jwt
    assert len(_jwt.split('.')) == 3


def test_jwt_pack_and_unpack():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg='RS256')
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB, allowed_sign_algs=["RS256"])
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid'}


def test_jwt_pack_and_unpack_with_lifetime():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, lifetime=600)
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid', 'exp'}


def test_jwt_pack_encrypt():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE)
    payload = {'sub': 'sub', 'aud': BOB}
    _jwt = alice.pack(payload=payload, encrypt=True, recv=BOB)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid', 'aud'}


def test_jwt_pack_unpack_sym():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, 'hemligt ordsprak', usage=['sig'])
    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    payload = {'sub': 'sub2'}
    _jwt = alice.pack(payload=payload)

    _kj = KeyJar()
    _kj.add_symmetric(ALICE, 'hemligt ordsprak', usage=['sig'])
    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256")
    info = bob.unpack(_jwt)
    assert info


def test_jwt_pack_encrypt_no_sign():
    alice = JWT(sign=False, key_jar=ALICE_KEY_JAR, iss=ALICE)

    payload = {'sub': 'sub', 'aud': BOB}
    _jwt = alice.pack(payload=payload, encrypt=True, recv=BOB)

    bob = JWT(key_jar=BOB_KEY_JAR, iss=BOB)
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'aud'}


def test_jwt_pack_and_unpack_with_alg():
    alice = JWT(key_jar=ALICE_KEY_JAR, iss=ALICE, sign_alg='RS384')
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(BOB_KEY_JAR, sign_alg='RS384')
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid'}


def test_extend_audience():
    _jwt = JWT()
    aud = _jwt.put_together_aud('abcdefgh')
    assert aud == ['abcdefgh']
    aud = _jwt.put_together_aud('12345678', aud)
    assert set(aud) == {'abcdefgh', '12345678'}


def test_with_jti():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, 'hemligt ordsprak', usage=['sig'])

    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    alice.with_jti = True
    payload = {'sub': 'sub2'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256")
    info = bob.unpack(_jwt)
    assert 'jti' in info


class DummyMsg(object):
    def __init__(self, **kwargs):
        for key,val in kwargs.items():
            setattr(self, key, val)

    def verify(self, **kwargs):
        return True


def test_msg_cls():
    _kj = KeyJar()
    _kj.add_symmetric(ALICE, 'hemligt ordsprak', usage=['sig'])

    alice = JWT(key_jar=_kj, iss=ALICE, sign_alg="HS256")
    payload = {'sub': 'sub2'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(key_jar=_kj, iss=BOB, sign_alg="HS256")
    bob.msg_cls = DummyMsg
    info = bob.unpack(_jwt)
    assert isinstance(info, DummyMsg)


KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
    ]

kj = init_key_jar(key_defs=KEY_DEFS)


def test_pick_key():
    keys = kj.get_issuer_keys('')

    _k = pick_key(keys, 'sig', 'RS256')
    assert len(_k) == 1

    _k = pick_key(keys, 'sig', 'ES256')
    assert len(_k) == 1

    _k = pick_key(keys, 'sig', 'ES384')
    assert len(_k) == 1

    _k = pick_key(keys, 'enc', "RSA-OAEP-256")
    assert len(_k) == 1

    _k = pick_key(keys, 'enc', "ECDH-ES")
    assert len(_k) == 0

