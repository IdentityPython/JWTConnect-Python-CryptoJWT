import os

from cryptojwt.jwk import import_private_rsa_key_from_file, SYMKey
from cryptojwt.jwk import RSAKey
from cryptojwt.jwt import JWT

__author__ = 'Roland Hedberg'

ALICE = 'https://example.org/alice'
BOB = 'https://example.com/bob'
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


k1 = import_private_rsa_key_from_file(full_path('rsa.key'))
k2 = import_private_rsa_key_from_file(full_path('size2048.key'))

ALICE_KEYS = [RSAKey(use='sig', kid='1').load_key(k1),
              RSAKey(use='enc', kid='2').load_key(k2)]
ALICE_PUB_KEYS = [RSAKey(use='sig', kid='1').load_key(k1.public_key()),
                  RSAKey(use='enc', kid='2').load_key(k2.public_key())]

k3 = import_private_rsa_key_from_file(full_path('server.key'))

BOB_KEYS = [RSAKey(use='enc', kid='3').load_key(k3)]
BOB_PUB_KEYS = [RSAKey(use='enc', kid='3').load_key(k3.public_key())]


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_jwt_pack():
    _jwt = JWT(own_keys=ALICE_KEYS, lifetime=3600, iss=ALICE).pack()

    assert _jwt
    assert len(_jwt.split('.')) == 3


def test_jwt_pack_and_unpack():
    alice = JWT(own_keys=ALICE_KEYS, iss=ALICE)
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(own_keys=BOB_KEYS, iss=BOB, rec_keys={ALICE: ALICE_PUB_KEYS})
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid'}


def test_jwt_pack_and_unpack_with_lifetime():
    alice = JWT(own_keys=ALICE_KEYS, iss=ALICE, lifetime=600)
    payload = {'sub': 'sub'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(own_keys=BOB_KEYS, iss=BOB, rec_keys={ALICE: ALICE_PUB_KEYS})
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid', 'exp'}


def test_jwt_pack_encrypt():
    alice = JWT(own_keys=ALICE_KEYS, iss=ALICE, rec_keys={BOB: BOB_PUB_KEYS})
    payload = {'sub': 'sub', 'aud': BOB}
    _jwt = alice.pack(payload=payload, encrypt=True, recv=BOB)

    bob = JWT(own_keys=BOB_KEYS, iss=BOB, rec_keys={ALICE: ALICE_PUB_KEYS})
    info = bob.unpack(_jwt)

    assert set(info.keys()) == {'iat', 'iss', 'sub', 'kid', 'aud'}


def test_jwt_pack_unpack_sym():
    _sym_key = SYMKey(key='hemligt ord', use='sig')
    alice = JWT(own_keys=[_sym_key], iss=ALICE, sign_alg="HS256")
    payload = {'sub': 'sub2'}
    _jwt = alice.pack(payload=payload)

    bob = JWT(own_keys=None, iss=BOB, rec_keys={ALICE: [_sym_key]})
    info = bob.unpack(_jwt)
    assert info
