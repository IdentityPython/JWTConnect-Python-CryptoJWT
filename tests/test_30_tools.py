import json
import os

import cryptojwt.tools.keyconv as keyconv
from cryptojwt.jwk import JWK
from cryptojwt.jwx import key_from_jwk_dict

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def jwk_from_file(filename: str, private: bool = True) -> JWK:
    """Read JWK from file"""
    with open(filename, mode="rt") as input_file:
        jwk_dict = json.loads(input_file.read())
    return key_from_jwk_dict(jwk_dict, private=private)


def convert_rsa_pem2jwt(filename_jwk: str, filename_pem: str, private: bool):
    k1 = jwk_from_file(filename=filename_jwk, private=private)
    k2 = keyconv.pem2jwk(
        filename=filename_pem, kid=k1.kid, kty="RSA", private=private, passphrase=""
    )
    if k1 != k2:
        raise Exception("Keys differ")


def convert_ec_pem2jwt(filename_jwk: str, filename_pem: str, private: bool):
    k1 = jwk_from_file(filename=filename_jwk, private=private)
    k2 = keyconv.pem2jwk(
        filename=filename_pem, kid=k1.kid, kty="EC", private=private, passphrase=""
    )
    if k1 != k2:
        raise Exception("Keys differ")


def test_pem2rsa_public():
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-1024.json",
        BASEDIR + "/test_keys/rsa-1024-public.pem",
        private=False,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-1280.json",
        BASEDIR + "/test_keys/rsa-1280-public.pem",
        private=False,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-2048.json",
        BASEDIR + "/test_keys/rsa-2048-public.pem",
        private=False,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-3072.json",
        BASEDIR + "/test_keys/rsa-3072-public.pem",
        private=False,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-4096.json",
        BASEDIR + "/test_keys/rsa-4096-public.pem",
        private=False,
    )


def test_pem2rsa_private():
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-1024.json",
        BASEDIR + "/test_keys/rsa-1024-private.pem",
        private=True,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-1280.json",
        BASEDIR + "/test_keys/rsa-1280-private.pem",
        private=True,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-2048.json",
        BASEDIR + "/test_keys/rsa-2048-private.pem",
        private=True,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-3072.json",
        BASEDIR + "/test_keys/rsa-3072-private.pem",
        private=True,
    )
    convert_rsa_pem2jwt(
        BASEDIR + "/test_keys/rsa-4096.json",
        BASEDIR + "/test_keys/rsa-4096-private.pem",
        private=True,
    )


def test_pem2ec_public():
    convert_ec_pem2jwt(
        BASEDIR + "/test_keys/ec-p256.json",
        BASEDIR + "/test_keys/ec-p256-public.pem",
        private=False,
    )
    convert_ec_pem2jwt(
        BASEDIR + "/test_keys/ec-p384.json",
        BASEDIR + "/test_keys/ec-p384-public.pem",
        private=False,
    )


def test_pem2ec_private():
    convert_ec_pem2jwt(
        BASEDIR + "/test_keys/ec-p256.json",
        BASEDIR + "/test_keys/ec-p256-private.pem",
        private=True,
    )
    convert_ec_pem2jwt(
        BASEDIR + "/test_keys/ec-p384.json",
        BASEDIR + "/test_keys/ec-p384-private.pem",
        private=True,
    )
