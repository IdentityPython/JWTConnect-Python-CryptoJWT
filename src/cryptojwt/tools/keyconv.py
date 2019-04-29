#!/usr/bin/env python3

"""Convert symmetric JWK from/to binary format"""

import argparse
import json
from binascii import hexlify
from getpass import getpass

from cryptography.hazmat.primitives import serialization
from cryptojwt.jwk import JWK
from cryptojwt.jwk.ec import (ECKey, import_private_key_from_file,
                              import_public_key_from_file)
from cryptojwt.jwk.rsa import (RSAKey, import_private_rsa_key_from_file,
                               import_public_rsa_key_from_file)
from cryptojwt.jwx import key_from_jwk_dict


def jwk_from_file(filename: str, private: bool = True) -> JWK:
    """Read JWK from file"""
    with open(filename, mode='rt') as input_file:
        jwk_dict = json.loads(input_file.read())
    return key_from_jwk_dict(jwk_dict, private=private)


def pem2rsa(filename: str, kid: str = None, private: bool = False, passphrase: str = None) -> JWK:
    """Convert RSA key from PEM to JWK"""
    if private:
        key = import_private_rsa_key_from_file(filename, passphrase)
    else:
        key = import_public_rsa_key_from_file(filename)
    jwk = RSAKey(kid=kid)
    jwk.load_key(key)
    return jwk


def pem2ec(filename: str, kid: str = None, private: bool = False, passphrase: str = None) -> JWK:
    """Convert EC key from PEM to JWK"""
    if private:
        key = import_private_key_from_file(filename, passphrase)
    else:
        key = import_public_key_from_file(filename)
    jwk = ECKey(kid=kid)
    jwk.load_key(key)
    return jwk


def jwk2bin(jwk: JWK) -> bytes:
    """Convert symmetric key from JWK to binary"""
    return jwk.key


def pem2jwk(filename: str, kid: str, private: bool = False) -> bytes:

    with open(filename, 'rt') as file:
        content = file.readlines()
    header = content[0]

    if private:
        passphrase = getpass('Private key passphrase: ')
        if len(passphrase) == 0:
            passphrase = None
    else:
        passphrase = None

    if 'BEGIN EC PRIVATE KEY' in header:
        jwk = pem2ec(filename, kid, private=True, passphrase=passphrase)
    elif 'BEGIN EC PUBLIC KEY' in header:
        jwk = pem2ec(filename, kid, private=False)
    elif 'BEGIN RSA PRIVATE KEY' in header:
        jwk = pem2rsa(filename, kid, private=True, passphrase=passphrase)
    elif 'BEGIN RSA PUBLIC KEY' in header:
        jwk = pem2rsa(filename, kid, private=False)
    else:
        raise ValueError("Unknown PEM format")

    return jwk


def jwk2pem(jwk: JWK, private: bool = False) -> bytes:
    """Convert asymmetric key from JWK to PEM"""

    if private:
        passphrase = getpass('Private key passphrase: ')
        if passphrase:
            enc = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            enc = serialization.NoEncryption
        serialized = jwk.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc)
    else:
        serialized = jwk.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return serialized


def main():
    """ Main function"""
    parser = argparse.ArgumentParser(description='JWK Key Conversion Utility')

    parser.add_argument('--kid',
                        dest='kid',
                        metavar='key_id',
                        help='Key ID')
    parser.add_argument('--private',
                        dest='private',
                        action='store_true',
                        help="Output private key")
    parser.add_argument('--output',
                        dest='output',
                        metavar='filename',
                        help='Output file name')
    parser.add_argument('filename', metavar='filename', nargs=1, help='filename')
    args = parser.parse_args()

    f = args.filename[0]

    if f.endswith('.json'):
        jwk = jwk_from_file(f, args.private)
        if jwk.kty == 'oct':
            serialized = jwk2bin(jwk)
        else:
            serialized = jwk2pem(jwk, args.private)

        if args.output:
            with open(args.output, mode='wt') as file:
                file.write(serialized)
        else:
            if jwk.kty == 'oct':
                print(hexlify(serialized).decode())
            else:
                print(serialized.decode())
    elif f.endswith('.pem'):
        jwk = pem2jwk(f, args.kid, args.private)
        serialized = jwk.serialize(private=args.private)

        if args.output:
            with open(args.output, mode='wt') as file:
                file.write(json.dumps(serialized))
        else:
            print(serialized)
    else:
        exit(-1)


if __name__ == "__main__":
    main()
