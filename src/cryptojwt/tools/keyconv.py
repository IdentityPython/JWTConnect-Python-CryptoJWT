#!/usr/bin/env python3

"""Convert JWK from/to PEM and other formats"""
import argparse
import json
from binascii import hexlify
from getpass import getpass
from typing import Optional

from cryptography.hazmat.primitives import serialization

from cryptojwt.jwk import JWK
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.ec import import_private_ec_key_from_file
from cryptojwt.jwk.ec import import_public_ec_key_from_file
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.jwk.rsa import import_public_rsa_key_from_file
from cryptojwt.jwx import key_from_jwk_dict


def jwk_from_file(filename: str, private: bool = True) -> JWK:
    """Read JWK from file"""
    with open(filename, mode="rt") as input_file:
        jwk_dict = json.loads(input_file.read())
    return key_from_jwk_dict(jwk_dict, private=private)


def pem2rsa(
    filename: str,
    kid: Optional[str] = None,
    private: bool = False,
    passphrase: Optional[str] = None,
) -> JWK:
    """Convert RSA key from PEM to JWK"""
    if private:
        key = import_private_rsa_key_from_file(filename, passphrase)
    else:
        key = import_public_rsa_key_from_file(filename)
    jwk = RSAKey(kid=kid)
    jwk.load_key(key)
    return jwk


def pem2ec(
    filename: str,
    kid: Optional[str] = None,
    private: bool = False,
    passphrase: Optional[str] = None,
) -> JWK:
    """Convert EC key from PEM to JWK"""
    if private:
        key = import_private_ec_key_from_file(filename, passphrase)
    else:
        key = import_public_ec_key_from_file(filename)
    jwk = ECKey(kid=kid)
    jwk.load_key(key)
    return jwk


def bin2jwk(filename: str, kid: str) -> JWK:
    """Read raw key from filename and return JWK"""
    with open(filename, "rb") as file:
        content = file.read()
    return SYMKey(kid=kid, key=content)


def pem2jwk(
    filename: str,
    kid: Optional[str] = None,
    kty: Optional[str] = None,
    private: bool = False,
    passphrase: Optional[str] = None,
) -> JWK:
    """Read PEM from filename and return JWK"""
    with open(filename, "rt") as file:
        content = file.readlines()
    header = content[0]

    if private:
        if passphrase is None:
            passphrase = getpass("Private key passphrase: ")
        if len(passphrase) == 0:
            passphrase = None
    else:
        passphrase = None

    if "BEGIN PUBLIC KEY" in header:
        if kty is not None and kty == "EC":
            jwk = pem2ec(filename, kid, private=False)
        elif kty is not None and kty == "RSA":
            jwk = pem2rsa(filename, kid, private=False)
        else:
            raise ValueError("Unknown key type")
    elif "BEGIN PRIVATE KEY" in header:
        if kty is not None and kty == "EC":
            jwk = pem2ec(filename, kid, private=True, passphrase=passphrase)
        elif kty is not None and kty == "RSA":
            jwk = pem2rsa(filename, kid, private=True, passphrase=passphrase)
        else:
            raise ValueError("Unknown key type")
    elif "BEGIN EC PRIVATE KEY" in header:
        jwk = pem2ec(filename, kid, private=True, passphrase=passphrase)
    elif "BEGIN EC PUBLIC KEY" in header:
        jwk = pem2ec(filename, kid, private=False)
    elif "BEGIN RSA PRIVATE KEY" in header:
        jwk = pem2rsa(filename, kid, private=True, passphrase=passphrase)
    elif "BEGIN RSA PUBLIC KEY" in header:
        jwk = pem2rsa(filename, kid, private=False)
    else:
        raise ValueError("Unknown PEM format")

    return jwk


def export_jwk(
    jwk: JWK,
    private: bool = False,
    encrypt: bool = False,
    passphrase: Optional[str] = None,
) -> bytes:
    """Export JWK as PEM/bin"""

    if jwk.kty == "oct":  # jwk is in fact a SYMKey
        return jwk.key

    # All other key types have private and public keys

    if private:
        if encrypt:
            if passphrase is None:
                passphrase = getpass("Private key passphrase: ")
        else:
            passphrase = None
        if passphrase:
            enc = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            enc = serialization.NoEncryption()
        serialized = jwk.priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
    else:
        serialized = jwk.pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    return serialized


def output_jwk(jwk: JWK, private: bool = False, filename: Optional[str] = None) -> None:
    """Output JWK to file"""
    serialized = jwk.serialize(private=private)
    if filename is not None:
        with open(filename, mode="wt") as file:
            file.write(json.dumps(serialized))
    else:
        print(json.dumps(serialized, indent=4))


def output_bytes(data: bytes, binary: bool = False, filename: Optional[str] = None) -> None:
    """Output data to file"""
    if filename is not None:
        with open(filename, mode="wb") as file:
            file.write(data)
    else:
        if binary:
            print(hexlify(data).decode())
        else:
            print(data.decode())


def main():
    """ Main function"""
    parser = argparse.ArgumentParser(description="JWK Conversion Utility")

    parser.add_argument("--kid", dest="kid", metavar="key_id", help="Key ID")
    parser.add_argument("--kty", dest="kty", metavar="type", help="Key type")
    parser.add_argument("--private", dest="private", action="store_true", help="Output private key")
    parser.add_argument(
        "--encrypt", dest="encrypt", action="store_true", help="Encrypt private key"
    )
    parser.add_argument("--output", dest="output", metavar="filename", help="Output file name")
    parser.add_argument("filename", metavar="filename", nargs=1, help="filename")
    args = parser.parse_args()

    f = args.filename[0]

    if f.endswith(".json"):
        jwk = jwk_from_file(f, args.private)
        serialized = export_jwk(jwk, private=args.private, encrypt=args.encrypt)
        output_bytes(data=serialized, binary=(jwk.kty == "oct"), filename=args.output)
    elif f.endswith(".bin"):
        jwk = bin2jwk(filename=f, kid=args.kid)
        output_jwk(jwk=jwk, private=True, filename=args.output)
    elif f.endswith(".pem"):
        jwk = pem2jwk(filename=f, kid=args.kid, private=args.private, kty=args.kty)
        output_jwk(jwk=jwk, private=args.private, filename=args.output)
    else:
        exit(-1)


if __name__ == "__main__":
    main()
