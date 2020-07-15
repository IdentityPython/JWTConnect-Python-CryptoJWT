#!/usr/bin/env python3

"""JSON Web Key (JWK) Generator"""
import argparse
import json
import os
import sys

from cryptojwt.jwk.ec import NIST2SEC
from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.utils import b64e

DEFAULT_SYM_KEYSIZE = 32
DEFAULT_RSA_KEYSIZE = 2048
DEFAULT_RSA_EXP = 65537
DEFAULT_EC_CURVE = "P-256"


def main():
    """ Main function"""
    parser = argparse.ArgumentParser(description="JSON Web Key (JWK) Generator")

    parser.add_argument("--kty", dest="kty", metavar="type", help="Key type", required=True)
    parser.add_argument("--size", dest="keysize", type=int, metavar="size", help="Key size")
    parser.add_argument(
        "--crv",
        dest="crv",
        metavar="curve",
        help="EC curve",
        choices=NIST2SEC.keys(),
        default=DEFAULT_EC_CURVE,
    )
    parser.add_argument(
        "--exp",
        dest="rsa_exp",
        type=int,
        metavar="exponent",
        help="RSA public key exponent (default {})".format(DEFAULT_RSA_EXP),
        default=DEFAULT_RSA_EXP,
    )
    parser.add_argument("--kid", dest="kid", metavar="id", help="Key ID")
    args = parser.parse_args()

    if args.kty.upper() == "RSA":
        if args.keysize is None:
            args.keysize = DEFAULT_RSA_KEYSIZE
        jwk = new_rsa_key(public_exponent=args.rsa_exp, key_size=args.keysize, kid=args.kid)
    elif args.kty.upper() == "EC":
        if args.crv not in NIST2SEC:
            print("Unknown curve: {0}".format(args.crv), file=sys.stderr)
            exit(1)
        jwk = new_ec_key(crv=args.crv, kid=args.kid)
    elif args.kty.upper() == "SYM":
        if args.keysize is None:
            args.keysize = DEFAULT_SYM_KEYSIZE
        randomkey = os.urandom(args.keysize)
        jwk = SYMKey(key=randomkey, kid=args.kid)
    else:
        print("Unknown key type: {}".format(args.kty), file=sys.stderr)
        exit(1)

    jwk_dict = jwk.serialize(private=True)
    print(json.dumps(jwk_dict, sort_keys=True, indent=4))
    print("SHA-256: " + jwk.thumbprint("SHA-256").decode(), file=sys.stderr)


if __name__ == "__main__":
    main()
