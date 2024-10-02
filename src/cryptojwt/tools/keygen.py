#!/usr/bin/env python3

"""JSON Web Key (JWK) Generator"""

import argparse
import json
import sys

from cryptojwt.jwk.ec import NIST2SEC, new_ec_key
from cryptojwt.jwk.hmac import new_sym_key
from cryptojwt.jwk.okp import OKP_CRV2PUBLIC, new_okp_key
from cryptojwt.jwk.rsa import new_rsa_key

DEFAULT_SYM_KEYSIZE = 32
DEFAULT_RSA_KEYSIZE = 2048
DEFAULT_RSA_EXP = 65537
DEFAULT_EC_CURVE = "P-256"


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="JSON Web Key (JWK) Generator")

    parser.add_argument("--kty", dest="kty", metavar="type", help="Key type", required=True)
    parser.add_argument("--size", dest="keysize", type=int, metavar="size", help="Key size")
    parser.add_argument(
        "--crv",
        dest="crv",
        metavar="curve",
        help="EC curve",
        choices=list(NIST2SEC.keys()) + list(OKP_CRV2PUBLIC.keys()),
        default=DEFAULT_EC_CURVE,
    )
    parser.add_argument(
        "--exp",
        dest="rsa_exp",
        type=int,
        metavar="exponent",
        help=f"RSA public key exponent (default {DEFAULT_RSA_EXP})",
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
            print(f"Unknown curve: {args.crv}", file=sys.stderr)
            exit(1)
        jwk = new_ec_key(crv=args.crv, kid=args.kid)
    elif args.kty.upper() == "OKP":
        if args.crv not in OKP_CRV2PUBLIC:
            print(f"Unknown curve: {args.crv}", file=sys.stderr)
            exit(1)
        jwk = new_okp_key(crv=args.crv, kid=args.kid)
    elif args.kty.upper() == "SYM" or args.kty.upper() == "OCT":
        if args.keysize is None:
            args.keysize = DEFAULT_SYM_KEYSIZE
        jwk = new_sym_key(bytes=args.keysize, kid=args.kid)
    else:
        print(f"Unknown key type: {args.kty}", file=sys.stderr)
        exit(1)

    jwk_dict = jwk.serialize(private=True)
    print(json.dumps(jwk_dict, sort_keys=True, indent=4))
    print("SHA-256: " + jwk.thumbprint("SHA-256").decode(), file=sys.stderr)


if __name__ == "__main__":
    main()
