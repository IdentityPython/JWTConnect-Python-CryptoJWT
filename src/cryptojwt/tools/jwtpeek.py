#!/usr/bin/env python3

# Thanks to @rohe Roland Hedberg for most of the lines in this script :).
import argparse
import json
import os
import sys

from pygments import highlight
from pygments.formatters.terminal import TerminalFormatter
from pygments.lexers.data import JsonLexer

from cryptojwt.jwe import jwe
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jwk.rsa import RSAKey
from cryptojwt.jwk.rsa import import_rsa_key
from cryptojwt.jws import jws
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_issuer import KeyIssuer
from cryptojwt.key_jar import KeyJar

__author__ = "roland"

"""
Tool to view, verify signature on and/or decrypt JSON Web Token.

Usage examples:

(1) read JWT from stdin, no keys

cat idtoken | ./jwtpeek.py -f -

or

cat idtoken | ./jwtpeek.py

(2) read JWT from file, use keys from file with a JWKS to verify/decrypt

./jwtpeek.py -f idtoken -J keys.jwks

or 

(3) JWT from stdin, no keys

echo json.web.token | ./jwtpeek.py
 
"""


def process(jwt, keys, quiet):
    _jw = jwe.factory(jwt)
    if _jw:
        if not quiet:
            print("Encrypted JSON Web Token")
            print("Headers: {}".format(_jw.jwt.headers))
        if keys:
            res = _jw.decrypt(keys=keys)
            json_object = json.loads(res)
            json_str = json.dumps(json_object, indent=2)
            print(highlight(json_str, JsonLexer(), TerminalFormatter()))
        else:
            print("No keys can't decrypt")
            sys.exit(1)
    else:
        _jw = jws.factory(jwt)
        if _jw:
            if quiet:
                json_object = json.loads(_jw.jwt.part[1].decode("utf-8"))
                json_str = json.dumps(json_object, indent=2)
                print(highlight(json_str, JsonLexer(), TerminalFormatter()))
            else:
                print("Signed JSON Web Token")
                print("Headers: {}".format(_jw.jwt.headers))
                if keys:
                    res = _jw.verify_compact(keys=keys)
                    print("Verified message: {}".format(res))
                else:
                    json_object = json.loads(_jw.jwt.part[1].decode("utf-8"))
                    json_str = json.dumps(json_object, indent=2)
                    print(
                        "Unverified message: {}".format(
                            highlight(json_str, JsonLexer(), TerminalFormatter())
                        )
                    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", dest="rsa_file", help="File containing a RSA key")
    parser.add_argument("-k", dest="hmac_key", help="If using a HMAC algorithm this is the key")
    parser.add_argument("-i", dest="kid", help="key id")
    parser.add_argument("-j", dest="jwk", help="JSON Web Key")
    parser.add_argument("-J", dest="jwks", help="JSON Web Keys")
    parser.add_argument("-u", dest="jwks_url", help="JSON Web Keys URL")
    parser.add_argument("-f", dest="msg", help="The message")
    parser.add_argument(
        "-q",
        dest="quiet",
        help="Quiet mode -- only show the RAW but prettified JSON",
        action="store_true",
    )

    args = parser.parse_args()

    if args.kid:
        _kid = args.kid
    else:
        _kid = ""

    keys = []
    if args.rsa_file:
        keys.append(RSAKey(key=import_rsa_key(args.rsa_file), kid=_kid))
    if args.hmac_key:
        keys.append(SYMKey(key=args.hmac_key, kid=_kid))

    if args.jwk:
        _key = key_from_jwk_dict(open(args.jwk).read())
        keys.append(_key)

    if args.jwks:
        _iss = KeyIssuer()
        _iss.import_jwks(open(args.jwks).read())
        keys.extend(_iss.all_keys())

    if args.jwks_url:
        _kb = KeyBundle(source=args.jwks_url)
        keys.extend(_kb.get())

    if not args.msg:  # If nothing specified assume stdin
        message = sys.stdin.read()
    elif args.msg == "-":
        message = sys.stdin.read()
    else:
        if os.path.isfile(args.msg):
            message = open(args.msg).read().strip("\n")
        else:
            message = args.msg

    message = message.strip()
    message = message.strip('"')
    process(message, keys, args.quiet)
