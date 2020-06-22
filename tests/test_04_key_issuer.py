import os
import shutil
import time

import pytest
import responses

from cryptojwt.exception import JWKESTException
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_issuer import KeyIssuer
from cryptojwt.key_issuer import build_keyissuer
from cryptojwt.key_issuer import init_key_issuer

__author__ = 'Roland Hedberg'

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         "test_keys"))
RSAKEY = os.path.join(BASE_PATH, "cert.key")
RSA0 = os.path.join(BASE_PATH, "rsa.key")
EC0 = os.path.join(BASE_PATH, "ec.key")
BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


JWK0 = {
    "keys": [
        {
            'kty': 'RSA', 'e': 'AQAB', 'kid': "abc",
            'n':
                'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5'
                'B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'
        }
    ]
}

JWK1 = {
    "keys": [
        {
            "n":
                "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8"
                "mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta"
                "-NvS-aG_jN5cstVbCGWE20H0vF"
                "VrJKNx0Zf-u-aA-syM4uX7wdWgQ"
                "-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1k"
                "leiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": "AQAB", "kty": "RSA", "kid": "rsa1"
        },
        {
            "k":
                "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct"
        },
    ]
}

JWK2 = {
    "keys": [
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "kriMPdmBvx68skT8-mPAB3BseeA",
            "kty": "RSA",
            "n":
                "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS_AHsBeQPqYygfYVJL6_EgzVuwRk5txr9e3n1um"
                "l94fLyq_AXbwo9yAduf4dCHTP8CWR1dnDR"
                "-Qnz_4PYlWVEuuHHONOw_blbfdMjhY"
                "-C_BYM2E3pRxbohBb3x__CfueV7ddz2LYiH3"
                "wjz0QS_7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd_GTgWN8A"
                "-6SN1r4hzpjFKFLbZnBt77ACSiYx-IHK4Mp-NaVEi5wQt"
                "SsjQtI--XsokxRDqYLwus1I1SihgbV_STTg5enufuw",
            "use": "sig",
            "x5c": [
                "MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb"
                "2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb2"
                "50cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipg"
                "H0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6"
                "/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Q"
                "nz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x"
                "//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13S"
                "QwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp"
                "+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5en"
                "ufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJ"
                "vbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdN"
                "VGKCmSf8M65b8h0NwlIjGGGy"
                "/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADD"
                "kN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5"
                "+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8y"
                "PJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW"
                "+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ"
            ],
            "x5t": "kriMPdmBvx68skT8-mPAB3BseeA"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "MnC_VZcATfM5pOYiJHMba9goEKY",
            "kty": "RSA",
            "n":
                "vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq"
                "-RtwN1Vs_z57hO82kkzL-cQHZX3bMJ"
                "D-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW_EW_P"
                "-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5yCw5T_Vuwqqsio3"
                "V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3-T-IA"
                "bsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ",
            "use": "sig",
            "x5c": [
                "MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb"
                "250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZX"
                "NzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs"
                "/uPhEf7zVizjfcr/ISGFe9+yUO"
                "qwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy"
                "/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW"
                "9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU"
                "/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg"
                "0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k"
                "/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX"
                "14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9"
                "+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNG"
                "zZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m"
                "/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uh"
                "bGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN"
                "/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrs"
                "KsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3"
                "/bKkLSuDaKLWSqMhozdhXsIIKvJQ=="
            ],
            "x5t": "MnC_VZcATfM5pOYiJHMba9goEKY"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b"
                      "-b112-36a304b66dad/v2.0/",
            "kid": "GvnPApfWMdLRi8PDmisFn7bprKg",
            "kty": "RSA",
            "n": "5ymq_xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMRG7sJq"
                 "-UWOKVOA4MVrd_NdV-ejj1DE5MPSiG"
                 "-mZK_5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ48thXOTED0oNa6U",
            "use": "sig",
            "x5c": [
                "MIICWzCCAcSgAwIBAgIJAKVzMH2FfC12MA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVib"
                "GljIEtleTAeFw0xMzExMTExODMzMDhaFw0xNjExMTAxODMzMDhaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibG"
                "ljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA5ymq"
                "/xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMR"
                "G7sJq+UWOKVOA4MVrd/NdV+ejj1DE5MPSiG+mZK"
                "/5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ"
                "48thXOTED0oNa6UCAwEAAaOBijCBhzAdBgNVHQ4EFgQURCN"
                "+4cb0pvkykJCUmpjyfUfnRMowWQYDVR0jBFIwUIAURCN+4cb0pvkyk"
                "JCUmpjyfUfnRMqhLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAKVzMH2FfC12MAsGA1UdDw"
                "QEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQB8v8G5"
                "/vUl8k7xVuTmMTDA878AcBKBrJ/Hp6RShmdqEGVI7SFR7IlBN1//NwD0n"
                "+Iqzmn"
                "RV2PPZ7iRgMF/Fyvqi96Gd8X53ds/FaiQpZjUUtcO3fk0hDRQPtCYMII5jq"
                "+YAYjSybvF84saB7HGtucVRn2nMZc5cAC42QNYIlPM"
                "qA=="
            ],
            "x5t": "GvnPApfWMdLRi8PDmisFn7bprKg"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b"
                      "-b112-36a304b66dad/v2.0/",
            "kid": "dEtpjbEvbhfgwUI-bdK5xAU_9UQ",
            "kty": "RSA",
            "n":
                "x7HNcD9ZxTFRaAgZ7-gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQeSML7qZPlowb5BUakdLI70ayM4vN36--0ht8-oCHhl8Yj"
                "GFQkU-Iv2yahWHEP-1EK6eOEYu6INQP9Lk0HMk3QViLwshwb"
                "-KXVD02jdmX2HNdYJdPyc0c",
            "use": "sig",
            "x5c": [
                "MIICWzCCAcSgAwIBAgIJAL3MzqqEFMYjMA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVib"
                "GljIEtleTAeFw0xMzExMTExOTA1MDJaFw0xOTExMTAxOTA1MDJaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibG"
                "ljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx7HNcD9ZxTFRaAgZ7"
                "+gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQ"
                "eSML7qZPlowb5BUakdLI70ayM4vN36++0ht8+oCHhl8YjGFQkU"
                "+Iv2yahWHEP+1EK6eOEYu6INQP9Lk0HMk3QViLwshwb+KXVD02j"
                "dmX2HNdYJdPyc0cCAwEAAaOBijCBhzAdBgNVHQ4EFgQULR0aj9AtiNMgqIY8ZyXZGsHcJ5gwWQYDVR0jBFIwUIAULR0aj9AtiNMgq"
                "IY8ZyXZGsHcJ5ihLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAL3MzqqEFMYjMAsGA1UdDw"
                "QEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQBshrsF9yls4ArxOKqXdQPDgHrbynZL8m1iinLI4TeSfmTCDevXVBJrQ6SgDkihl3aCj74"
                "IEte2MWN78sHvLLTWTAkiQSlGf1Zb0durw+OvlunQ2AKbK79Qv0Q+wwGuK"
                "+oymWc3GSdP1wZqk9dhrQxb3FtdU2tMke01QTut6wr7"
                "ig=="
            ],
            "x5t": "dEtpjbEvbhfgwUI-bdK5xAU_9UQ"
        }
    ]
}


def test_build_keyissuer():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
    ]

    key_issuer = build_keyissuer(keys)
    jwks = key_issuer.export_jwks()
    for key in jwks["keys"]:
        assert "d" not in key  # the JWKS shouldn't contain the private part
        # of the keys

    assert len(key_issuer) == 3  # 3 keys
    assert len(key_issuer.get('sig')) == 2  # 2 for signing
    assert len(key_issuer.get('enc')) == 1  # 1 for encryption


def test_build_keyissuer_usage():
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        {"type": "oct", "use": ["enc"]},
        {"type": "oct", "use": ["enc"]},
    ]

    key_issuer = build_keyissuer(keys)
    jwks_sig = key_issuer.export_jwks(usage='sig')
    jwks_enc = key_issuer.export_jwks(usage='enc')
    assert len(jwks_sig.get('keys')) == 2  # A total of 2 keys with use=sig
    assert len(jwks_enc.get('keys')) == 3  # A total of 3 keys with use=enc


def test_build_keyissuer_missing(tmpdir):
    keys = [
        {
            "type": "RSA", "key": os.path.join(tmpdir.dirname, "missing_file"),
            "use": ["enc", "sig"]
        }]

    key_issuer = build_keyissuer(keys)

    assert key_issuer is None


def test_build_RSA_keyissuer_from_file(tmpdir):
    keys = [
        {
            "type": "RSA", "key": RSA0,
            "use": ["enc", "sig"]
        }]

    key_issuer = build_keyissuer(keys)

    assert len(key_issuer) == 2


def test_build_EC_keyissuer_missing(tmpdir):
    keys = [
        {
            "type": "EC", "key": os.path.join(tmpdir.dirname, "missing_file"),
            "use": ["enc", "sig"]
        }]

    key_issuer = build_keyissuer(keys)

    assert key_issuer is None


def test_build_EC_keyissuer_from_file(tmpdir):
    keys = [
        {
            "type": "EC", "key": EC0,
            "use": ["enc", "sig"]
        }]

    key_issuer = build_keyissuer(keys)

    assert len(key_issuer) == 2


class TestKeyJar(object):
    def test_keyissuer_add(self):
        issuer = KeyIssuer()
        kb = keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"])
        issuer.add_kb(kb)
        assert len(issuer.all_keys()) == 1

    def test_add_symmetric(self):
        issuer = KeyIssuer()
        issuer.add_symmetric('abcdefghijklmnop', ['sig'])
        assert len(issuer.get('sig', 'oct')) == 1

    def test_items(self):
        issuer = KeyIssuer()
        issuer.add_kb(KeyBundle(
            [{"kty": "oct", "key": "abcdefghijklmnop", "use": "sig"},
             {"kty": "oct", "key": "ABCDEFGHIJKLMNOP", "use": "enc"}]))
        issuer.add_kb(KeyBundle([
            {"kty": "oct", "key": "0123456789012345", "use": "sig"},
            {"kty": "oct", "key": "1234567890123456", "use": "enc"}]))
        issuer.add_kb(keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]))

        assert len(issuer.all_keys()) == 5

    def test_get_enc(self):
        issuer = KeyIssuer()
        issuer.add_kb(KeyBundle(
            [{"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "sig"},
             {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "enc"}]))
        issuer.add_kb(KeyBundle([
            {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "sig"},
            {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "enc"}]))
        issuer.add_kb(keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]))

        assert issuer.get('enc', 'oct')

    def test_get_enc_not_mine(self):
        issuer = KeyIssuer()
        issuer.add_kb(KeyBundle(
            [{"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "sig"},
             {"kty": "oct", "key": "a1b2c3d4e5f6g7h8", "use": "enc"}]))
        issuer.add_kb(KeyBundle([
            {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "sig"},
            {"kty": "oct", "key": "1a2b3c4d5e6f7g8h", "use": "ver"}]))
        issuer.add_kb(keybundle_from_local_file(RSAKEY, "der", ["ver", "sig"]))

        assert issuer.get('enc', 'oct')

    def test_dump_issuer_keys(self):
        kb = keybundle_from_local_file("file://%s/jwk.json" % BASE_PATH, "jwks",
                                       ["sig"])
        assert len(kb) == 1
        issuer = KeyIssuer()
        issuer.add_kb(kb)
        _jwks_dict = issuer.export_jwks()

        _info = _jwks_dict['keys'][0]
        assert _info == {
            'use': 'sig',
            'e': 'AQAB',
            'kty': 'RSA',
            'alg': 'RS256',
            'n': 'pKybs0WaHU_y4cHxWbm8Wzj66HtcyFn7Fh3n'
                 '-99qTXu5yNa30MRYIYfSDwe9JVc1JUoGw41yq2StdGBJ40HxichjE'
                 '-Yopfu3B58Q'
                 'lgJvToUbWD4gmTDGgMGxQxtv1En2yedaynQ73sDpIK-12JJDY55pvf'
                 '-PCiSQ9OjxZLiVGKlClDus44_uv2370b9IN2JiEOF-a7JB'
                 'qaTEYLPpXaoKWDSnJNonr79tL0T7iuJmO1l705oO3Y0TQ'
                 '-INLY6jnKG_RpsvyvGNnwP9pMvcP1phKsWZ10ofuuhJGRp8IxQL9Rfz'
                 'T87OvF0RBSO1U73h09YP-corWDsnKIi6TbzRpN5YDw',
            'kid': 'abc'
        }

    def test_no_use(self):
        kb = KeyBundle(JWK0["keys"])
        issuer = KeyIssuer()
        issuer.add_kb(kb)
        enc_key = issuer.get('enc', "RSA")
        assert enc_key != []

    # @pytest.mark.network
    # def test_provider(self):
    #     issuer = KeyIssuer()
    #     issuer.load_keys(jwks_uri="https://connect-op.herokuapp.com/jwks.json")
    #
    #     assert issuer.get("https://connect-op.heroku.com")[0].keys()


def test_import_jwks():
    issuer = KeyIssuer()
    issuer.import_jwks(JWK1)
    assert len(issuer.all_keys()) == 2


def test_get_signing_key_use_undefined():
    issuer = KeyIssuer()
    issuer.import_jwks(JWK1)
    keys = issuer.get('sig', kid='rsa1')
    assert len(keys) == 1

    keys = issuer.get('sig', key_type='rsa')
    assert len(keys) == 1

    keys = issuer.get('sig', key_type='rsa', kid='rsa1')
    assert len(keys) == 1


KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]


def test_remove_after():
    # initial key_issuer
    key_issuer = build_keyissuer(KEYDEFS)
    _old = [k.kid for k in key_issuer.all_keys() if k.kid]
    assert len(_old) == 2

    key_issuer.remove_after = 1
    # rotate_keys = create new keys + make the old as inactive
    key_issuer = key_issuer.rotate_keys(KEYDEFS)

    key_issuer.remove_outdated(time.time() + 3600)

    _interm = [k.kid for k in key_issuer.all_keys() if k.kid]
    assert len(_interm) == 2

    # The remainder are the new keys
    _new = [k.kid for k in key_issuer.all_keys() if k.kid]
    assert len(_new) == 2

    # should not be any overlap between old and new
    assert set(_new).intersection(set(_old)) == set()


JWK_UK = {
    "keys": [
        {
            "n":
                "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8"
                "mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta"
                "-NvS-aG_jN5cstVbCGWE20H0vF"
                "VrJKNx0Zf-u-aA-syM4uX7wdWgQ"
                "-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1k"
                "leiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": "AQAB", "kty": "RSA", "kid": "rsa1"
        },
        {
            "k":
                "YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "buz"
        },
    ]
}


def test_load_unknown_keytype():
    issuer = KeyIssuer()
    issuer.import_jwks(JWK_UK)
    assert len(issuer.all_keys()) == 1


JWK_FP = {
    "keys": [
        {"e": "AQAB", "kty": "RSA", "kid": "rsa1"},
    ]
}


def test_load_missing_key_parameter():
    issuer = KeyIssuer()
    with pytest.raises(JWKESTException):
        issuer.import_jwks(JWK_FP)


JWKS_SPO = {
    "keys": [
        {
            "kid":
                "BfxfnahEtkRBG3Hojc9XGLGht_5rDBj49Wh3sBDVnzRpulMqYwMRmpizA0aSPT1fhCHYivTiaucWUqFu_GwTqA",
            "use": "sig",
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": "1XXUXq75gOPZ4bEj1o2Z5XKJWSs6LmL6fAOK3vyMzSc",
            "y": "ac1h_DwyuUxhkrD9oKMJ-b_KuiVvvSARIwT-XoEmDXs"
        },
        {
            "kid":
                "91pD1H81rXUvrfg9mkngIG-tXjnldykKUVbITDIU1SgJvq91b8clOcJuEHNAq61eIvg8owpEvWcWAtlbV2awyA",
            "use": "sig",
            "alg": "ES256",
            "kty": "EC",
            "crv": "P-256",
            "x": "2DfQoLpZS2j3hHEcHDkzV8ISx-RdLt6Opy8YZYVm4AQ",
            "y": "ycvkFMBIzgsowiaf6500YlG4vaMSK4OF7WVtQpUbEE0"
        },
        {
            "kid": "0sIEl3MUJiCxrqleEBBF-_bZq5uClE84xp-wpt8oOI"
                   "-WIeNxBjSR4ak_OTOmLdndB0EfDLtC7X1JrnfZILJkxA",
            "use": "sig",
            "alg": "RS256",
            "kty": "RSA",
            "n":
                "yG9914Q1j63Os4jX5dBQbUfImGq4zsXJD4R59XNjGJlEt5ek6NoiDl0ucJO3_7_R9e5my2ONTSqZhtzFW6MImnIn8idWYzJzO2EhUPCHTvw_2oOGjeYTE2VltIyY_ogIxGwY66G0fVPRRH9tCxnkGOrIvmVgkhCCGkamqeXuWvx9MCHL_gJbZJVwogPSRN_SjA1gDlvsyCdA6__CkgAFcSt1sGgiZ_4cQheKexxf1-7l8R91ZYetz53drk2FS3SfuMZuwMM4KbXt6CifNhzh1Ye-5Tr_ZENXdAvuBRDzfy168xnk9m0JBtvul9GoVIqvCVECB4MPUb7zU6FTIcwRAw",
            "e": "AQAB"
        },
        {
            "kid":
                "zyDfdEU7pvH0xEROK156ik8G7vLO1MIL9TKyL631kSPtr9tnvs9XOIiq5jafK2hrGr2qqvJdejmoonlGqWWZRA",
            "use": "sig",
            "alg": "RS256",
            "kty": "RSA",
            "n":
                "68be-nJp46VLj4Ci1V36IrVGYqkuBfYNyjQTZD_7yRYcERZebowOnwr3w0DoIQpl8iL2X8OXUo7rUW_LMzLxKx2hEmdJfUn4LL2QqA3KPgjYz8hZJQPG92O14w9IZ-8bdDUgXrg9216H09yq6ZvJrn5Nwvap3MXgECEzsZ6zQLRKdb_R96KFFgCiI3bEiZKvZJRA7hM2ePyTm15D9En_Wzzfn_JLMYgE_DlVpoKR1MsTinfACOlwwdO9U5Dm-5elapovILTyVTgjN75i-wsPU2TqzdHFKA-4hJNiWGrYPiihlAFbA2eUSXuEYFkX43ahoQNpeaf0mc17Jt5kp7pM2w",
            "e": "AQAB"
        },
        {
            "kid": "q-H9y8iuh3BIKZBbK6S0mH_isBlJsk"
                   "-u6VtZ5rAdBo5fCjjy3LnkrsoK_QWrlKB08j_PcvwpAMfTEDHw5spepw",
            "use": "sig",
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "FnbcUAXZ4ySvrmdXK1MrDuiqlqTXvGdAaE4RWZjmFIQ"
        },
        {
            "kid":
                "bL33HthM3fWaYkY2_pDzUd7a65FV2R2LHAKCOsye8eNmAPDgRgpHWPYpWFVmeaujUUEXRyDLHN"
                "-Up4QH_sFcmw",
            "use": "sig",
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "CS01DGXDBPV9cFmd8tgFu3E7eHn1UcP7N1UCgd_JgZo"
        }
    ]
}


def test_load_spomky_keys():
    issuer = KeyIssuer()
    issuer.import_jwks(JWKS_SPO)
    assert len(issuer) == 4


def test_get_ec():
    issuer = KeyIssuer()
    issuer.import_jwks(JWKS_SPO)
    k = issuer.get('sig', 'EC', alg='ES256')
    assert k


def test_get_ec_wrong_alg():
    issuer = KeyIssuer()
    issuer.import_jwks(JWKS_SPO)
    k = issuer.get('sig', 'EC', alg='ES512')
    assert k == []


def test_keyissuer_eq():
    kj1 = KeyIssuer()
    kj1.import_jwks(JWKS_SPO)

    kj2 = KeyIssuer()
    kj2.import_jwks(JWKS_SPO)

    assert kj1 == kj2


PUBLIC_FILE = '{}/public_jwks.json'.format(BASEDIR)
PRIVATE_FILE = '{}/private_jwks.json'.format(BASEDIR)
KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]
KEYSPEC_2 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
]
KEYSPEC_3 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]},
    {"type": "EC", "crv": "P-521", "use": ["sig"]}
]
KEYSPEC_4 = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
]
KEYSPEC_5 = [
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-384", "use": ["sig"]}
]


def test_init_key_issuer():
    # Nothing written to file
    _keyissuer = init_key_issuer(key_defs=KEYSPEC)
    assert len(_keyissuer) == 2


def test_init_key_issuer_dump_public():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # JWKS with public keys written to file
    _keyissuer = init_key_issuer(public_path=PUBLIC_FILE, key_defs=KEYSPEC)
    assert len(_keyissuer) == 2

    # JWKS will be read from disc, not created new
    _keyissuer2 = init_key_issuer(public_path=PUBLIC_FILE, key_defs=KEYSPEC)
    assert len(_keyissuer2) == 2

    # verify that the 2 Key issuers contains the same keys


def test_init_key_issuer_dump_private():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # New set of keys, JWKSs with keys and public written to file
    _keyissuer = init_key_issuer(private_path=PRIVATE_FILE, key_defs=KEYSPEC, read_only=False)

    # JWKS will be read from disc, not created new
    _keyissuer2 = init_key_issuer(private_path=PRIVATE_FILE, key_defs=KEYSPEC, read_only=False)
    assert _keyissuer == _keyissuer2


def test_init_key_issuer_update():
    for _file in [PRIVATE_FILE, PUBLIC_FILE]:
        if os.path.isfile(_file):
            os.unlink(_file)

    # New set of keys, JWKSs with keys and public written to file
    _keyissuer_1 = init_key_issuer(private_path=PRIVATE_FILE, key_defs=KEYSPEC,
                                   public_path=PUBLIC_FILE, read_only=False)
    assert len(_keyissuer_1) == 2

    _keyissuer_2 = init_key_issuer(private_path=PRIVATE_FILE, key_defs=KEYSPEC_2,
                                   public_path=PUBLIC_FILE)

    # Both should contain the same RSA key
    rsa1 = _keyissuer_1.get('sig', 'RSA')
    rsa2 = _keyissuer_2.get('sig', 'RSA')

    assert len(rsa1) == 1
    assert len(rsa2) == 1
    assert rsa1[0] == rsa2[0]

    # keyissuer1 should only contain one EC key while keyissuer2 should contain 2.

    ec1 = _keyissuer_1.get('sig', 'EC')
    ec2 = _keyissuer_2.get('sig', 'EC', '')
    assert len(ec1) == 1
    assert len(ec2) == 2

    # The file on disc should not have changed
    _keyissuer_3 = init_key_issuer(private_path=PRIVATE_FILE)

    assert len(_keyissuer_3.get('sig', 'RSA')) == 1
    assert len(_keyissuer_3.get('sig', 'EC')) == 1

    _keyissuer_4 = init_key_issuer(private_path=PRIVATE_FILE, key_defs=KEYSPEC_2,
                                   public_path=PUBLIC_FILE, read_only=False)

    # Now it should
    _keyissuer_5 = init_key_issuer(private_path=PRIVATE_FILE)

    assert len(_keyissuer_5.get('sig', 'RSA')) == 1
    assert len(_keyissuer_5.get('sig', 'EC')) == 2


OIDC_KEYS = {
    'private_path': "{}/priv/jwks.json".format(BASEDIR),
    'key_defs': KEYSPEC,
    'public_path': '{}/public/jwks.json'.format(BASEDIR)
}


def test_init_key_issuer_create_directories():
    # make sure the directories are gone
    for _dir in ['priv', 'public']:
        if os.path.isdir("{}/{}".format(BASEDIR, _dir)):
            shutil.rmtree("{}/{}".format(BASEDIR, _dir))

    _keyissuer = init_key_issuer(**OIDC_KEYS)
    assert len(_keyissuer.get('sig', 'RSA')) == 1
    assert len(_keyissuer.get('sig', 'EC')) == 1


OIDC_PUB_KEYS = {
    'key_defs': KEYSPEC,
    'public_path': '{}/public/jwks.json'.format(BASEDIR),
    'read_only': False
}


def test_init_key_issuer_public_key_only():
    # make sure the directories are gone
    for _dir in ['public']:
        if os.path.isdir("{}/{}".format(BASEDIR, _dir)):
            shutil.rmtree("{}/{}".format(BASEDIR, _dir))

    _keyissuer = init_key_issuer(**OIDC_PUB_KEYS)
    assert len(_keyissuer.get('sig', 'RSA')) == 1
    assert len(_keyissuer.get('sig', 'EC')) == 1

    _keyissuer2 = init_key_issuer(**OIDC_PUB_KEYS)
    assert len(_keyissuer2.get('sig', 'RSA')) == 1
    assert len(_keyissuer2.get('sig', 'EC')) == 1


OIDC_PUB_KEYS2 = {
    'key_defs': KEYSPEC_3,
    'public_path': '{}/public/jwks.json'.format(BASEDIR),
    'read_only': False
}


def test_init_key_issuer_public_key_only_with_diff():
    # make sure the directories are gone
    for _dir in ['public']:
        if os.path.isdir("{}/{}".format(BASEDIR, _dir)):
            shutil.rmtree("{}/{}".format(BASEDIR, _dir))

    _keyissuer = init_key_issuer(**OIDC_PUB_KEYS)
    assert len(_keyissuer.get('sig', 'RSA')) == 1
    assert len(_keyissuer.get('sig', 'EC')) == 1

    _keyissuer2 = init_key_issuer(**OIDC_PUB_KEYS2)
    assert len(_keyissuer2.get('sig', 'RSA')) == 1
    assert len(_keyissuer2.get('sig', 'EC')) == 3


def test_dump():
    issuer = KeyIssuer()
    issuer.add_kb(KeyBundle(JWK2['keys']))

    res = issuer.dump()

    nkj = KeyIssuer().load(res)
    assert nkj.get('sig', 'rsa', kid="kriMPdmBvx68skT8-mPAB3BseeA")
    assert nkj.get('sig', 'rsa', kid='MnC_VZcATfM5pOYiJHMba9goEKY')


def test_contains():
    issuer = KeyIssuer()
    issuer.add_kb(KeyBundle(JWK1['keys']))
    for k in issuer.all_keys():
        assert k in issuer


def test_missing_url():
    issuer = KeyIssuer()
    with pytest.raises(KeyError):
        issuer.add_url('')


def test_localhost_url():
    issuer = KeyIssuer(httpc_params={'verify': True})
    url = 'http://localhost/jwks.json'
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=url, json=JWK2, status=200)
        issuer.add_url(url)

    kb = issuer.find(url)
    assert len(kb) == 1
    assert kb[0].httpc_params == {'verify': False}


def test_add_url():
    issuer = KeyIssuer(httpc_params={'verify': True})
    url = 'http://localhost/jwks.json'
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=url, json=JWK2, status=200)
        issuer.add(url)

    kb = issuer.find(url)
    assert len(kb) == 1
    assert kb[0].source == url


def test_add_symmetric():
    issuer = KeyIssuer()
    issuer.add('LongRamblingKeyThatShouldBeLongEnough')
    kb = issuer.find(None)
    assert len(kb) == 1
    assert kb[0].keys()[0].kty == 'oct'


def test_not_in():
    issuer = KeyIssuer()
    _jwk = SYMKey(key='LongRamblingKeyThatShouldBeLongEnough')
    assert _jwk not in issuer


def test_str():
    issuer = KeyIssuer(name='foo')
    issuer.add('LongRamblingKeyThatShouldBeLongEnough')
    assert str(issuer).startswith('<KeyIssuer "foo" oct::')


def test_items():
    issuer = KeyIssuer(name='foo')
    url = 'http://localhost/jwks.json'
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=url, json=JWK2, status=200)
        issuer.add(url)

    issuer.add('LongRamblingKeyThatShouldBeLongEnough')

    items = issuer.items()
    assert set(items.keys()) == {None, url}
    assert items[None][0].keys()[0].kty == 'oct'
    assert len(items[url][0].keys()) == 4


def test_load_keys_uri():
    issuer = KeyIssuer(httpc_params={'verify': True})
    url = 'http://localhost/jwks.json'
    with responses.RequestsMock() as rsps:
        rsps.add(method="GET", url=url, json=JWK2, status=200)
        issuer.load_keys(jwks_uri=url)

    kb = issuer.find(url)
    assert len(kb) == 1
    assert kb[0].source == url


def test_load_keys():
    issuer = KeyIssuer(httpc_params={'verify': True})
    issuer.load_keys(jwks=JWK2)

    items = issuer.items()
    assert len(items[None][0].keys()) == 4


def test_ec_alg():
    kb = KeyBundle(source=os.path.join(BASE_PATH, 'ec-p256.json'), keyusage='sig')
    issuer = KeyIssuer()
    issuer.add_kb(kb)
    k = issuer.get(key_use='sig', key_type='ec', alg='P-384')
    assert k == []
    k = issuer.get(key_use='sig', key_type='ec', alg='P-256')
    assert len(k) == 1
