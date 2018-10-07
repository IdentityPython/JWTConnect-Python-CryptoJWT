# pylint: disable=missing-docstring,no-self-use
import json
import os
import pytest
import shutil
import time

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptojwt.jwk.ec import new_ec_key

from cryptojwt.jwk.rsa import RSAKey, new_rsa_key, import_rsa_key_from_cert_file
from cryptojwt.jwk.hmac import SYMKey

from cryptojwt.key_bundle import dump_jwks
from cryptojwt.key_bundle import rsa_init
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_bundle import KeyBundle

__author__ = 'Roland Hedberg'

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "test_keys"))

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


RSAKEY = os.path.join(BASE_PATH, "cert.key")
RSA0 = os.path.join(BASE_PATH, "rsa.key")
CERT = full_path("cert.pem")

JWK0 = {"keys": [
    {'kty': 'RSA', 'e': 'AQAB', 'kid': "abc",
     'n':
         'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY'
         '2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfK'
         'qoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8'}
]}

JWK1 = {"keys": [
    {
        "n":
            'zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S'
            '_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFY'
            'Inq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVb'
            'CGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znan'
            'LwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MX'
            'sGxBHf3AKT5w',
        "e": "AQAB", "kty": "RSA", "kid": "rsa1"},
    {
        "k":
            'YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNT'
            'Y0NzMzYjE',
        "kty": "oct"},
]}

JWK2 = {
    "keys": [
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "kriMPdmBvx68skT8-mPAB3BseeA",
            "kty": "RSA",
            "n":
                'kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS'
                '_AHsBeQPqYygfYVJL6_EgzVuwRk5txr9e3n1uml94fLyq_AXbwo9yAduf4dCHT'
                'P8CWR1dnDR-Qnz_4PYlWVEuuHHONOw_blbfdMjhY-C_BYM2E3pRxbohBb3x__C'
                'fueV7ddz2LYiH3wjz0QS_7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd_'
                'GTgWN8A-6SN1r4hzpjFKFLbZnBt77ACSiYx-IHK4Mp-NaVEi5wQtSsjQtI--Xs'
                'okxRDqYLwus1I1SihgbV_STTg5enufuw',
            "use": "sig",
            "x5c": [
                'MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKz'
                'ApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcN'
                'MTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW'
                '50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEF'
                'AAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs'
                '5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94f'
                'Lyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C'
                '/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHF'
                'i3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp'
                '+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2Iw'
                'YDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYW'
                'Njb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49Y'
                'D0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDb'
                'dNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajy'
                'vlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5Uqn'
                'I7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF4'
                '6aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODY'
                'RMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ'
            ],
            "x5t": "kriMPdmBvx68skT8-mPAB3BseeA"
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "MnC_VZcATfM5pOYiJHMba9goEKY",
            "kty": "RSA",
            "n":
                'vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhz'
                'h23V9Tkq-RtwN1Vs_z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuz'
                'QoW9vFb1k3cR1RW_EW_P-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5y'
                'Cw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_K'
                'AS_qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3-T-IAbsk1wRtWDn'
                'dhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ',
            "use": "sig",
            "x5c": [
                "MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb"
                "250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZX"
                "NzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUO"
                "qwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy"
                "/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW"
                "9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU"
                "/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg"
                "0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX"
                "14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNG"
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
                "ljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx7HNcD9ZxTFRaAgZ7+gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQ"
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

if os.path.isdir('keys'):
    shutil.rmtree('keys')


def test_with_sym_key():
    kc = KeyBundle({"kty": "oct", "key": "highestsupersecret", "use": "sig"})
    assert len(kc.get("oct")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None


def test_with_2_sym_key():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    assert len(kb.get("oct")) == 2
    assert len(kb) == 2

    assert kb.get_key_with_kid('kid') is None
    assert kb.kids() == []


def test_remove_sym():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    assert len(kb) == 2
    keys = kb.get('oct')
    kb.remove(keys[0])
    assert len(kb) == 1


def test_remove_key_sym():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    assert len(kb) == 2
    keys = kb.get('oct')
    kb.remove(keys[0])
    assert len(kb) == 1

    # This should not work
    kb.remove_keys_by_type('rsa')
    # should still be one
    assert len(kb) == 1


def test_rsa_init():
    kb = rsa_init(
        {'use': ['enc', 'sig'], 'size': 1024, 'name': 'rsa', 'path': 'keys'})
    assert kb
    assert len(kb) == 2
    assert len(kb.get('rsa')) == 2


def test_rsa_init_under_spec():
    kb = rsa_init(
        {'use': ['enc', 'sig'], 'size': 1024})
    assert kb
    assert len(kb) == 2
    assert len(kb.get('rsa')) == 2


def test_unknown_source():
    with pytest.raises(ImportError):
        kb = KeyBundle(source='foobar')


def test_ignore_unknown_types():
    kb = KeyBundle({
            "kid": "q-H9y8iuh3BIKZBbK6S0mH_isBlJsk"
                   "-u6VtZ5rAdBo5fCjjy3LnkrsoK_QWrlKB08j_PcvwpAMfTEDHw5spepw",
            "use": "sig",
            "alg": "EdDSA",
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "FnbcUAXZ4ySvrmdXK1MrDuiqlqTXvGdAaE4RWZjmFIQ"
        })

    assert len(kb) == 0


def test_remove_rsa():
    kb = rsa_init(
        {'use': ['enc', 'sig'], 'size': 1024, 'name': 'rsa', 'path': 'keys'})
    assert len(kb) == 2
    keys = kb.get('rsa')
    assert len(keys) == 2
    kb.remove(keys[0])
    assert len(kb) == 1


def test_key_mix():
    kb = rsa_init(
        {'use': ['enc', 'sig'], 'size': 1024, 'name': 'rsa', 'path': 'keys'})
    _sym = SYMKey(**{"kty": "oct", "key": "highestsupersecret", "use": "enc"})
    kb.append(_sym)
    assert len(kb) == 3
    assert len(kb.get('rsa')) == 2
    assert len(kb.get('oct')) == 1

    kb.remove(_sym)

    assert len(kb) == 2
    assert len(kb.get('rsa')) == 2
    assert len(kb.get('oct')) == 0


def test_get_all():
    kb = rsa_init(
        {'use': ['enc', 'sig'], 'size': 1024, 'name': 'rsa', 'path': 'keys'})
    _sym = SYMKey(**{"kty": "oct", "key": "highestsupersecret", "use": "enc"})
    kb.append(_sym)
    assert len(kb.get()) == 3

    _k = kb.keys()
    assert len(_k) == 3


def test_keybundle_from_local_der():
    kb = keybundle_from_local_file(
        "{}".format(os.path.join(BASE_PATH, 'rsa.key')),
        "der", ['enc'])
    assert len(kb) == 1
    keys = kb.get('rsa')
    assert len(keys) == 1
    assert isinstance(keys[0], RSAKey)


def test_keybundle_from_local_der_update():
    kb = keybundle_from_local_file(
        "file://{}".format(os.path.join(BASE_PATH, 'rsa.key')),
        "der", ['enc'])
    assert len(kb) == 1
    keys = kb.get('rsa')
    assert len(keys) == 1
    assert isinstance(keys[0], RSAKey)

    kb.update()

    # Nothing should change
    assert len(kb) == 1
    keys = kb.get('rsa')
    assert len(keys) == 1
    assert isinstance(keys[0], RSAKey)


def test_creat_jwks_sym():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([a])
    _jwks = kb.jwks()
    _loc = json.loads(_jwks)
    assert list(_loc.keys()) == ["keys"]
    assert set(_loc['keys'][0].keys()) == {'kty', 'use', 'k'}


def test_keybundle_from_local_jwks_file():
    kb = keybundle_from_local_file(
        "file://{}".format(os.path.join(BASE_PATH, "jwk.json")), "jwks", ["sig"])
    assert len(kb) == 1


def test_keybundle_from_local_jwks():
    kb = keybundle_from_local_file(
        "{}".format(os.path.join(BASE_PATH, "jwk.json")), "jwks", ["sig"])
    assert len(kb) == 1


def test_update():
    kc = KeyBundle([{"kty": "oct", "key": "highestsupersecret", "use": "sig"}])
    assert len(kc.get("oct")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None

    kc.update()  # Nothing should happen
    assert len(kc.get("oct")) == 1
    assert len(kc.get("rsa")) == 0
    assert kc.remote is False
    assert kc.source is None


def test_update_RSA():
    kc = keybundle_from_local_file(RSAKEY, "der", ["sig"])
    assert kc.remote is False
    assert len(kc.get("oct")) == 0
    assert len(kc.get("RSA")) == 1

    key = kc.get("RSA")[0]
    assert isinstance(key, RSAKey)

    kc.update()
    assert kc.remote is False
    assert len(kc.get("oct")) == 0
    assert len(kc.get("RSA")) == 1

    key = kc.get("RSA")[0]
    assert isinstance(key, RSAKey)


def test_outdated():
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb = KeyBundle([a, b])
    keys = kb.keys()
    now = time.time()
    keys[0].inactive_since = now - 60
    kb.remove_outdated(30)
    assert len(kb) == 1


def test_dump_jwks():
    kb1 = rsa_init(
        {'use': ['enc', 'sig'], 'size': 1024, 'name': 'rsa', 'path': 'keys'})
    a = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    b = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb2 = KeyBundle([a, b])
    dump_jwks([kb1, kb2], 'jwks_combo')

    # Now read it

    nkb = KeyBundle(source='file://jwks_combo', fileformat='jwks')

    assert len(nkb) == 2
    # both RSA keys
    assert len(nkb.get('rsa')) == 2


def test_mark_as_inactive():
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([desc])
    assert len(kb.keys()) == 1
    for k in kb.keys():
        kb.mark_as_inactive(k.kid)
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb.do_keys([desc])
    assert len(kb.keys()) == 2
    assert len(kb.active_keys()) == 1


def test_copy():
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "sig"}
    kb = KeyBundle([desc])
    assert len(kb.keys()) == 1
    for k in kb.keys():
        kb.mark_as_inactive(k.kid)
    desc = {"kty": "oct", "key": "highestsupersecret", "use": "enc"}
    kb.do_keys([desc])

    kbc = kb.copy()
    assert len(kbc.keys()) == 2
    assert len(kbc.active_keys()) == 1


def test_local_jwk():
    _path = full_path('jwk_private_key.json')
    kb = KeyBundle(source='file://{}'.format(_path))
    assert kb


def test_local_jwk_copy():
    _path = full_path('jwk_private_key.json')
    kb = KeyBundle(source='file://{}'.format(_path))
    kb2 = kb.copy()
    assert kb2.source == kb.source


def test_remote(httpserver):
    httpserver.serve_content(json.dumps(JWK1))
    kb = KeyBundle(source=httpserver.url)
    assert len(kb.keys())
    assert len(kb.get('rsa')) == 1
    assert len(kb.get('oct')) == 1


def test_update_2():
    rsa_key = new_rsa_key()
    _jwks = {"keys": [rsa_key.serialize()]}
    fname = 'tmp_jwks.json'
    with open(fname, 'w') as fp:
        fp.write(json.dumps(_jwks))

    kb = KeyBundle(source="file://{}".format(fname), fileformat='jwks')
    assert len(kb) == 1

    # Added one more key
    ec_key = new_ec_key(crv='P-256')
    _jwks = {'keys': [rsa_key.serialize(), ec_key.serialize()]}

    with open(fname, 'w') as fp:
        fp.write(json.dumps(_jwks))

    kb.update()
    assert len(kb) == 2


def test_update_mark_inactive():
    rsa_key = new_rsa_key()
    _jwks = {"keys": [rsa_key.serialize()]}
    fname = 'tmp_jwks.json'
    with open(fname, 'w') as fp:
        fp.write(json.dumps(_jwks))

    kb = KeyBundle(source="file://{}".format(fname), fileformat='jwks')
    assert len(kb) == 1

    # new set of keys
    rsa_key = new_rsa_key()
    ec_key = new_ec_key(crv='P-256')
    _jwks = {'keys': [rsa_key.serialize(), ec_key.serialize()]}

    with open(fname, 'w') as fp:
        fp.write(json.dumps(_jwks))

    kb.update()
    # 2 active and 1 inactive
    assert len(kb) == 3
    assert len(kb.active_keys()) == 2

    assert len(kb.get('rsa')) == 1
    assert len(kb.get('rsa', only_active=False)) == 2


def test_loads_0():
    kb = KeyBundle(JWK0)
    assert len(kb) == 1
    key = kb.get("rsa")[0]
    assert key.kid == 'abc'
    assert key.kty == 'RSA'


def test_loads_1():
    jwks = {
        "keys": [
            {
                'kty': 'RSA',
                'use': 'sig',
                'e': 'AQAB',
                "n": 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8',
                'kid': "1"
            }, {
                'kty': 'RSA',
                'use': 'enc',
                'e': 'AQAB',
                "n": 'wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtVzeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6Jtu82nB5k8',
                'kid': "2"
            }
        ]
    }

    kb = KeyBundle(jwks)

    assert len(kb) == 2
    assert set(kb.kids()) == {'1', '2'}


def test_dump_jwk():
    kb = KeyBundle()
    kb.append(RSAKey(pub_key=import_rsa_key_from_cert_file(CERT)))
    jwks = kb.jwks()

    _wk = json.loads(jwks)
    assert list(_wk.keys()) == ["keys"]
    assert len(_wk["keys"]) == 1
    assert set(_wk["keys"][0].keys()) == {"kty", "e", "n"}

    kb2 = KeyBundle(_wk)

    assert len(kb2) == 1
    key = kb2.get("rsa")[0]
    assert key.kty == 'RSA'
    assert isinstance(key.public_key(), rsa.RSAPublicKey)

JWKS_DICT = {"keys": [
    {
        "n": u"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": u"AQAB",
        "kty": "RSA",
        "kid": "5-VBFv40P8D4I-7SFz7hMugTbPs",
        "use": "enc"
    },
    {
        "k": u"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "enc"
    },
    {
        "kty": "EC",
        "kid": "7snis",
        "use": "sig",
        "x": u'q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po',
        "y": u'GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E',
        "crv": "P-256"
    }
]}


def test_keys():
    kb = KeyBundle(JWKS_DICT)

    assert len(kb) == 3

    assert len(kb.get('rsa')) == 1
    assert len(kb.get('oct')) == 1
    assert len(kb.get('ec')) == 1


EXPECTED = [
    b'iA7PvG_DfJIeeqQcuXFmvUGjqBkda8In_uMpZrcodVA',
    b'kLsuyGef1kfw5-t-N9CJLIHx_dpZ79-KemwqjwdrvTI',
    b'8w34j9PLyCVC7VOZZb1tFVf0MOa2KZoy87lICMeD5w8',
    b'nKzalL5pJOtVAdCtBAU8giNRNimE-XbylWZ4vq6ZlF8'
]


def test_thumbprint():
    kb = KeyBundle(JWKS_DICT)
    for key in kb:
        txt = key.thumbprint('SHA-256')
        assert txt in EXPECTED


@pytest.mark.network
def test_jwks_url():
    keys = KeyBundle(source='https://login.salesforce.com/id/keys')
    # Forces read from the network
    keys.update()
    assert len(keys)

