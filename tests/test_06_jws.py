import json
import os.path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from cryptojwt import as_unicode
from cryptojwt.exception import BadSignature, UnknownAlgorithm, WrongNumberOfParts
from cryptojwt.jwk.ec import ECKey
from cryptojwt.jwk.hmac import SYMKey
from cryptojwt.jwk.okp import OKPKey
from cryptojwt.jwk.rsa import RSAKey, import_private_rsa_key_from_file
from cryptojwt.jws.exception import FormatError, NoSuitableSigningKeys, SignerAlgError
from cryptojwt.jws.jws import JWS, SIGNER_ALGS, JWSig, factory
from cryptojwt.jws.rsa import RSASigner
from cryptojwt.jws.utils import left_hash, parse_rsa_algorithm
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.utils import (
    as_bytes,
    b64d,
    b64d_enc_dec,
    b64e,
    intarr2bin,
    is_compact_jws,
    is_json_jws,
)

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)


PRIV_KEY = full_path("server.key")

JWK_a = {
    "keys": [
        {
            "alg": "RSA",
            "use": "foo",
            "e": "AQAB",
            "n": (
                "wf-wiusGhA-gleZYQAOPQlNUIucPiqXdPVyieDqQbXXOPBe3nuggtV"
                "zeq7pVFH1dZz4dY2Q2LA5DaegvP8kRvoSB_87ds3dy3Rfym_GUSc5B"
                "0l1TgEobcyaep8jguRoHto6GWHfCfKqoUYZq4N8vh4LLMQwLR6zi6J"
                "tu82nB5k8"
            ),
        }
    ]
}

# 64*8 = 256 bits
HMAC_KEY = [
    3,
    35,
    53,
    75,
    43,
    15,
    165,
    188,
    131,
    126,
    6,
    101,
    119,
    123,
    166,
    143,
    90,
    179,
    40,
    230,
    240,
    84,
    201,
    40,
    169,
    15,
    132,
    178,
    210,
    80,
    46,
    191,
    211,
    251,
    90,
    146,
    210,
    6,
    71,
    239,
    150,
    138,
    180,
    195,
    119,
    98,
    61,
    34,
    61,
    46,
    33,
    114,
    5,
    46,
    79,
    8,
    192,
    205,
    154,
    245,
    103,
    208,
    128,
    163,
]

JWKS_a = {
    "keys": [
        {
            "e": "AQAB",
            "kty": "RSA",
            "alg": "RSA256",
            "n": "qYJqXTXsDroPYyQBBmSolK3bJtrSerEm"
            "-nrmbSpfn8Rz3y3oXLydvUqj8869PkcEzoJIY5Xf7xDN1Co_qyT9qge"
            "-3C6DEwGVHXOwRoXRGQ_h50Vsh60MB5MIuDN188EeZnQ30dtCTBB9KDTSEA2DunplhwLCq4xphnMNUaeHdEk",
            "kid": "rsa1",
        },
        {
            "k": b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct",
        },
    ]
}

JWKS_b = {
    "keys": [
        {
            "n": b"zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
            "e": b"AQAB",
            "kty": "RSA",
            "kid": "rsa1",
            "use": "sig",
        },
        {
            "k": b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
            "kty": "oct",
            "use": "sig",
        },
        {
            "kty": "EC",
            "kid": "ec1",
            "use": "sig",
            "x": "q0WbWhflRbxyQZKFuQvh2nZvg98ak-twRoO5uo2L7Po",
            "y": "GOd2jL_6wa0cfnyA0SmEhok9fkYEnAHFKLLM79BZ8_E",
            "crv": "P-256",
        },
    ]
}

JWK_b = {
    "keys": [
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "kriMPdmBvx68skT8-mPAB3BseeA",
            "kty": "RSA",
            "n": "kSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS_AHsBeQPqYygfYVJL6_EgzVuwRk5txr9e3n1uml94fLyq_AXbwo9yAduf4dCHTP8CWR1dnDR-Qnz_4PYlWVEuuHHONOw_blbfdMjhY-C_BYM2E3pRxbohBb3x__CfueV7ddz2LYiH3wjz0QS_7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd_GTgWN8A-6SN1r4hzpjFKFLbZnBt77ACSiYx-IHK4Mp-NaVEi5wQtSsjQtI--XsokxRDqYLwus1I1SihgbV_STTg5enufuw",
            "use": "sig",
            "x5c": [
                "MIIDPjCCAiqgAwIBAgIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTQwMTAxMDcwMDAwWhcNMTYwMTAxMDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkSCWg6q9iYxvJE2NIhSyOiKvqoWCO2GFipgH0sTSAs5FalHQosk9ZNTztX0ywS/AHsBeQPqYygfYVJL6/EgzVuwRk5txr9e3n1uml94fLyq/AXbwo9yAduf4dCHTP8CWR1dnDR+Qnz/4PYlWVEuuHHONOw/blbfdMjhY+C/BYM2E3pRxbohBb3x//CfueV7ddz2LYiH3wjz0QS/7kjPiNCsXcNyKQEOTkbHFi3mu0u13SQwNddhcynd/GTgWN8A+6SN1r4hzpjFKFLbZnBt77ACSiYx+IHK4Mp+NaVEi5wQtSsjQtI++XsokxRDqYLwus1I1SihgbV/STTg5enufuwIDAQABo2IwYDBeBgNVHQEEVzBVgBDLebM6bK3BjWGqIBrBNFeNoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQsRiM0jheFZhKk49YD0SK1TAJBgUrDgMCHQUAA4IBAQCJ4JApryF77EKC4zF5bUaBLQHQ1PNtA1uMDbdNVGKCmSf8M65b8h0NwlIjGGGy/unK8P6jWFdm5IlZ0YPTOgzcRZguXDPj7ajyvlVEQ2K2ICvTYiRQqrOhEhZMSSZsTKXFVwNfW6ADDkN3bvVOVbtpty+nBY5UqnI7xbcoHLZ4wYD251uj5+lo13YLnsVrmQ16NCBYq2nQFNPuNJw6t3XUbwBHXpF46aLT1/eGf/7Xx6iy8yPJX4DyrpFTutDz882RWofGEO5t4Cw+zZg70dJ/hH/ODYRMorfXEW+8uKmXMKmX2wyxMKvfiPbTy5LmAU8Jvjs2tLg4rOBcXWLAIarZ"
            ],
            "x5t": "kriMPdmBvx68skT8-mPAB3BseeA",
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0/",
            "kid": "MnC_VZcATfM5pOYiJHMba9goEKY",
            "kty": "RSA",
            "n": "vIqz-4-ER_vNWLON9yv8hIYV737JQ6rCl6XfzOC628seYUPf0TaGk91CFxefhzh23V9Tkq"
            "-RtwN1Vs_z57hO82kkzL-cQHZX3bMJD-GEGOKXCEXURN7VMyZWMAuzQoW9vFb1k3cR1RW_EW_P"
            "-C8bb2dCGXhBYqPfHyimvz2WarXhntPSbM5XyS5v5yCw5T_Vuwqqsio3V8wooWGMpp61y12NhN8bNVDQAkDPNu2DT9DXB1g0CeFINp_KAS_qQ2Kq6TSvRHJqxRR68RezYtje9KAqwqx4jxlmVAQy0T3-T-IAbsk1wRtWDndhO6s1Os-dck5TzyZ_dNOhfXgelixLUQ",
            "use": "sig",
            "x5c": [
                "MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdYNAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7JNcEbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaYxNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmRqWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBDYRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ=="
            ],
            "x5t": "MnC_VZcATfM5pOYiJHMba9goEKY",
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
                "MIICWzCCAcSgAwIBAgIJAKVzMH2FfC12MA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xMzExMTExODMzMDhaFw0xNjExMTAxODMzMDhaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA5ymq/xwmst1nstPr8YFOTyD1J5N4idYmrph7AyAv95RbWXfDRqy8CMRG7sJq+UWOKVOA4MVrd/NdV+ejj1DE5MPSiG+mZK/5iqRCDFvPYqOyRj539xaTlARNY4jeXZ0N6irZYKqSfYACjkkKxbLKcijSu1pJ48thXOTED0oNa6UCAwEAAaOBijCBhzAdBgNVHQ4EFgQURCN+4cb0pvkykJCUmpjyfUfnRMowWQYDVR0jBFIwUIAURCN+4cb0pvkykJCUmpjyfUfnRMqhLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAKVzMH2FfC12MAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQB8v8G5/vUl8k7xVuTmMTDA878AcBKBrJ/Hp6RShmdqEGVI7SFR7IlBN1//NwD0n+IqzmnRV2PPZ7iRgMF/Fyvqi96Gd8X53ds/FaiQpZjUUtcO3fk0hDRQPtCYMII5jq+YAYjSybvF84saB7HGtucVRn2nMZc5cAC42QNYIlPMqA=="
            ],
            "x5t": "GvnPApfWMdLRi8PDmisFn7bprKg",
        },
        {
            "e": "AQAB",
            "issuer": "https://login.microsoftonline.com/9188040d-6c67-4c5b"
            "-b112-36a304b66dad/v2.0/",
            "kid": "dEtpjbEvbhfgwUI-bdK5xAU_9UQ",
            "kty": "RSA",
            "n": "x7HNcD9ZxTFRaAgZ7-gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQeSML7qZPlowb5BUakdLI70ayM4vN36--0ht8-oCHhl8YjGFQkU-Iv2yahWHEP-1EK6eOEYu6INQP9Lk0HMk3QViLwshwb-KXVD02jdmX2HNdYJdPyc0c",
            "use": "sig",
            "x5c": [
                "MIICWzCCAcSgAwIBAgIJAL3MzqqEFMYjMA0GCSqGSIb3DQEBBQUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0xMzExMTExOTA1MDJaFw0xOTExMTAxOTA1MDJaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAx7HNcD9ZxTFRaAgZ7+gdYLkgQua3zvQseqBJIt8Uq3MimInMZoE9QGQeSML7qZPlowb5BUakdLI70ayM4vN36++0ht8+oCHhl8YjGFQkU+Iv2yahWHEP+1EK6eOEYu6INQP9Lk0HMk3QViLwshwb+KXVD02jdmX2HNdYJdPyc0cCAwEAAaOBijCBhzAdBgNVHQ4EFgQULR0aj9AtiNMgqIY8ZyXZGsHcJ5gwWQYDVR0jBFIwUIAULR0aj9AtiNMgqIY8ZyXZGsHcJ5ihLaQrMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleYIJAL3MzqqEFMYjMAsGA1UdDwQEAwIBxjANBgkqhkiG9w0BAQUFAAOBgQBshrsF9yls4ArxOKqXdQPDgHrbynZL8m1iinLI4TeSfmTCDevXVBJrQ6SgDkihl3aCj74IEte2MWN78sHvLLTWTAkiQSlGf1Zb0durw+OvlunQ2AKbK79Qv0Q+wwGuK+oymWc3GSdP1wZqk9dhrQxb3FtdU2tMke01QTut6wr7ig=="
            ],
            "x5t": "dEtpjbEvbhfgwUI-bdK5xAU_9UQ",
        },
    ]
}

JWKS_WITH_USE = {
    "keys": [
        {
            "e": "AQAB",
            "kid": "R3NJRW1EVHRsaUcwSXVydi14cVVoTmxhaU4zckU1MlFPa05NWGNpUUZtcw",
            "kty": "RSA",
            "n": "rp7aJD9FKKHQgLTeXLMyjB5TS51x_KqA15gBJHF2Ps-rrmcBujpMAi39D7w4"
            "SArr9X7DPgHekTPRV6-i46TyqnY1EXPGRb0nCg0rCmkyOAMysXhhuexu3vS7"
            "Fa2YPvX2zpl5svdkOOwLmHBplCTtvScz-L7N1xeknauOLF5Ct39C5Ipv-BWx"
            "bNrqD68uIPSOH9ZsoGKVArSI0MSmw5LB7B3i30D8FvmlJyxcEPZOFVahFCmS"
            "qqUXHuXV2Z0BpvgvDhzB5cSNO12clwD_fZ4CnbvuvfbBAgpVg774smz2z3ov"
            "6SsZ6ZD5Tc_9gE2ryLW6x0RS1y2KSME8EUI2sdJYZw",
            "x5c": [
                "MIIDOjCCAiKgAwIBAgIUJACZrVNr3gHJrde3OkQwy1lXL6owDQYJKoZIhvcN"
                "AQELBQAwSjELMAkGA1UEBhMCU0UxDjAMBgNVBAcMBVVtZcOlMRgwFgYDVQQK"
                "DA9JZGVudGl0eSBQeXRob24xETAPBgNVBAMMCGlkcHkub3JnMB4XDTIxMTEw"
                "MjA5MzIzOFoXDTIxMTExMjA5MzIzOFowSjELMAkGA1UEBhMCU0UxDjAMBgNV"
                "BAcMBVVtZcOlMRgwFgYDVQQKDA9JZGVudGl0eSBQeXRob24xETAPBgNVBAMM"
                "CGlkcHkub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArp7a"
                "JD9FKKHQgLTeXLMyjB5TS51x/KqA15gBJHF2Ps+rrmcBujpMAi39D7w4SArr"
                "9X7DPgHekTPRV6+i46TyqnY1EXPGRb0nCg0rCmkyOAMysXhhuexu3vS7Fa2Y"
                "PvX2zpl5svdkOOwLmHBplCTtvScz+L7N1xeknauOLF5Ct39C5Ipv+BWxbNrq"
                "D68uIPSOH9ZsoGKVArSI0MSmw5LB7B3i30D8FvmlJyxcEPZOFVahFCmSqqUX"
                "HuXV2Z0BpvgvDhzB5cSNO12clwD/fZ4CnbvuvfbBAgpVg774smz2z3ov6SsZ"
                "6ZD5Tc/9gE2ryLW6x0RS1y2KSME8EUI2sdJYZwIDAQABoxgwFjAUBgNVHREE"
                "DTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEBAARJIf6TZrhGjI/g"
                "QnvOybc6o3lv4nPCJojRoHjFtTd9uk9Eve4Ba7NG8goCs9l3Cq4tPUpqfW42"
                "iSr+1Vd9O+cozJAa6PVGwTCfHrtBvQWgM9gk+09lmP8kO73KBcmK9lcwYThJ"
                "NNVmZgEwV37hP6sUmyfmuAsxgePPSQqahCej1ORN9YGSH2aeXw+1rhyfTZ6c"
                "Kl791b+6So8bDEhfQcFmwNJ/75tr++dRnEdPfSLfid13PFT0W6uxQqeSpCh6"
                "TtRiqTb47SIKKnG4YPta2eVOnMNOvy2Lw4nl95V7RSvVw6VbPOx9XXYaONdm"
                "mSpbgK1tK1XMkhrp95sU3q1OS8I="
            ],
            "x5t": "ScM0uv4bxGMJ7bbrc1scc_uOyLI",
            "use": ["sig"],
        },
        {
            "e": "AQAB",
            "kid": "d1Z6RTJHQmh0NnBaeHpfYVd0U1dIb25fUTQ1aVhjNXFhWHEyTE4wbVh5bw",
            "kty": "RSA",
            "n": "zpQAmVzABLrRWV6HiBVbFeho_KhQhm8T_r6LvGP-Znnewpr6J7lBYD9gfVJo2_"
            "lOpCqitJvoMJoZxoULJ1xU_Am4padc-as8Sk9vb3FkvxoDrZFByNgmbrNTJCco"
            "wUBLTgb1wWde1CPNmr_U_-VBODOy17uTrt7DNEMqEwUi3Qb76J8duHVQT0ECcw"
            "crGXbsfV74jSaBAehHxlTt4tG4-LVC9I0IFs9bBykdZVh59uwtaKTlBNuC5frt"
            "kGyn_2TM1zCWSVparxqQ_T3e_g2NOr3v5fW_gjDsYZ2543DrE8ta_OCyrqw4wz"
            "fBEOb6raI6wCyqFQ5My1bz-qVTap-4hQ",
            "x5c": [
                "MIIDPjCCAiagAwIBAgIUB70yEjwKX+/dUw4YvP61BKpDHJQwDQYJKoZIhvcNAQ"
                "ELBQAwTDELMAkGA1UEBhMCVVMxEDAOBgNVBAcMB1NlYXR0bGUxGDAWBgNVBAoM"
                "D0lkZW50aXR5IFB5dGhvbjERMA8GA1UEAwwIaWRweS5vcmcwHhcNMjExMTAyMD"
                "kzMjM4WhcNMjExMTEyMDkzMjM4WjBMMQswCQYDVQQGEwJVUzEQMA4GA1UEBwwH"
                "U2VhdHRsZTEYMBYGA1UECgwPSWRlbnRpdHkgUHl0aG9uMREwDwYDVQQDDAhpZH"
                "B5Lm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM6UAJlcwAS6"
                "0Vleh4gVWxXoaPyoUIZvE/6+i7xj/mZ53sKa+ie5QWA/YH1SaNv5TqQqorSb6D"
                "CaGcaFCydcVPwJuKWnXPmrPEpPb29xZL8aA62RQcjYJm6zUyQnKMFAS04G9cFn"
                "XtQjzZq/1P/lQTgzste7k67ewzRDKhMFIt0G++ifHbh1UE9BAnMHKxl27H1e+I"
                "0mgQHoR8ZU7eLRuPi1QvSNCBbPWwcpHWVYefbsLWik5QTbguX67ZBsp/9kzNcw"
                "lklaWq8akP093v4NjTq97+X1v4Iw7GGdueNw6xPLWvzgsq6sOMM3wRDm+q2iOs"
                "AsqhUOTMtW8/qlU2qfuIUCAwEAAaMYMBYwFAYDVR0RBA0wC4IJbG9jYWxob3N0"
                "MA0GCSqGSIb3DQEBCwUAA4IBAQAyRDDxQcaNDP93SCmZaCnRgpQU8ZnrNk+QpF"
                "LPlzUM+CopC5KnJuqBX3C54/uQve54/YpNTbBGGYgqB07381L7z7hn9aNylyFf"
                "N9Ck51/lMnG2YYjdwDwhskfsekOA9H44N3GdxYhVuSrZDr+DuS8Sve26HRzh1Z"
                "r+1PqSanM7pTJngGFDor7Hn02mKwAYk2HduT7ulYXxzLBcDhgagGTT86P3Jmwm"
                "eM6PvsICMpP/6ewzRnsfJ+tmT/WXSS9IX1ZL/UxSEiNYPyJdls83stnjAxpS41"
                "IKNMtebp/78p/BGG5Tm+YUPES4h5YwBUsJi3ehhdzzQXjdqSF8xe2wjs6y"
            ],
            "x5t": "WlQYbhnE2ZQvZKF45tqK5Lwmt8k",
            "use": ["sig"],
        },
    ]
}

SIGJWKS = KeyBundle(JWKS_b)


def P256():
    return ec.generate_private_key(curve=ec.SECP256R1())


def test_1():
    claimset = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}

    _jws = JWS(claimset, cty="JWT", alg="none", typ="JWT")
    _jwt = _jws.sign_compact()

    _jr = JWS()
    _msg = _jr.verify_compact(_jwt, allow_none=True)
    print(_jr)
    assert _jr.jwt.headers["alg"] == "none"
    assert _jr.jwt.headers["typ"] == "JWT"
    assert _msg == claimset


def test_hmac_256():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=intarr2bin(HMAC_KEY))]
    _jws = JWS(payload, alg="HS256")
    _jwt = _jws.sign_compact(keys)

    info = JWS(alg="HS256").verify_compact(_jwt, keys)

    assert info == payload


def test_hmac_384():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=b"My hollow echo chamber", alg="HS384")]
    _jws = JWS(payload, alg="HS384")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS(alg="HS384")
    info = _rj.verify_compact(_jwt, keys)

    assert info == payload


def test_hmac_512():
    payload = "Please take a moment to register today"
    keys = [SYMKey(key=b"My hollow echo chamber", alg="HS512")]
    _jws = JWS(payload, alg="HS512")
    _jwt = _jws.sign_compact(keys)

    _rj = JWS(alg="HS512")
    info = _rj.verify_compact(_jwt, keys)
    assert info == payload


def test_hmac_from_keyrep():
    payload = "Please take a moment to register today"
    symkeys = [k for k in SIGJWKS if k.kty == "oct"]
    _jws = JWS(payload, alg="HS512")
    _jwt = _jws.sign_compact(symkeys)

    _rj = JWS(alg="HS512")
    info = _rj.verify_compact(_jwt, symkeys)
    assert info == payload


def test_left_hash_hs256():
    hsh = left_hash("Please take a moment to register today")
    assert hsh == "rCFHVJuxTqRxOsn2IUzgvA"


def test_left_hash_hs512():
    hsh = left_hash("Please take a moment to register today", "HS512")
    assert hsh == "_h6feWLt8zbYcOFnaBmekTzMJYEHdVTaXlDgJSWsEeY"


def test_rs256():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    skeys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS256")
    _jwt = _jws.sign_compact(skeys)

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = JWS(alg="RS256")
    info = _rj.verify_compact(_jwt, vkeys)

    assert info == payload


def test_rs384():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS384")
    _jwt = _jws.sign_compact(keys)

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = JWS(alg="RS384")
    info = _rj.verify_compact(_jwt, vkeys)
    assert info == payload


def test_rs512():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS512")
    _jwt = _jws.sign_compact(keys)

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = JWS(alg="RS512")
    info = _rj.verify_compact(_jwt, vkeys)
    assert info == payload


def test_a_1_1a():
    header = b'{"typ":"JWT",\r\n "alg":"HS256"}'
    val = b64e(header)
    assert val == b"eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"


def test_a_1_1b():
    payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    val = b64e(payload)
    assert val == (
        b"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9"
        b"leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    )


def test_a_1_1c():
    hmac = intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    header = b'{"typ":"JWT",\r\n "alg":"HS256"}'
    payload = b'{"iss":"joe",\r\n "exp":1300819380,\r\n "http://example.com/is_root":true}'
    sign_input = b64e(header) + b"." + b64e(payload)
    sig = signer.sign(sign_input, hmac)
    assert b64e(sig) == b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def test_a_1_3a():
    _jwt = (
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJle"
        "HAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnV"
        "lfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )

    # alg == '' means I'm fine with whatever I get
    jwt = JWSig(alg="").unpack(_jwt)
    assert jwt.valid()

    hmac = intarr2bin(HMAC_KEY)
    signer = SIGNER_ALGS["HS256"]
    signer.verify(jwt.sign_input(), jwt.signature(), hmac)


def test_a_1_3b():
    _jwt = (
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJl"
        "eHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0c"
        "nVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    keys = [SYMKey(key=intarr2bin(HMAC_KEY))]
    _jws2 = JWS(alg="")
    _jws2.verify_compact(_jwt, keys)


def test_jws_1():
    msg = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
    key = SYMKey(key=intarr2bin(HMAC_KEY))
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=key.serialize())
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS256")
    _jws2.verify_compact(res, keys=[key])
    assert _jws2.msg == msg


def test_jws_2():
    msg = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
    key = SYMKey(key=intarr2bin(HMAC_KEY))
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=key.serialize())
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS256")
    _jws2.verify_compact_verbose(res, keys=[key])
    assert _jws2.msg == msg
    assert _jws2.key == key


def test_jws_mm():
    msg = {"iss": "joe", "exp": 1300819380, "http://example.com/is_root": True}
    key = SYMKey(key=intarr2bin(HMAC_KEY))
    _jws = JWS(msg, cty="JWT", alg="HS256", jwk=key.serialize())
    res = _jws.sign_compact()

    _jws2 = JWS(alg="HS512")

    with pytest.raises(SignerAlgError):
        _jws2.verify_compact(res, keys=[key])


@pytest.mark.parametrize(
    "ec_func,alg",
    [
        (ec.SECP256R1, "ES256"),
        (ec.SECP384R1, "ES384"),
        (ec.SECP521R1, "ES512"),
        (ec.SECP256K1, "ES256K"),
    ],
)
def test_signer_es(ec_func, alg):
    payload = "Please take a moment to register today"
    eck = ec.generate_private_key(curve=ec_func())
    keys = [ECKey().load_key(eck)]
    _jws = JWS(payload, alg=alg)
    _jwt = _jws.sign_compact(keys)

    _pubkey = ECKey().load_key(eck.public_key())
    _rj = JWS(alg=alg)
    info = _rj.verify_compact(_jwt, [_pubkey])
    assert info == payload


def test_signer_es256_verbose():
    payload = "Please take a moment to register today"
    eck = ec.generate_private_key(curve=ec.SECP256R1())
    _key = ECKey().load_key(eck)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    _jwt = _jws.sign_compact(keys)

    _pubkey = ECKey().load_key(eck.public_key())
    _rj = JWS(alg="ES256")
    info = _rj.verify_compact_verbose(_jwt, [_pubkey])
    assert info["msg"] == payload
    assert info["key"] == _pubkey


def test_signer_ps256():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS256")
    _jwt = _jws.sign_compact(keys)

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = JWS(alg="PS256")
    info = _rj.verify_compact(_jwt, vkeys)
    assert info == payload


def test_signer_ps256_fail():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS256")
    _jwt = _jws.sign_compact(keys)[:-5] + "abcde"

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = JWS(alg="PS256")
    try:
        _rj.verify_compact(_jwt, vkeys)
    except BadSignature:
        pass
    else:
        raise AssertionError


def test_signer_ps384():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS384")
    _jwt = _jws.sign_compact(keys)

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = JWS(alg="PS384")
    info = _rj.verify_compact(_jwt, vkeys)
    assert info == payload


def test_signer_ps512():
    payload = "Please take a moment to register today"
    # Key has to be big enough  > 512+512+2
    _pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="PS512")
    _jwt = _jws.sign_compact(keys)

    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    _rj = factory(_jwt, alg="PS512")
    info = _rj.verify_compact(_jwt, vkeys)
    assert info == payload
    assert _rj.verify_alg("PS512")


def test_signer_eddsa():
    payload = "Please take a moment to register today"
    okp = ed25519.Ed25519PrivateKey.generate()
    _key = OKPKey().load_key(okp)
    keys = [_key]
    _jws = JWS(payload, alg="Ed25519")
    _jwt = _jws.sign_compact(keys)

    _pubkey = OKPKey().load_key(okp.public_key())
    _rj = JWS(alg="Ed25519")
    info = _rj.verify_compact(_jwt, [_pubkey])
    assert info == payload


def test_signer_eddsa_polymorphic():
    payload = "Please take a moment to register today"
    okp = ed25519.Ed25519PrivateKey.generate()
    _key = OKPKey().load_key(okp)
    keys = [_key]
    _jws = JWS(payload, alg="EdDSA")
    _jwt = _jws.sign_compact(keys)

    _pubkey = OKPKey().load_key(okp.public_key())
    _rj = JWS(alg="EdDSA")
    info = _rj.verify_compact(_jwt, [_pubkey])
    assert info == payload


def test_signer_eddsa_fail():
    payload = "Please take a moment to register today"
    okp = ed25519.Ed25519PrivateKey.generate()
    _key = OKPKey().load_key(okp)
    keys = [_key]
    _jws = JWS(payload, alg="Ed25519")
    _jwt = _jws.sign_compact(keys)

    okp2 = ed25519.Ed25519PrivateKey.generate()
    _pubkey = OKPKey().load_key(okp2.public_key())
    _rj = JWS(alg="Ed25519")
    try:
        _ = _rj.verify_compact(_jwt, [_pubkey])
    except BadSignature:
        pass
    else:
        raise AssertionError


def test_no_alg_and_alg_none_same():
    payload = "Please take a moment to register today"
    _jws = JWS(payload, alg="none")

    # Create a JWS (signed JWT)
    _jwt0 = _jws.sign_compact([])

    # The class instance that sets up the signing operation
    _jws = JWS(payload, alg="none")

    # Create a JWS (signed JWT)
    _jwt1 = _jws.sign_compact([])

    assert _jwt0 == _jwt1


def test_sign_2():
    keyset = {
        "keys": [
            {
                "alg": "RS512",
                "kty": "RSA",
                "d": "ckLyXxkbjC4szg8q8G0ERBZV"
                "-9CszeOxpRtx1KM9BLl0Do3li_Km2vvFvfXJ7MxQpiZ18pBoCcyYQEU262ym8wI22JWMPrZe24HCNxLxqzr_JEuBhpKFxQF6EFTSvJEJD1FkoTuCTvN0zD7YHGaJQG6JzVEuFUY3ewxjH0FYNa_ppTnPP3LC-T9u_GX9Yqyuw1KOYoHSzhWSWQOeAgs4dH9-iAxN1wdZ6eH1jFWAs43svk_rhwdgyJMlihFtV9MAInBlfi_Zu8wRVhVl5urkJrLf0tGFnMbnzb6dYSlUXxEYClpY12W7kXW9aePDqkCwI4oZyxmOmgq4hunKGR1dAQ",
                "e": "AQAB",
                "use": "sig",
                "kid": "af22448d-4c7b-464d-b63a-f5bd90f6d7d1",
                "n": "o9g8DpUwBW6B1qmcm-TfEh4rNX7n1t38jdo4Gkl_cI3q"
                "--7n0Blg0kN88LHZvyZjUB2NhBdFYNxMP8ucy0dOXvWGWzaPmGnq3DM__lN8P4WjD1cCTAVEYKawNBAmGKqrFj1SgpPNsSqiqK-ALM1w6mZ-QGimjOgwCyJy3l9lzZh5D8tKnS2t1pZgE0X5P7lZQWHYpHPqp4jKhETzrCpPGfv0Rl6nmmjp7NlRYBkWKf_HEKE333J6M039m2FbKgxrBg3zmYYpmHuMzVgxxb8LSiv5aqyeyJjxM-YDUAgNQBfKNhONqXyu9DqtSprNkw6sqmuxK0QUVrNYl3b03PgS5Q",
            }
        ]
    }

    keys = KeyBundle(keyset)
    jws = JWS("payload", alg="RS512")
    jws.sign_compact(keys=keys)


def test_signer_protected_headers():
    payload = "Please take a moment to register today"
    eck = ec.generate_private_key(curve=ec.SECP256R1())
    _key = ECKey().load_key(eck)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    protected = dict(header1="header1 is protected", header2="header2 is protected too", a=1)
    _jwt = _jws.sign_compact(keys, protected=protected)

    exp_protected = protected.copy()
    exp_protected["alg"] = "ES256"
    enc_header, enc_payload, sig = _jwt.split(".")
    assert json.loads(b64d(enc_header.encode("utf-8")).decode("utf-8")) == exp_protected
    assert b64d(enc_payload.encode("utf-8")).decode("utf-8") == payload

    _pub_key = ECKey().load_key(eck.public_key())
    _rj = JWS(alg="ES256")
    info = _rj.verify_compact(_jwt, [_pub_key])
    assert info == payload
    # Protected by default
    protected["alg"] = "ES256"
    assert _rj.protected_headers() == protected


def test_verify_protected_headers():
    payload = "Please take a moment to register today"
    eck = ec.generate_private_key(curve=ec.SECP256R1())
    _key = ECKey().load_key(eck)
    keys = [_key]
    _jws = JWS(payload, alg="ES256")
    protected = dict(header1="header1 is protected", header2="header2 is protected too", a=1)
    _jwt = _jws.sign_compact(keys, protected=protected)
    protectedHeader, enc_payload, sig = _jwt.split(".")
    data = dict(
        payload=enc_payload,
        signatures=[
            dict(
                header=dict(alg="ES256", jwk=_key.serialize()),
                protected=protectedHeader,
                signature=sig,
            )
        ],
    )

    # _pub_key = ECKey().load_key(eck.public_key())
    _jws = JWS()
    assert _jws.verify_json(json.dumps(data)) == payload


def test_sign_json():
    eck = ec.generate_private_key(curve=ec.SECP256R1())
    key = ECKey().load_key(eck)
    payload = "hello world"
    unprotected_headers = {"abc": "xyz"}
    protected_headers = {"foo": "bar"}
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
        headers=[(protected_headers, unprotected_headers)], keys=[key]
    )
    jwt = json.loads(_jwt)
    assert b64d_enc_dec(jwt["payload"]) == payload
    assert len(jwt["signatures"]) == 1
    assert jwt["signatures"][0]["header"] == unprotected_headers
    assert json.loads(b64d_enc_dec(jwt["signatures"][0]["protected"])) == protected_headers


def test_verify_json():
    eck = ec.generate_private_key(curve=ec.SECP256R1())
    key = ECKey().load_key(eck)
    payload = "hello world"
    unprotected_headers = {"abc": "xyz"}
    protected_headers = {"foo": "bar"}
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
        headers=[(protected_headers, unprotected_headers)], keys=[key]
    )

    vkeys = [ECKey().load_key(eck.public_key())]
    _jws = JWS()
    assert _jws.verify_json(_jwt, keys=vkeys)
    _protected = _jws.protected_headers()
    assert set(_protected.keys()) == {"foo", "alg"}
    assert _protected["foo"] == protected_headers["foo"]
    # alg is always protected by default
    assert _protected["alg"] == "ES256"


def test_sign_json_dont_include_empty_unprotected_headers():
    key = ECKey().load_key(P256())
    protected_headers = {"foo": "bar"}
    _jwt = JWS(msg="hello world", alg="ES256").sign_json(
        headers=[(protected_headers, None)], keys=[key]
    )
    json_jws = json.loads(_jwt)
    assert "header" not in json_jws["signatures"][0]
    jws_protected_headers = json.loads(b64d_enc_dec(json_jws["signatures"][0]["protected"]))
    assert set(protected_headers.items()).issubset(set(jws_protected_headers.items()))


def test_sign_json_dont_include_empty_protected_headers():
    key = ECKey().load_key(P256())
    unprotected_headers = {"foo": "bar"}
    _jwt = JWS(msg="hello world", alg="ES256").sign_json(
        headers=[(None, unprotected_headers)], keys=[key]
    )
    json_jws = json.loads(_jwt)
    jws_protected_headers = json.loads(b64d_enc_dec(json_jws["signatures"][0]["protected"]))
    assert jws_protected_headers == {"alg": "ES256"}
    jws_unprotected_headers = json_jws["signatures"][0]["header"]
    assert unprotected_headers == jws_unprotected_headers


def test_sign_json_flattened_syntax():
    key = ECKey().load_key(P256())
    protected_headers = {"foo": "bar"}
    unprotected_headers = {"abc": "xyz"}
    payload = "hello world"
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
        headers=[(protected_headers, unprotected_headers)], keys=[key], flatten=True
    )
    json_jws = json.loads(_jwt)
    assert "signatures" not in json_jws

    assert b64d_enc_dec(json_jws["payload"]) == payload
    assert json_jws["header"] == unprotected_headers
    assert json.loads(b64d_enc_dec(json_jws["protected"])) == protected_headers


def test_verify_json_flattened_syntax():
    key = ECKey().load_key(P256())
    protected_headers = {"foo": "bar"}
    unprotected_headers = {"abc": "xyz"}
    payload = "hello world"
    _jwt = JWS(msg=payload, alg="ES256").sign_json(
        headers=[(protected_headers, unprotected_headers)], keys=[key], flatten=True
    )

    vkeys = [ECKey().load_key(key.public_key())]
    _jws = JWS()
    assert _jws.verify_json(_jwt, keys=vkeys)
    assert _jws.protected_headers() == {"alg": "ES256", "foo": "bar"}


def test_sign_json_dont_flatten_if_multiple_signatures():
    key = ECKey().load_key(P256())
    unprotected_headers = {"foo": "bar"}
    _jwt = JWS(msg="hello world", alg="ES256").sign_json(
        headers=[(None, unprotected_headers), (None, {"abc": "xyz"})],
        keys=[key],
        flatten=True,
    )
    assert "signatures" in json.loads(_jwt)


def test_is_jws_recognize_compact_jws():
    key = ECKey().load_key(P256())
    jws = JWS(msg="hello world", alg="ES256").sign_compact([key])
    assert JWS().is_jws(jws)


def test_is_jws_recognize_json_serialized_jws():
    key = ECKey().load_key(P256())
    jws = JWS(msg="hello world", alg="ES256").sign_json([key])
    assert JWS().is_jws(jws)


def test_is_jws_recognize_flattened_json_serialized_jws():
    key = ECKey().load_key(P256())
    jws = JWS(msg="hello world", alg="ES256").sign_json([key], flatten=True)
    assert JWS().is_jws(jws)


def test_pick_use():
    keys = KeyBundle(JWKS_WITH_USE)
    _jws = JWS(
        "foobar", alg="RS256", kid="R3NJRW1EVHRsaUcwSXVydi14cVVoTmxhaU4zckU1MlFPa05NWGNpUUZtcw"
    )
    _keys = _jws.pick_keys(keys, use="sig")
    assert len(_keys) == 1


def test_pick_wrong_alg():
    keys = KeyBundle(JWKS_b)
    _jws = JWS("foobar", alg="EC256", kid="rsa1")
    with pytest.raises(ValueError):
        _keys = _jws.pick_keys(keys, use="sig")


def test_dj_usage():
    pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    payload = "Please take a moment to register today"
    keys = [RSAKey(priv_key=pkey)]
    _jws = JWS(payload, alg="RS256")
    sjwt = _jws.sign_compact(keys)
    _jwt = factory(sjwt)
    assert _jwt.jwt.headers["alg"] == "RS256"


def test_rs256_rm_signature():
    payload = "Please take a moment to register today"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    keys = [RSAKey(priv_key=_pkey)]
    # keys[0]._keytype = "private"
    _jws = JWS(payload, alg="RS256")
    _jwt = _jws.sign_compact(keys)

    p = _jwt.split(".")
    _jwt = ".".join(p[:-1])

    vkeys = [RSAKey(key=_pkey.public_key())]
    _rj = JWS()
    try:
        _ = _rj.verify_compact(_jwt, vkeys)
    except WrongNumberOfParts:
        pass
    else:
        raise AssertionError


def test_pick_alg_assume_alg_from_single_key():
    expected_alg = "HS256"
    keys = [SYMKey(key="foobar subdued thought", alg=expected_alg)]

    alg = JWS(alg=expected_alg)._pick_alg(keys)
    assert alg == expected_alg


def test_pick_alg_dont_get_alg_from_single_key_if_already_specified():
    expected_alg = "RS512"
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    vkeys = [RSAKey(pub_key=_pkey.public_key())]
    alg = JWS(alg=expected_alg)._pick_alg(vkeys)
    assert alg == expected_alg


def test_alg_keys_no_keys():
    jws = JWS(kid="abc1", alg="RS256")
    with pytest.raises(NoSuitableSigningKeys):
        jws.alg_keys(None, "sig")

    jws = JWS(alg="RS256")
    with pytest.raises(NoSuitableSigningKeys):
        jws.alg_keys(None, "sig")


def test_unknown_alg():
    jws = JWS(msg="Please take a moment to register today", jwk=JWKS_b["keys"][0], alg="RS768")

    with pytest.raises(UnknownAlgorithm):
        jws.sign_compact()


def test_missing_payload():
    jws = JWS()
    with pytest.raises(FormatError):
        jws.verify_json('{"foo":"bar"}')


def test_rsasigner_wrong_key_variant():
    _pkey = import_private_rsa_key_from_file(PRIV_KEY)
    with pytest.raises(TypeError):
        RSASigner().sign(b"Message to whom it may concern", _pkey.public_key)


def test_parse_rsa_algorithm_rs256():
    (hash, padding) = parse_rsa_algorithm("RS256")
    assert hash.name == "sha256"
    assert padding.name == "EMSA-PKCS1-v1_5"


def test_parse_rsa_algorithm_rs384():
    (hash, padding) = parse_rsa_algorithm("RS384")
    assert hash.name == "sha384"
    assert padding.name == "EMSA-PKCS1-v1_5"


def test_parse_rsa_algorithm_rs512():
    (hash, padding) = parse_rsa_algorithm("RS512")
    assert hash.name == "sha512"
    assert padding.name == "EMSA-PKCS1-v1_5"


def test_parse_rsa_algorithm_ps256():
    (hash, padding) = parse_rsa_algorithm("PS256")
    assert hash.name == "sha256"
    assert padding.name == "EMSA-PSS"


def test_parse_rsa_algorithm_ps384():
    (hash, padding) = parse_rsa_algorithm("PS384")
    assert hash
    assert hash.name == "sha384"
    assert padding.name == "EMSA-PSS"


def test_parse_rsa_algorithm_ps512():
    (hash, padding) = parse_rsa_algorithm("PS512")
    assert hash
    assert hash.name == "sha512"
    assert padding.name == "EMSA-PSS"


def test_extra_headers_1():
    pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    payload = "Please take a moment to register today"
    keys = [RSAKey(priv_key=pkey)]
    _jws = JWS(payload, alg="RS256")
    sjwt = _jws.sign_compact(keys, foo="bar")
    _jwt = factory(sjwt)
    assert set(_jwt.jwt.headers.keys()) == {"alg", "foo"}


def test_extra_headers_2():
    pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    payload = "Please take a moment to register today"
    keys = [RSAKey(priv_key=pkey)]
    _jws = JWS(payload, alg="RS256")
    _jws.set_header_claim("foo", "bar")
    sjwt = _jws.sign_compact(keys)
    _jwt = factory(sjwt)
    assert set(_jwt.jwt.headers.keys()) == {"alg", "foo"}


def test_mismatch_alg_and_key():
    pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    payload = "Please take a moment to register today"
    keys = [RSAKey(priv_key=pkey)]
    _jws = JWS(payload, alg="ES256")
    with pytest.raises(NoSuitableSigningKeys):
        _jws.sign_compact(keys)


def test_extra_headers_3():
    pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    payload = "Please take a moment to register today"
    keys = [RSAKey(priv_key=pkey)]
    _jws = JWS(payload, alg="RS256")
    _jws.set_header_claim("foo", "bar")
    sjwt = _jws.sign_compact(keys, abc=123)
    _jwt = factory(sjwt)
    assert set(_jwt.jwt.headers.keys()) == {"alg", "foo", "abc"}


def test_factory_verify_alg():
    pkey = import_private_rsa_key_from_file(full_path("./size2048.key"))
    payload = "Please take a moment to register today"
    keys = [RSAKey(priv_key=pkey)]
    _signer = JWS(payload, alg="RS256")
    _signer.set_header_claim("foo", "bar")
    _jws = _signer.sign_compact(keys, abc=123)
    _verifier = factory(_jws)
    assert _verifier.jwt.verify_headers(alg="RS512") is False


def test_verify_json_missing_key():
    ec_key = ECKey().load_key(P256())
    sym_key = SYMKey(key=b"My hollow echo chamber", alg="HS384")

    protected_headers_1 = {"foo": "bar", "alg": "ES256"}
    unprotected_headers_1 = {"abc": "xyz"}
    protected_headers_2 = {"foo": "bar", "alg": "HS384"}
    unprotected_headers_2 = {"abc": "zeb"}
    payload = "hello world"
    _jwt = JWS(msg=payload).sign_json(
        headers=[
            (protected_headers_1, unprotected_headers_1),
            (protected_headers_2, unprotected_headers_2),
        ],
        keys=[ec_key, sym_key],
    )

    # Only the EC key
    vkeys = [ECKey().load_key(ec_key.public_key())]
    with pytest.raises(NoSuitableSigningKeys):
        JWS().verify_json(_jwt, keys=vkeys)

    assert JWS().verify_json(_jwt, keys=vkeys, at_least_one=True)

    # Only the SYM key
    with pytest.raises(NoSuitableSigningKeys):
        JWS().verify_json(_jwt, keys=[sym_key])

    assert JWS().verify_json(_jwt, keys=[sym_key], at_least_one=True)

    # With both
    assert JWS().verify_json(_jwt, keys=[vkeys[0], sym_key])


def test_is_compact_jws():
    _header = {"foo": "bar", "alg": "HS384"}
    _payload = "hello world"
    _sym_key = SYMKey(key=b"My hollow echo chamber", alg="HS384")

    _jwt = JWS(msg=_payload, alg="HS384").sign_compact(keys=[_sym_key])

    assert is_compact_jws(_jwt)

    # Faulty examples

    # to few parts
    assert is_compact_jws("abc.def") is False

    # right number of parts but not base64

    assert is_compact_jws("abc.def.ghi") is False

    # not base64 illegal characters
    assert is_compact_jws("abc.::::.ghi") is False

    # Faulty header
    _faulty_header = {"foo": "bar"}  # alg is a MUST
    _jwt = ".".join([as_unicode(b64e(as_bytes(json.dumps(_faulty_header)))), "def", "ghi"])
    assert is_compact_jws(_jwt) is False


def test_is_json_jws():
    ec_key = ECKey().load_key(P256())
    sym_key = SYMKey(key=b"My hollow echo chamber", alg="HS384")

    protected_headers_1 = {"foo": "bar", "alg": "ES256"}
    unprotected_headers_1 = {"abc": "xyz"}
    protected_headers_2 = {"foo": "bar", "alg": "HS384"}
    unprotected_headers_2 = {"abc": "zeb"}
    payload = "hello world"
    _jwt = JWS(msg=payload).sign_json(
        headers=[
            (protected_headers_1, unprotected_headers_1),
            (protected_headers_2, unprotected_headers_2),
        ],
        keys=[ec_key, sym_key],
    )

    assert is_json_jws(_jwt)
