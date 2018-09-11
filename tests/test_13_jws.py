import json
import pytest
import sys

from cryptojwt import utils
from cryptojwt.exception import JWKESTException
from cryptojwt.jwk.jwks import JWKS
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.exception import NoSuitableSigningKeys
from cryptojwt.jws.jws import JWS
from cryptojwt.utils import as_bytes
from cryptojwt.utils import as_unicode

sys.path.insert(0, '. ')

import test_vector


def modify_header(token, **kwargs):
    part = token.split('.')
    _txt = utils.b64d(as_bytes(part[0]))
    header = json.loads(as_unicode(_txt))
    header.update(kwargs)
    part[0] = utils.b64e(as_bytes(json.dumps(header)))
    return b'.'.join([as_bytes(p) for p in part])


def modify_str(s):
    # Modify each bit of string.
    for i in range(len(s)):
        c = s[i]
        for j in range(8):
            yield (s[:i] + chr(ord(c) ^ (1 << j)) + s[i+1:])

    # Truncate string.
    for i in range(len(s)):
        yield s[:i]


def modify_bytes(b):
    # Modify each bit of string.
    for i in range(len(b)):
        c = b[i]
        for j in range(8):
            yield (b[:i] + bytes([c ^ (1 << j)]) + b[i+1:])

    # Truncate string.
    for i in range(len(b)):
        yield b[:i]


def modify_json_message(token):
    part = [as_bytes(p) for p in token.split('.')]
    _txt = utils.b64d(part[1])
    msg = json.loads(as_unicode(_txt))
    for k,v in msg.items():
        msg_copy = msg.copy()
        del msg_copy[k]

        for _k in modify_str(k):
            msg_copy[_k] = v
            part[1] = utils.b64e(as_bytes(json.dumps(msg_copy)))
            yield b'.'.join([as_bytes(p) for p in part])

        if isinstance(v, str):
            for _v in modify_str(v):
                msg_copy[k] = _v
                part[1] = utils.b64e(as_bytes(json.dumps(msg_copy)))
                yield b'.'.join([as_bytes(p) for p in part])
        elif isinstance(v, int):
            _v = v+1
            msg_copy[k] = _v
            part[1] = utils.b64e(as_bytes(json.dumps(msg_copy)))
            yield b'.'.join([as_bytes(p) for p in part])


def modify_signature(token):
    part = [as_bytes(p) for p in token.split('.')]
    signature = utils.b64d(part[2])
    for sig in modify_bytes(signature):
        part[2] = utils.b64e(sig)
        yield b'.'.join([as_bytes(p) for p in part])


def modify_token(token, algs):
    # change alg
    for alg in algs:
        _token = modify_header(test_vector.rsa_token, alg=alg)
        yield _token

    # change message
    for _token in modify_json_message(test_vector.rsa_token):
        yield _token

    # change signature
    for _token in modify_signature(test_vector.rsa_token):
        yield _token


def test_jws_rsa_verifier_with_rfc():
    # Set up phase: parse the key and initialize the verifier.
    key = key_from_jwk_dict(json.loads(test_vector.json_rsa_pub_key))
    jws = JWS()

    assert jws.verify_compact(test_vector.rsa_token, [key])

    # mess with the JWS
    for _token in modify_token(
            test_vector.rsa_token,
            ['RS384', 'RS512', 'PS256', 'PS384', 'PS512']):
        with pytest.raises(JWKESTException):
            jws.verify_compact(_token, [key])


def test_jws_rsa_signer_and_verifier():
    algs = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
    for alg in algs:
        calgs = algs[:]
        calgs.remove(alg)
        json_priv_key = json.loads(test_vector.json_rsa_priv_key)
        json_priv_key['alg'] = alg
        json_priv_key = json.dumps(json_priv_key)
        json_pub_key = json.loads(test_vector.json_rsa_pub_key)
        json_pub_key['alg'] = alg
        json_pub_key = json.dumps(json_pub_key)

        json_header_rsa = json.loads(test_vector.test_header_rsa)
        json_header_rsa['alg'] = alg

        # Sign
        priv_key = key_from_jwk_dict(json.loads(json_priv_key))
        jws = JWS(msg=test_vector.test_payload, **json_header_rsa)
        signed_token = jws.sign_compact([priv_key])

        # Verify
        pub_key = key_from_jwk_dict(json.loads(json_pub_key))
        verifier = JWS()
        assert verifier.verify_compact(signed_token, [pub_key])

        for modified_token in modify_token(signed_token, calgs):
            with pytest.raises(JWKESTException):
                verifier.verify_compact(modified_token, [pub_key])


def test_jws_ecdsa_verifier_with_rfc_es256():
    # Set up phase: parse the key and initialize the verifier.
    key = key_from_jwk_dict(json.loads(test_vector.es256_ecdsa_pub_key))
    verifier = JWS()

    # Use phase
    assert verifier.verify_compact(test_vector.es256_ecdsa_token, [key])
    for modified_token in modify_token(test_vector.es256_ecdsa_token,
                                       ['ES384', 'ES512']):
        with pytest.raises(JWKESTException):
            verifier.verify_compact(modified_token, [key])


def test_jws_ecdsa_verifier_with_rfc_es512():
    # Set up phase: parse the key and initialize the verifier.
    key = key_from_jwk_dict(json.loads(test_vector.es512_ecdsa_pub_key))
    verifier = JWS()

    # Use phase
    assert verifier.verify_compact(test_vector.es512_ecdsa_token, [key])
    for modified_token in modify_token(test_vector.es512_ecdsa_token,
                                       ['ES256', 'ES512']):
        with pytest.raises(JWKESTException):
            verifier.verify_compact(modified_token, [key])


def test_jws_ecdsa_signer_verifier_es256():
    # Sign
    priv_key = key_from_jwk_dict(json.loads(test_vector.es256_ecdsa_priv_key))
    signer = JWS(msg=test_vector.test_payload,
                 **json.loads(test_vector.test_header_ecdsa))
    signed_token = signer.sign_compact([priv_key])

    # Verify
    pub_key = key_from_jwk_dict(json.loads(test_vector.es256_ecdsa_pub_key))
    verifier = JWS()
    assert verifier.verify_compact(signed_token, [pub_key])
    for modified_token in modify_token(signed_token, ['ES384', 'ES512']):
        with pytest.raises(JWKESTException):
            verifier.verify_compact(modified_token, [pub_key])


def test_jws_verifier_with_multiple_keys():
    # Set up phase: parse the keys and initialize the verifier.
    jwks = JWKS().load_jwks(test_vector.json_pub_keys)
    keys = jwks.keys()

    verifier = JWS()
    assert verifier.verify_compact(test_vector.rsa_token, keys)
    for modified_token in modify_token(
            test_vector.rsa_token, ['RS384', 'RS512', 'PS256', 'PS384',
                                    'PS512']):
        with pytest.raises(JWKESTException):
            verifier.verify_compact(modified_token, keys)

    verifier = JWS()
    assert verifier.verify_compact(test_vector.es256_ecdsa_token, keys)
    for modified_token in modify_token(test_vector.es256_ecdsa_token,
                                       ['ES384', 'ES512']):
        with pytest.raises(JWKESTException):
            verifier.verify_compact(modified_token, keys)


def test_jws_verifier_with_kid():
    # Sign
    priv_key = key_from_jwk_dict(
        json.loads(test_vector.test_json_ecdsa_priv_key_kid1))

    signer = JWS(test_vector.test_payload,
                 **json.loads(test_vector.test_header_ecdsa_kid1))
    signed_token_kid1 = signer.sign_compact([priv_key])

    priv_key = key_from_jwk_dict(
        json.loads(test_vector.test_json_ecdsa_priv_key_kid2))
    signer = JWS(test_vector.test_payload,
                 **json.loads(test_vector.test_header_ecdsa_kid2))
    signed_token_kid2 = signer.sign_compact([priv_key])

    # Verify
    pub_key = key_from_jwk_dict(
        json.loads(test_vector.test_json_ecdsa_pub_key_kid1))

    verifier = JWS()
    assert verifier.verify_compact(signed_token_kid1, [pub_key])
    # The signature is valid but the kids don't match.
    with pytest.raises(NoSuitableSigningKeys):
        verifier.verify_compact(signed_token_kid2, [pub_key])


def test_jws_mac_verifier_with_rfc():
    # Set up phase: parse the key and initialize the JwsMacVerify
    key = key_from_jwk_dict(json.loads(test_vector.json_hmac_key))
    verifier = JWS()

    # Use phase
    assert verifier.verify_compact(test_vector.hmac_token, [key])
    for modified_token in modify_token(test_vector.hmac_token,
                                       ['HS384', 'HS512']):
        with pytest.raises(JWKESTException):
            assert verifier.verify_compact(modified_token, [key])


def test_jws_mac_authenticator_and_verifier():
    algs = ['HS256', 'HS384', 'HS512']
    for alg in algs:
        calgs = algs[:]
        calgs.remove(alg)

        json_hmac_key = json.loads(test_vector.json_hmac_key)
        json_hmac_key['alg'] = alg
        json_hmac_key = json.dumps(json_hmac_key)
        json_header_hmac = json.loads(test_vector.test_header_hmac)
        json_header_hmac['alg'] = alg
        json_header_hmac = json.dumps(json_header_hmac)

        # Authenticator
        mac_key = key_from_jwk_dict(json.loads(json_hmac_key))
        authenticator = JWS(test_vector.test_payload,
                            **json.loads(json_header_hmac))
        signed_token = authenticator.sign_compact([mac_key])

        # Verify
        verifier = JWS()
        assert verifier.verify_compact(signed_token, [mac_key])
        for modified_token in modify_token(signed_token, calgs):
            with pytest.raises(JWKESTException):
                assert verifier.verify_compact(modified_token, [mac_key])


if __name__ == "__main__":
    test_jws_rsa_verifier_with_rfc()
