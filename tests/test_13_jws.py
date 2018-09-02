import json
import sys

from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS

sys.path.insert(0,'. ')

import test_util
import test_vector


def test_jws_rsa_verifier_with_rfc():
    # Set up phase: parse the key and initialize the verifier.
    key = key_from_jwk_dict(json.loads(test_vector.json_rsa_pub_key))
    jws = JWS()

    assert jws.verify_compact(test_vector.rsa_token, [key])

    for modified_token in test_util.modify_token(test_vector.rsa_token):
        assert not jws.verify_compact(modified_token, [key])


# def test_jws_rsa_signer_and_verifier(self):
#     algs = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
#     for alg in algs:
#         json_priv_key = json.loads(test_vector.json_rsa_priv_key)
#         json_priv_key['alg'] = alg
#         json_priv_key = json.dumps(json_priv_key)
#         json_pub_key = json.loads(test_vector.json_rsa_pub_key)
#         json_pub_key['alg'] = alg
#         json_pub_key = json.dumps(json_pub_key)
#
#         json_header_rsa = json.loads(test_vector.test_header_rsa)
#         json_header_rsa['alg'] = alg
#         json_header_rsa = json.dumps(json_header_rsa)
#
#         # Sign
#         priv_key = CleartextJwkSetReader.from_json(json_priv_key)
#         signer = jws.JwsPublicKeySign(priv_key)
#         signed_token = signer.sign(json_header_rsa, test_vector.test_payload)
#
#         # Verify
#         pub_key = CleartextJwkSetReader.from_json(json_pub_key)
#         verifier = jws.JwsPublicKeyVerify(pub_key)
#         self.assertTrue(verifier.verify(signed_token))
#         for modified_token in test_util.modify_token(signed_token):
#             self.assertFalse(verifier.verify(modified_token))
#
#
# def test_jws_ecdsa_verifier_with_rfc_es256(self):
#     # Set up phase: parse the key and initialize the verifier.
#     key = CleartextJwkSetReader.from_json(test_vector.es256_ecdsa_pub_key)
#     verifier = jws.JwsPublicKeyVerify(key)
#
#     # Use phase
#     self.assertTrue(verifier.verify(test_vector.es256_ecdsa_token))
#     for modified_token in test_util.modify_token(test_vector.es256_ecdsa_token):
#         self.assertFalse(verifier.verify(modified_token))
#
#
# def test_jws_ecdsa_verifier_with_rfc_es512(self):
#     # Set up phase: parse the key and initialize the verifier.
#     key = CleartextJwkSetReader.from_json(test_vector.es512_ecdsa_pub_key)
#     verifier = jws.JwsPublicKeyVerify(key)
#
#     # Use phase
#     self.assertTrue(verifier.verify(test_vector.es512_ecdsa_token))
#     for modified_token in test_util.modify_token(test_vector.es512_ecdsa_token):
#         self.assertFalse(verifier.verify(modified_token))
#
#
# def test_jws_ecdsa_signer_verifier_es256(self):
#     # Sign
#     priv_key = CleartextJwkSetReader.from_json(test_vector.es256_ecdsa_priv_key)
#     signer = jws.JwsPublicKeySign(priv_key)
#     signed_token = signer.sign(test_vector.test_header_ecdsa,
#                                test_vector.test_payload)
#
#     # Verify
#     pub_key = CleartextJwkSetReader.from_json(test_vector.es256_ecdsa_pub_key)
#     verifier = jws.JwsPublicKeyVerify(pub_key)
#     self.assertTrue(verifier.verify(signed_token))
#     for modified_token in test_util.modify_token(signed_token):
#         self.assertFalse(verifier.verify(modified_token))
#
#
# def test_jws_verifier_with_multiple_keys(self):
#     # Set up phase: parse the keys and initialize the verifier.
#     keys = CleartextJwkSetReader.from_json(test_vector.json_pub_keys)
#     verifier = jws.JwsPublicKeyVerify(keys)
#
#     # Use phase
#     self.assertTrue(verifier.verify(test_vector.rsa_token))
#     self.assertTrue(verifier.verify(test_vector.es256_ecdsa_token))
#     for modified_token in test_util.modify_token(test_vector.rsa_token):
#         self.assertFalse(verifier.verify(modified_token))
#     for modified_token in test_util.modify_token(test_vector.es256_ecdsa_token):
#         self.assertFalse(verifier.verify(modified_token))
#
#
# def test_jws_verifier_with_kid(self):
#     # Sign
#     priv_key = CleartextJwkSetReader.from_json(
#         test_vector.test_json_ecdsa_priv_key_kid1)
#     signer = jws.JwsPublicKeySign(priv_key)
#     signed_token_kid1 = signer.sign(test_vector.test_header_ecdsa_kid1,
#                                     test_vector.test_payload)
#     signed_token_kid2 = signer.sign(test_vector.test_header_ecdsa_kid2,
#                                     test_vector.test_payload)
#
#     # Verify
#     pub_key = CleartextJwkSetReader.from_json(
#         test_vector.test_json_ecdsa_pub_key_kid1)
#     verifier = jws.JwsPublicKeyVerify(pub_key)
#     self.assertTrue(verifier.verify(signed_token_kid1))
#     # The signature is valid but the kids don't match.
#     self.assertFalse(verifier.verify(signed_token_kid2))
#
#
# def test_jws_mac_verifier_with_rfc(self):
#     # Set up phase: parse the key and initialize the JwsMacVerify
#     key = CleartextJwkSetReader.from_json(test_vector.json_hmac_key)
#     verifier = jws.JwsMacVerify(key)
#
#     # Use phase
#     self.assertTrue(verifier.verify(test_vector.hmac_token))
#     for modified_token in test_util.modify_token(test_vector.hmac_token):
#         self.assertFalse(verifier.verify(modified_token))
#
#
# def test_jws_mac_authenticator_and_verifier(self):
#     algs = ['HS256', 'HS384', 'HS512']
#     for alg in algs:
#         json_hmac_key = json.loads(test_vector.json_hmac_key)
#         json_hmac_key['alg'] = alg
#         json_hmac_key = json.dumps(json_hmac_key)
#         json_header_hmac = json.loads(test_vector.test_header_hmac)
#         json_header_hmac['alg'] = alg
#         json_header_hmac = json.dumps(json_header_hmac)
#
#         # Authenticator
#         mac_key = CleartextJwkSetReader.from_json(json_hmac_key)
#         authenticator = jws.JwsMacAuthenticator(mac_key)
#         signed_token = authenticator.authenticate(json_header_hmac,
#                                                   test_vector.test_payload)
#         # Verify
#         verifier = jws.JwsMacVerify(mac_key)
#         self.assertTrue(verifier.verify(signed_token))
#         for modified_token in test_util.modify_token(signed_token):
#             self.assertFalse(verifier.verify(modified_token))