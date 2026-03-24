import json

import pytest
import test_vector

from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS


@pytest.mark.parametrize("alg", ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
def test_jws_rsa_signer_and_verifier(alg):
    _jwk_dict = json.loads(test_vector.json_rsa_priv_key)
    _key = key_from_jwk_dict(_jwk_dict)
    _key.alg = alg
    _key.add_kid()

    json_header_rsa = json.loads(test_vector.test_header_rsa)
    json_header_rsa["alg"] = alg

    # Sign
    jws = JWS(msg=test_vector.test_payload, **json_header_rsa)
    signed_token = jws.sign_compact([_key])

    # Verify
    verifier = JWS(alg=[alg])
    assert verifier.verify_compact(signed_token, [_key])
