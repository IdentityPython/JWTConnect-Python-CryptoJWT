import pytest
from cryptojwt.jwe import JWE_EC
from cryptojwt.jwe import factory
from cryptojwt.jwk import ECKey

JWK = {
    "kty": "EC",
    "kid": "3f7b122d-e9d2-4ff7-bdeb-a1487063d799",
    "crv": "P-256",
    "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
    "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
    "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
}

ALG = "ECDH-ES+A128KW"
ENC = "A128CBC-HS256"
PLAINTEXT = "Gambling is illegal at Bushwood sir, and I never slice."

maliciousJWE = '.'.join(
    [
        "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0",
        "qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg",
        "pEA5kX304PMCOmFSKX_cEg",
        "a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg",
        "72CHiYFecyDvuUa43KKT6w"
    ]
)


def test():
    key = ECKey(**JWK)

    ret_jwe = factory(maliciousJWE)
    jwdec = JWE_EC()
    with pytest.raises(ValueError):
        jwdec.dec_setup(ret_jwe.jwt, key=key.keys())
