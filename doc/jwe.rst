.. _jwe:

JSON Web Encryption (JWE)
=========================

JSON Web Encryption (JWE) represents encrypted content using JSON-based data
structures.

It's assumed that you know all you need to know about key handling if not
please spend some time reading keyhandling_ .

When it comes to JWE there are basically 2 things you want to be able to do:
encrypt some data and decrypt some encrypted data. I'll deal with
them in that order.

Encrypting a document
---------------------

This is the high level way of doing things.
There are few steps you have to go through. Let us start with an example and then break it into its parts::

    >>> from cryptojwt.jwk.rsa import RSAKey
    >>> from cryptojwt.jwe.jwe import JWE

    >>> priv_key = import_private_rsa_key_from_file(KEY)
    >>> pub_key = priv_key.public_key()
    >>> encryption_key = RSAKey(use="enc", pub_key=pub_key, kid="some-key-id")
    >>> plain = b'Now is the time for all good men to come to the aid of ...'
    >>> encryptor = JWE(plain, alg="RSA-OAEP", enc="A256CBC-HS512")
    >>> jwe = encryptor.encrypt(keys=[encryption_key], kid="some-key-id")

The steps:

    1. You need an encryption key. The key *MUST* be instances of
       :py:class:`cryptojwt.jwk.JWK`.
    2. You need the information that are to be signed. It must be in the form of a string.
    3. You initiate the encryptor, provide it with the message and other
       needed information.
    4. And then you encrypt as described in RFC7516_ .

There is a lower level way of doing the same it will look like this::

    >>> from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
    >>> from cryptojwt.jwe.jwe_rsa import JWE_RSA

    >>> priv_key = import_private_rsa_key_from_file(KEY)
    >>> pub_key = priv_key.public_key()
    >>> plain = b'Now is the time for all good men to come to the aid of ...'
    >>> _rsa = JWE_RSA(plain, alg="RSA1_5", enc="A128CBC-HS256")
    >>> jwe = _rsa.encrypt(pub_key)

Here the key is an cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
instance and the encryptor is a :py:class:`cryptojwt.jwe.jew_rsa.JWE_RSA`
instance.

Decrypting something encrypted
------------------------------

Decrypting using the encrypted message above.

    >>> from cryptojwt.jwe.jwe import factory
    >>> from cryptojwt.jwk.rsa import RSAKey

    >>> _decryptor = factory(jwt, alg="RSA1_5", enc="A128CBC-HS256")
    >>> _dkey = RSAKey(priv_key=priv_key)
    >>> msg = _decryptor.decrypt(jwe, [_dkey])



.. _RFC7516: https://tools.ietf.org/html/rfc7516