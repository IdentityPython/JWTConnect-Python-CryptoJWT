.. _keyhandling:

How to deal with Cryptographic keys
===================================

Absolutely vital to doing cryptography is to be able to handle keys.
This document will show you have to accomplish this with this package.

CryptoJWT deals with keys by defining 4 'layers'.

    1. At the bottom we have the keys as used by the cryptographic package
       (in this case cryptography_) .
    2. Above that we have something we call a JSON Web Key. The base class
       here is :py:class:`cryptojwt.jwk.JWK`. This class can import keys in
       a number of formats and can export a key as a JWK_.
    3. A :py:class:`cryptojwt.key_bundle.KeyBundle` keeps track of a set of
       keys that has the same origin. Like being part of a JWKS_.
    4. A :py:class:`cryptojwt.key_jar.KeyJar` lastly is there to sort the keys
       by their owners/issuers.


I will not describe who to deal with keys in layer 1, that is done best by
cryptography_. So, I'll start at layer 2.

JSON Web Key (JWK)
------------------

Let us start with you not having any key at all and you want to create a
signed JSON Web Token (JWS_).
What to do ?

Well if you know what kind of key you want, if it is a asymmetric key you can
use one of the provided factory methods.

    RSA
        :py:func:`cryptojwt.jwk.rsa.new_rsa_key`
    Elliptic Curve:
        :py:func:`cryptojwt.jwk.ec.new_ec_key`


As an example::

    >>> from cryptojwt.jwk.rsa import new_rsa_key
    >>> rsa_key = new_rsa_key()
    >>> type(rsa_key)
    <class 'cryptojwt.jwk.rsa.RSAKey'>


If you want a symmetric key you only need some sort of "secure random"
mechanism. You can use this to acquire a byte array of the appropriate length
(e.g. 32 bytes for AES256), which can be used as a key.

If you already has a key, like if you have a PEM encoded private RSA key in
a file on your machine you can load it this way::

    >>> from cryptojwt.jwk.rsa import RSAKey
    >>> rsa_key = RSAKey().load('key.pem')
    >>> rsa_key.has_private_key()
    True

If you have a PEM encoded X.509 certificate you may want to grab the public
RSA key from you could do like this::

    >>> from cryptojwt.jwk.rsa import import_rsa_key_from_cert_file
    >>> from cryptojwt.jwk.rsa import RSAKey
    >>> _key = import_rsa_key_from_cert_file('cert.pem')
    >>> rsa_key = RSAKey(pub_key=_key)
    >>> rsa_key.has_private_key()
    False
    >>> rsa_key.public_key()
    <cryptography.hazmat.backends.openssl.rsa._RSAPublicKey object at 0x1036b1f60>

If you are dealing with Elliptic Curve keys the equivalent would be::

    >>> from cryptojwt.jwk.ec import new_ec_key
    >>> ec_key = new_ec_key('P-256')
    >>> type(ec_key)
    <class 'cryptojwt.jwk.ec.ECKey'>
    >>> ec_key.has_private_key()
    True

and::

    >>> from cryptojwt.jwk.ec import ECKey
    >>> ec_key = ECKey().load('ec-keypair.pem')
    >>> ec_key.has_private_key()
    True



.. _cryptography: https://cryptography.io/en/latest/
.. _JWK: https://tools.ietf.org/html/rfc7517
.. _JWKS: https://tools.ietf.org/html/rfc7517#section-5
.. _JWS: https://tools.ietf.org/html/rfc7515
