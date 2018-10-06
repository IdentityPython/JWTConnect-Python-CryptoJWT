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

When it comes to exporting keys a :py:class:`cryptojwt.jwk.JWK` instance
only know how to serialize into the format described in JWK_.

    >>> from cryptojwt.jwk.rsa import new_rsa_key
    >>> rsa_key = new_rsa_key()
    >>> rsa_key.serialize()
    {
      'kty': 'RSA',
      'kid': 'NXhZYllJOXdLSW50aUVkcGY4XzZrSVF5blI5aEYxeEJDdFZLV2tHZDlFUQ',
      'n':
        'xRgpX7q-kvQ02EhkHi63TQBR0RMcGCnxCugxtcPmaIX8brilwbkwQyZraEHzWzj-g
         aQyro_dWR7QqbhgiQ6U9Hj3x6HINJuw7LbqR_GE4TvTu3rJXPh3MqTs7yK6GcgKso
         Tv8wQy6Pwl7gjrQRk37zfIHWLkxU-crz2dd1QdSmStlxRjbczik66llF5ENXE3wVz
         raPAdjIv1Y4n5dT3kw7QerVv2Dntn5TJ_8QSkmDJW-FA2TQbKBnOd_OgYeKZnGx5c
         nguWa23uQZTxfGnE7IXA2XYpZhHIgAGMXQ0SaR07MwIZDmreI_Mxypg2ES7XT42qh
         nxXUiGm9fA8nhHjwQ',
      'e': 'AQAB'
    }


What you get when doing it like above is the representation of the public key.
You can also get the values for the private key like this::

    >>> from cryptojwt.jwk.rsa import new_rsa_key
    >>> rsa_key = new_rsa_key()
    >>> rsa_key.serialize(private=True)
    {
      'kty': 'RSA',
      'kid': 'NXhZYllJOXdLSW50aUVkcGY4XzZrSVF5blI5aEYxeEJDdFZLV2tHZDlFUQ',
      'n':
        'xRgpX7q-kvQ02EhkHi63TQBR0RMcGCnxCugxtcPmaIX8brilwbkwQyZraEHzWzj-
         gaQyro_dWR7QqbhgiQ6U9Hj3x6HINJuw7LbqR_GE4TvTu3rJXPh3MqTs7yK6GcgK
         soTv8wQy6Pwl7gjrQRk37zfIHWLkxU-crz2dd1QdSmStlxRjbczik66llF5ENXE3
         wVzraPAdjIv1Y4n5dT3kw7QerVv2Dntn5TJ_8QSkmDJW-FA2TQbKBnOd_OgYeKZn
         Gx5cnguWa23uQZTxfGnE7IXA2XYpZhHIgAGMXQ0SaR07MwIZDmreI_Mxypg2ES7X
         T42qhnxXUiGm9fA8nhHjwQ',
      'e': 'AQAB',
      'd':
        's-2jz73WvqdsGsqzg45YTlZtWrXcXv7jC3b_8pTdoiw3UAkHYXwjYBoR0cLrXCsC
         xO1WS2AQzYxBJ7-neVezih9o7Hl4IPbFJMSzymvlSA1q9OtaKqK1hqljl8gXJvQl
         N-X-e9coduPB6LWBtxNDqgI9kP44JRzRyHUybL6AYuk970_RoqxH2nr8FqMZbNWl
         Vk2X-v06EcO4E_ROSl8vqpb811UidXIvWAJw36LAUw0BTpdvpejSVM1B7PZWbzD9
         1T4vwJYOAVdwWxpmA5HEXRbpNJLnMJus7iq7EVyG2ZbA4TXT-EIoASKMyxJtAuKM
         Dk6cSISWay6LwjdBgVMAAQ',
      'p':
        '588dwE505-i7wL5mWkhH19xS1RzKahFhA66ZVmPjBaA88TBlaZxsdqEADwqXoMq_
         XIUh-P5Tc-ueiCw5rUVNTMb45HWr5fnQXtnJt4yMukNpERABIcWvZWLQg_ONW4iA
         Kid9MLg5EYd2VkAAwXwzzdD1hiYEcxMwQVQ3nLmQ8AE',
      'q':
        '2amgmjQD5Jx7kAR-9oLFjnuvgbUMBOUieQKUCpeJu8q00S7kHb2Hy6ZsanJ--Biu
         1XKz1lxelpN2upsjiKU7f08PB_IPCenBZIU3YwozZd15wCoSyKtffgqk5RXeyi3I
         1ULKXHxr3L7g-7Yi_APgtInQncNnm0Q_t7A_c-P888E'
    }

And you can of course create a key from a JWK representation::

    >>> from cryptojwt.jwk.rsa import new_rsa_key
    >>> from cryptojwt.jwk.jwk import key_from_jwk_dict
    >>> rsa_key = new_rsa_key()
    >>> jwk = rsa_key.serialize(private=True)
    >>> _key = key_from_jwk_dict(jwk)
    >>> type(_key)
    <class 'cryptojwt.jwk.rsa.RSAKey'>
    >>> _key.has_private_key()
    True



Key bundle
----------

As mentioned above a key bundle is used to manage keys that have a common
origin.

You can initiate a key bundle in serveral ways. You can use all the
import variants we described above and then add the resulting key to a key
bundle::

    >>> from cryptojwt.jwk.ec import ECKey
    >>> from cryptojwt.key_bundle import KeyBundle
    >>> ec_key = ECKey().load('ec-keypair.pem')
    >>> kb = KeyBundle()
    >>> kb.append(ec_key)
    >>> len(kb)
    1
    >>> rsa_key = new_rsa_key()
    >>> kb.append(rsa_key)
    >>> len(kb)
    2
    >>> kb.jwks()
    {"keys":
      [
        {
          "kty": "EC",
          "crv": "B-571",
          "x":
            "AhnRFzRjeOyo-qqm1HPe2JIC69McD29SKAzaBSMzpiRMqh8_tFGWzh2q3pozv_V
             4tsWDgl2H0NdLjNTUQV6JlBn52tJBgCYC",
          "y":
            "LU86ZrZlKMvposLYkgaJrtwklHumK1b1m_joq5r8NsdwQkyVtl44cucurQz1UUc
             oYNJ4ecJv1MWb-I6OwGbiVfM7WSsAhAA",
        },
        {
          "kty": "RSA",
          "kid":
            "cjBobXZ6UHVVdkFmaEJIQXNLbklNNjBMbHo5cWM4U2VjOFRrRkM4RzNaZw",
          "e": "AQAB",
          "n":
            "pyyKp3Fv5ZmyHInUjdEskmI5A-4R19gmzy8SL5waAPd7DMtndQoa-MyMPVP1je
             BPdM_WP17bm1IKt3AWIDpXPq2g0KQxiUU6X9hP738CZaqSmff_hiiT0I3VzsUT
             1SHhdIAeFIeUeuH8RusWo1NnxT7iXRFHbXsG2EOnxr-xB9FZUgMenU4dBIHh2h
             CUW6EZBsYBWuSTyMwRrNp_ZkrH5VJZSCke7bMvlyLlgMFOoDqhuibxEdRmVJAL
             7KkfKQjC0OAd6BXrTk1es590MtMsAIIdKXbgcvxZKeGYSjJ8p8HXLelz50uBhh
             eJdbUmx7MDWCTgouTGzxDaJuCbAR5wMQ",
        }
      ]
    }

**Note** that you will get a JWKS representing the public keys unless you
specify that you want a representation of the private keys.

Key Jar
-------



.. _cryptography: https://cryptography.io/en/latest/
.. _JWK: https://tools.ietf.org/html/rfc7517
.. _JWKS: https://tools.ietf.org/html/rfc7517#section-5
.. _JWS: https://tools.ietf.org/html/rfc7515
