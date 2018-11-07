.. _jws:

JSON Web Signature (JWS)
========================

JSON Web Signature (JWS) represents content secured with digital signatures
or Message Authentication Codes (MACs) using JSON-based data structures.

It's assumed that you know all you need to know about key handling if not
please spend some time reading keyhandling_ .

When it comes to JWS there are basically 2 things you want to be able to do: sign some data and verify that a
signature over some data is correct. I'll deal with them in that order.

Signing a document
------------------

There are few steps you have to go through. Let us start with an example and then break it into its parts::

    >>> from cryptojwt.jwk.hmac import SYMKey
    >>> from cryptojwt.jws.jws import JWS

    >>> key = SYMKey(key=b'My hollow echo chamber', alg="HS512")
    >>> payload = "Please take a moment to register today"
    >>> _signer = JWS(payload, alg="HS512")
    >>> _jws = _signer.sign_compact([key])

The steps:

    1. You need keys, one of more. If you provide more then one the software will pick one that has all the necessary
       qualifications. The keys *MUST* be instances of :py:class:`cryptojwt.jwk.JWK` or of sub classes of that class.
    2. You need the information that are to be signed. It must be in the form of a string.
    3. You initiate the signer, providing it with the message and other needed information.
    4. You sign using the compact or the JSON method as described in section 7 of RFC7515_ .


Verifying a signature
---------------------

Verifying a signature works like this (_jws comes from the first signing example)::

    >>> from cryptojwt.jwk.hmac import SYMKey
    >>> from cryptojwt.jws.jws import JWS

    >>> key = SYMKey(key=b'My hollow echo chamber', alg="HS512")
    >>> _verifier = JWS(alg="HS512")
    >>> _msg = _verifier.verify_compact(_jws, [key])
    >>> print(_msg)
    "Please take a moment to register today"

The steps:

    1. As with signing, you need a set of keys that can be used to verify the signature. If you provider more then
       one possible, then the default is to use then one by one until one works or the list is empty.
    2. Initiate the verifier. If you have a reason to expect that a particular signing algorithm is to be used you
       should give that information to the verifier as shown here. If you don't know you can leave it out.
    3. Verify, using the compact or JSON method.

Or slightly different::

    >>> from cryptojwt.jws.jws import factory
    >>> from cryptojwt.jwk.hmac import SYMKey

    >>> key = SYMKey(key=b'My hollow echo chamber', alg="HS512")
    >>> _verifier = factory(_jwt)
    >>> _verifier.verify_alg('HS512')
    True
    >>> print(_verifier.verify_compact(_jwt, [key]))
    "Please take a moment to register today"

Or

    >>> from cryptojwt.jws.jws import factory
    >>> from cryptojwt.jwk.hmac import SYMKey

    >>> key = SYMKey(key=b'My hollow echo chamber', alg="HS512")
    >>> _verifier = factory(_jwt, alg="HS512")
    >>> print(_verifier.verify_compact(_jwt, [key]))
    "Please take a moment to register today"

In which case the check of the signing algorithm is done by default.

If you have Key Jar instead of a simple set of keys you can do (not showing how the key jar was initiated here)::

    >>> _verifier = factory(_jws, alg=RS256")
    >>> keys = key_jar.get_jwt_verify_keys(_verifier.jwt)
    >>> msg = _verifier.verify_compact(token, keys)

This is a trick that is used in :py:class:`cryptojwt.jwt.JWT`


.. _RFC7515: https://tools.ietf.org/html/rfc7515