from . import JWK
from . import USE


class AsymmetricKey(JWK):
    """
    JSON Web key representation of an Asymmetric key
    """

    def __init__(
        self,
        kty="oct",
        alg="",
        use="",
        kid="",
        x5c=None,
        x5t="",
        x5u="",
        k="",
        pub_key=None,
        priv_key=None,
        **kwargs
    ):
        JWK.__init__(self, kty, alg, use, kid, x5c, x5t, x5u, **kwargs)
        self.k = k
        self.pub_key = pub_key
        self.priv_key = priv_key

    def appropriate_for(self, usage, **kwargs):
        """
        Make sure there is a key instance present that can be used for
        the specified usage.

        :param usage: Usage specification, one of [sign, verify, decrypt,
            encrypt]
        :param kwargs: Extra keyword arguments
        :return: Suitable key or None
        """
        try:
            _use = USE[usage]
        except KeyError:
            raise ValueError("Unknown key usage")
        else:
            if usage in ["sign", "decrypt"]:
                if not self.use or _use == self.use:
                    if self.priv_key:
                        return self.priv_key
                return None
            else:  # has to be one of ['encrypt', 'verify']
                if not self.use or _use == self.use:
                    if self.pub_key:
                        return self.pub_key
                return None

    def has_private_key(self):
        """
        Checks whether there is a private key avaliable.

        :return: True/False
        """
        if self.priv_key:
            return True
        else:
            return False

    def public_key(self):
        """
        Return a public key instance.
        """
        return self.pub_key

    def private_key(self):
        """
        Return a private key instance.
        """
        return self.priv_key
