from cryptojwt import jwk
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt import key_bundle
from cryptojwt import key_issuer


class JWK:
    @staticmethod
    def serialize(key: jwk.JWK) -> dict:
        _dict = key.serialize()
        inactive = key.inactive_since
        if inactive:
            _dict['inactive_since'] = inactive
        return _dict

    @staticmethod
    def deserialize(jwk: dict) -> jwk.JWK:
        k = key_from_jwk_dict(jwk)
        inactive = jwk.get("inactive_since", 0)
        if inactive:
            k.inactive_since = inactive
        return k


class KeyBundle:
    def __init__(self, storage_conf=None):
        self.storage_conf = storage_conf

    @staticmethod
    def serialize(item: key_bundle.KeyBundle) -> dict:
        _dict = item.dump()
        return _dict

    def deserialize(self, spec: dict) -> key_bundle.KeyBundle:
        bundle = key_bundle.KeyBundle(storage_conf=self.storage_conf).load(spec)
        return bundle


class KeyIssuer:
    def __init__(self, storage_conf=None):
        self.storage_conf = storage_conf

    @staticmethod
    def serialize(item: key_issuer.KeyIssuer) -> dict:
        _dict = item.dump()
        return _dict

    def deserialize(self, spec: dict) -> key_issuer.KeyIssuer:
        issuer = key_issuer.KeyIssuer(storage_conf=self.storage_conf).load(spec)
        return issuer
