import json
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from cryptojwt import key_issuer


class KeyIssuer:
    @staticmethod
    def serialize(item: key_issuer.KeyIssuer) -> str:
        """ Convert from KeyIssuer to JSON """
        return json.dumps(item.dump())

    def deserialize(self, spec: str) -> key_issuer.KeyIssuer:
        """ Convert from JSON to KeyIssuer """
        _dict = json.loads(spec)
        issuer = key_issuer.KeyIssuer().load(_dict)
        return issuer


class QUOTE:
    @staticmethod
    def serialize(item: str) -> str:
        return quote_plus(item)

    def deserialize(self, spec: str) -> str:
        return unquote_plus(spec)
