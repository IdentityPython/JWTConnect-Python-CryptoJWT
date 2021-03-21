import json

from cryptojwt import key_issuer


class KeyIssuer:
    @staticmethod
    def serialize(item: key_issuer.KeyIssuer) -> str:
        """ Convert from KeyIssuer to JSON """
        return json.dumps(item.dump(exclude_attributes=["keybundle_cls"]))

    def deserialize(self, spec: str) -> key_issuer.KeyIssuer:
        """ Convert from JSON to KeyIssuer """
        _dict = json.loads(spec)
        issuer = key_issuer.KeyIssuer().load(_dict)
        return issuer
