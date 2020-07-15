import logging

from ..simple_jwt import SimpleJWT
from ..utils import b64encode_item
from . import SUPPORTED

logger = logging.getLogger(__name__)


class JWEnc(SimpleJWT):
    def b64_protected_header(self):
        return self.b64part[0]

    def b64_encrypted_key(self):
        return self.b64part[1]

    def b64_initialization_vector(self):
        return self.b64part[2]

    def b64_ciphertext(self):
        return self.b64part[3]

    def b64_authentication_tag(self):
        return self.b64part[4]

    def protected_header(self):
        return self.part[0]

    def encrypted_key(self):
        return self.part[1]

    def initialization_vector(self):
        return self.part[2]

    def ciphertext(self):
        return self.part[3]

    def authentication_tag(self):
        return self.part[4]

    def b64_encode_header(self):
        return b64encode_item(self.headers)

    def is_jwe(self):
        if "typ" in self.headers and self.headers["typ"].lower() == "jwe":
            return True

        if "alg" in self.headers and "enc" in self.headers:
            for typ in ["alg", "enc"]:
                if self.headers[typ] not in SUPPORTED[typ]:
                    logger.debug("Not supported %s algorithm: %s" % (typ, self.headers[typ]))
                    return False
        else:
            return False
        return True

    def __len__(self):
        return len(self.part)
