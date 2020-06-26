from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from . import Encrypter


class RSAEncrypter(Encrypter):
    def encrypt(self, msg, key, sign_padding="pkcs1_padding"):
        _chosen_hash = hashes.SHA1
        if sign_padding == "pkcs1_padding":
            _padding = padding.PKCS1v15
            return key.encrypt(msg, _padding())
        elif sign_padding == "pkcs1_oaep_padding":
            _padding = padding.OAEP
        elif sign_padding == "pkcs1_oaep_256_padding":
            _padding = padding.OAEP
            _chosen_hash = hashes.SHA256
        else:
            raise Exception("Unsupported padding")
        return key.encrypt(
            msg,
            _padding(
                mgf=padding.MGF1(algorithm=_chosen_hash()),
                algorithm=_chosen_hash(),
                label=None,
            ),
        )

    def decrypt(self, ciphertext, key, sign_padding="pkcs1_padding"):
        _chosen_hash = hashes.SHA1
        if sign_padding == "pkcs1_padding":
            _padding = padding.PKCS1v15
            return key.decrypt(ciphertext, _padding())
        elif sign_padding == "pkcs1_oaep_padding":
            _padding = padding.OAEP
        elif sign_padding == "pkcs1_oaep_256_padding":
            _padding = padding.OAEP
            _chosen_hash = hashes.SHA256
        else:
            raise Exception("Unsupported padding")

        try:
            text = key.decrypt(
                ciphertext,
                _padding(
                    mgf=padding.MGF1(algorithm=_chosen_hash()),
                    algorithm=_chosen_hash(),
                    label=None,
                ),
            )
        except Exception:
            raise

        return text
