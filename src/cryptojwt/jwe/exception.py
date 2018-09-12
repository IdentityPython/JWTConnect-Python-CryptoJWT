from ..exception import JWKESTException


class JWEException(JWKESTException):
    pass


class CannotDecode(JWEException):
    pass


class NotSupportedAlgorithm(JWEException):
    pass


class MethodNotSupported(JWEException):
    pass


class ParameterError(JWEException):
    pass


class NoSuitableEncryptionKey(JWEException):
    pass


class NoSuitableDecryptionKey(JWEException):
    pass


class NoSuitableECDHKey(JWEException):
    pass


class DecryptionFailed(JWEException):
    pass


class WrongEncryptionAlgorithm(JWEException):
    pass


class UnsupportedBitLength(JWEException):
    pass
