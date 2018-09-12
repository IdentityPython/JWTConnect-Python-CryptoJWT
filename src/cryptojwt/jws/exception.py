from ..exception import JWKESTException


class JWSException(JWKESTException):
    pass


class NoSuitableSigningKeys(JWSException):
    pass


class FormatError(JWSException):
    pass


class WrongTypeOfKey(JWSException):
    pass


class UnknownSignerAlg(JWSException):
    pass


class SignerAlgError(JWSException):
    pass
