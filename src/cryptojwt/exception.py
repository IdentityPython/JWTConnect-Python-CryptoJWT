class JWKESTException(Exception):
    pass


# XXX Should this be a subclass of ValueError?
class Invalid(JWKESTException):
    """The JWT is invalid."""


class WrongNumberOfParts(Invalid):
    pass


class BadSyntax(Invalid):
    """The JWT could not be parsed because the syntax is invalid."""

    def __init__(self, value, msg):
        Invalid.__init__(self)
        self.value = value
        self.msg = msg

    def __str__(self):
        return "%s: %r" % (self.msg, self.value)


class BadSignature(Invalid):
    """The signature of the JWT is invalid."""


class Expired(Invalid):
    """The JWT claim has expired or is not yet valid."""


class UnknownAlgorithm(Invalid):
    """The JWT uses an unknown signing algorithm"""


class BadType(Invalid):
    """The JWT has an unexpected "typ" value."""


class MissingKey(JWKESTException):
    """ No usable key """


class UnknownKeytype(Invalid):
    """An unknown key type"""


class JWKException(JWKESTException):
    pass


class FormatError(JWKException):
    pass


class SerializationNotPossible(JWKException):
    pass


class DeSerializationNotPossible(JWKException):
    pass


class HeaderError(JWKESTException):
    pass


class UnSupported(JWKESTException):
    pass


class MissingValue(JWKESTException):
    pass


class VerificationError(JWKESTException):
    pass
