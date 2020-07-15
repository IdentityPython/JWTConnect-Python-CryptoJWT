import base64
import hashlib
import logging

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptojwt.utils import b64e

logger = logging.getLogger(__name__)


def import_public_key_from_pem_file(filename):
    """
    Read a public RSA key from a PEM file.

    :param filename: The name of the file
    :param passphrase: A pass phrase to use to unpack the PEM file.
    :return: A public key instance
    """
    with open(filename, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    return public_key


def import_private_key_from_pem_file(filename, passphrase=None):
    """
    Read a private RSA key from a PEM file.

    :param filename: The name of the file
    :param passphrase: A pass phrase to use to unpack the PEM file.
    :return: A private key instance
    """
    with open(filename, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=passphrase, backend=default_backend()
        )
    return private_key


PREFIX = "-----BEGIN CERTIFICATE-----"
POSTFIX = "-----END CERTIFICATE-----"


def import_public_key_from_pem_data(pem_data):
    """
    Extract an RSA key from a PEM-encoded X.509 certificate

    :param pem_data: RSA key encoded in standard form
    :return: rsa.RSAPublicKey instance
    """
    if not pem_data.startswith(PREFIX):
        pem_data = bytes("{}\n{}\n{}".format(PREFIX, pem_data, POSTFIX), "utf-8")
    else:
        pem_data = bytes(pem_data, "utf-8")
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert.public_key()


def import_public_key_from_cert_file(filename):
    """
    Read a public key from a certificate file.

    :param filename: The name of the file
    :return: A public key instance
    """
    with open(filename, "rb") as key_file:
        cert = x509.load_pem_x509_certificate(key_file.read(), backend=default_backend())
    return cert.public_key()


def der_cert(der_data):
    """
    Load a DER encoded certificate

    :param der_data: DER-encoded certificate
    :return: A cryptography.x509.certificate instance
    """
    if isinstance(der_data, str):
        der_data = bytes(der_data, "utf-8")
    return x509.load_der_x509_certificate(der_data, default_backend())


def load_x509_cert(url, httpc, spec2key, **get_args):
    """
    Get and transform a X509 cert into a key.

    :param url: Where the X509 cert can be found
    :param httpc: HTTP client to use for fetching
    :param spec2key: A dictionary over keys already seen
    :param get_args: Extra key word arguments to the HTTP GET request
    :return: List of 2-tuples (keytype, key)
    """
    try:
        r = httpc("GET", url, allow_redirects=True, **get_args)
        if r.status_code == 200:
            cert = str(r.text)
            try:
                public_key = spec2key[cert]  # If I've already seen it
            except KeyError:
                public_key = import_public_key_from_pem_data(cert)
                spec2key[cert] = public_key

            if isinstance(public_key, rsa.RSAPublicKey):
                return {"rsa": public_key}
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                return {"ec": public_key}
        else:
            raise Exception("HTTP Get error: %s" % r.status_code)
    except Exception as err:  # not a RSA key
        logger.warning("Can't load key: %s" % err)
        return []


def x5t_calculation(cert):
    """
    base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
    encoding of an X.509 certificate.

    :param cert: DER encoded X.509 certificate
    :return: x5t value
    """
    if isinstance(cert, str):
        der_cert = base64.b64decode(cert.encode("ascii"))
    else:
        der_cert = base64.b64decode(cert)

    return b64e(hashlib.sha1(der_cert).digest())
