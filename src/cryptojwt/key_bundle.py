import json
import logging
import os
import requests
import sys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from .exception import JWKException
from .exception import UnknownKeyType
from .exception import UpdateFailed
from .jwk.hmac import SYMKey
from .jwk.ec import ECKey
from .jwk.ec import NIST2SEC
from .jwk.rsa import RSAKey
from .jwk.rsa import rsa_load
from .utils import as_unicode


__author__ = 'Roland Hedberg'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
REMOTE_FAILED = "Remote key update from '{}' failed, HTTP status {}"
MALFORMED = "Remote key update from {} failed, malformed JWKS."

logger = logging.getLogger(__name__)

# def raise_exception(excep, descr, error='service_error'):
#     _err = json.dumps({'error': error, 'error_description': descr})
#     raise excep(_err, 'application/json')


K2C = {
    "RSA": RSAKey,
    "EC": ECKey,
    "oct": SYMKey,
}

MAP = {'dec': 'enc', 'enc': 'enc', 'ver': 'sig', 'sig': 'sig'}


def harmonize_usage(use):
    """

    :param use:
    :return: list of usage
    """
    if isinstance(use, str):
        return [MAP[use]]
    elif isinstance(use, list):
        ul = list(MAP.keys())
        return list(set([MAP[u] for u in use if u in ul]))


def create_and_store_rsa_key_pair(name="oidcmsg", path=".", size=2048, use=''):
    """
    Mints a new RSA key pair and stores it in a file.
    
    :param name: Name of the key file. 2 files will be created one with
        the private key the name without extension and the other containing
        the public key with '.pub' as extension. 
    :param path: Path to where the key files are stored
    :param size: RSA key size
    :return: RSA key
    """

    key = generate_private_key(public_exponent=65537, key_size=size,
                               backend=default_backend())

    os.makedirs(path, exist_ok=True)

    if name:
        if use:
            name = '{}_{}'.format(name, use)

        pem = key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption())

        with open(os.path.join(path, name), 'wb') as f:
            f.write(pem)

        public_key = key.public_key()
        pub_pem = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo)

        with open(os.path.join(path, '{}.pub'.format(name)), 'wb') as f:
            f.write(pub_pem)

    return key


def rsa_init(spec):
    """
    Initiates a :py:class:`oidcmsg.keybundle.KeyBundle` instance
    containing newly minted RSA keys according to a spec.
    
    Example of specification::
        {'name': 'myrsakey', 'path': 'keystore', 'size':2048, 
         'use': ['enc', 'sig'] }
         
    Using the spec above 2 RSA keys would be minted, one for 
    encryption and one for signing.
        
    :param spec:
    :return: KeyBundle
    """
    if 'name' not in spec:
        try:
            _key_name = spec['key']
        except KeyError:
            pass
        else:
            if '/' in _key_name:
                (head, tail) = os.path.split(spec['key'])
                spec['path'] = head
                spec['name'] = tail
            else:
                spec['name'] = _key_name

    arg = {}
    for param in ["name", "path", "size"]:
        try:
            arg[param] = spec[param]
        except KeyError:
            pass

    kb = KeyBundle(keytype="RSA")
    for use in harmonize_usage(spec["use"]):
        _key = create_and_store_rsa_key_pair(use=use, **arg)
        kb.append(RSAKey(use=use, priv_key=_key))
    return kb


def ec_init(spec):
    """
    Initiate a keybundle with an elliptic curve key.

    :param spec: Key specifics of the form::
        {"type": "EC", "crv": "P-256", "use": ["sig"]}

    :return: A KeyBundle instance
    """

    _key = ec.generate_private_key(NIST2SEC[spec['crv']], default_backend())

    kb = KeyBundle(keytype="EC", keyusage=spec["use"])
    for use in spec["use"]:
        eck = ECKey(use=use).load_key(_key)
        kb.append(eck)
    return kb


class KeyBundle(object):
    def __init__(self, keys=None, source="", cache_time=300, verify_ssl=True,
                 fileformat="jwk", keytype="RSA", keyusage=None, kid=''):
        """
        Contains a set of keys that have a common origin.
        The sources can be serveral:
        - A dictionary provided at the initialization, see keys below.
        - A list of dictionaries provided at initialization
        - A file containing one of: JWKS, DER encoded key
        - A URL pointing to a webpages from which an JWKS can be downloaded
                 
        :param keys: A dictionary or a list of dictionaries
            with the keys ["kty", "key", "alg", "use", "kid"]
        :param source: Where the key set can be fetch from
        :param verify_ssl: Verify the SSL cert used by the server
        :param fileformat: For a local file either "jwk" or "der"
        :param keytype: Iff local file and 'der' format what kind of key it is.
            presently only 'rsa' is supported.
        :param keyusage: What the key loaded from file should be used for.
            Only applicable for DER files
        """

        self._keys = []
        self.remote = False
        self.verify_ssl = verify_ssl
        self.cache_time = cache_time
        self.time_out = 0
        self.etag = ""
        self.source = None
        self.fileformat = fileformat.lower()
        self.keytype = keytype
        self.keyusage = keyusage
        self.imp_jwks = None
        self.last_updated = 0

        if keys:
            self.source = None
            if isinstance(keys, dict):
                self.do_keys([keys])
            else:
                self.do_keys(keys)
        else:
            if source.startswith("file://"):
                self.source = source[7:]
            elif source.startswith("http://") or source.startswith("https://"):
                self.source = source
                self.remote = True
            elif source == "":
                return
            else:
                if fileformat.lower() in ['rsa', 'der', 'jwks']:
                    if os.path.isfile(source):
                        self.source = source
                    else:
                        raise ImportError('No such file')
                else:
                    raise ImportError('Unknown source')

            if not self.remote:  # local file
                if self.fileformat in ['jwks', "jwk"]:
                    self.do_local_jwk(self.source)
                elif self.fileformat == "der":  # Only valid for RSA keys
                    self.do_local_der(self.source, self.keytype, self.keyusage,
                                      kid)

    def do_keys(self, keys):
        """
        Go from JWK description to binary keys

        :param keys:
        :return:
        """
        for inst in keys:
            typ = inst["kty"]
            try:
                _usage = harmonize_usage(inst['use'])
            except KeyError:
                _usage = ['']
            else:
                del inst['use']

            flag = 0
            for _use in _usage:
                for _typ in [typ, typ.lower(), typ.upper()]:
                    try:
                        _key = K2C[_typ](use=_use, **inst)
                    except KeyError:
                        continue
                    except JWKException as err:
                        logger.warning('While loading keys: {}'.format(err))
                    else:
                        self._keys.append(_key)
                        flag = 1
                        break
            if not flag:
                logger.warning(
                    'While loading keys, UnknownKeyType: {}'.format(typ))

    def do_local_jwk(self, filename):
        """
        Load a JWKS from a local file
         
        :param filename: 
        """
        _info = json.loads(open(filename).read())
        if 'keys' in _info:
            self.do_keys(_info["keys"])
        else:
            self.do_keys([_info])

        self.last_updated = time.time()

    def do_local_der(self, filename, keytype, keyusage=None, kid=''):
        """
        Load a DER encoded file amd create a key from it.
         
        :param filename: 
        :param keytype: Presently only 'rsa' supported
        :param keyusage: encryption ('enc') or signing ('sig') or both
        """
        _bkey = rsa_load(filename)

        if keytype.lower() != 'rsa':
            raise NotImplemented('No support for DER decoding of that key type')

        if not keyusage:
            keyusage = ["enc", "sig"]
        else:
            keyusage = harmonize_usage(keyusage)

        for use in keyusage:
            _key = RSAKey().load_key(_bkey)
            _key.use = use
            if kid:
                _key.kid = kid
            self._keys.append(_key)

        self.last_updated = time.time()

    def do_remote(self):
        """
        Load a JWKS from a webpage

        :return: True or False if load was successful        
        """
        args = {"verify": self.verify_ssl}

        try:
            logging.debug('KeyBundle fetch keys from: {}'.format(self.source))
            r = requests.get(self.source, **args)
        except Exception as err:
            logger.error(err)
            raise UpdateFailed(
                REMOTE_FAILED.format(self.source, str(err)))

        if r.status_code == 200:  # New content
            self.time_out = time.time() + self.cache_time

            self.imp_jwks = self._parse_remote_response(r)
            if not isinstance(self.imp_jwks,
                              dict) or "keys" not in self.imp_jwks:
                raise UpdateFailed(MALFORMED.format(self.source))

            logger.debug("Loaded JWKS: %s from %s" % (r.text, self.source))
            try:
                self.do_keys(self.imp_jwks["keys"])
            except KeyError:
                logger.error("No 'keys' keyword in JWKS")
                raise UpdateFailed(MALFORMED.format(self.source))

        else:
            raise UpdateFailed(
                REMOTE_FAILED.format(self.source, r.status_code))
        self.last_updated = time.time()
        return True

    def _parse_remote_response(self, response):
        """
        Parse JWKS from the HTTP response.

        Should be overriden by subclasses for adding support of e.g. signed
        JWKS.
        :param response: HTTP response from the 'jwks_uri' endpoint
        :return: response parsed as JSON
        """
        # Check if the content type is the right one.
        try:
            if response.headers["Content-Type"] != 'application/json':
                logger.warning('Wrong Content_type ({})'.format(
                    response.headers["Content-Type"]))
        except KeyError:
            pass

        logger.debug("Loaded JWKS: %s from %s" % (response.text, self.source))
        try:
            return json.loads(response.text)
        except ValueError:
            return None

    def _uptodate(self):
        res = False
        if self._keys is not []:
            if self.remote:  # verify that it's not to old
                if time.time() > self.time_out:
                    if self.update():
                        res = True
        elif self.remote:
            if self.update():
                res = True
        return res

    def update(self):
        """
        Reload the keys if necessary
        This is a forced update, will happen even if cache time has not elapsed.

        Replaced keys will be marked as inactive and not removed.        
        """
        res = True  # An update was successful
        if self.source:
            _keys = self._keys  # just in case

            # reread everything
            self._keys = []

            try:
                if self.remote is False:
                    if self.fileformat == "jwks":
                        self.do_local_jwk(self.source)
                    elif self.fileformat == "der":
                        self.do_local_der(self.source, self.keytype,
                                          self.keyusage)
                else:
                    res = self.do_remote()
            except Exception as err:
                logger.error('Key bundle update failed: {}'.format(err))
                self._keys = _keys  # restore
                return False

            now = time.time()
            for _key in _keys:
                if _key not in self._keys:
                    try:
                        _key.inactive_since  # If already marked don't mess
                    except ValueError:
                        _key.inactive_since = now
                    self._keys.append(_key)

        return res

    def get(self, typ=""):
        """
        Return a list of keys. Either all keys or only keys of a specific type
        
        :param typ: Type of key (rsa, ec, oct, ..)
        :return: If typ is undefined all the keys as a dictionary
            otherwise the appropriate keys in a list
        """
        self._uptodate()
        _typs = [typ.lower(), typ.upper()]

        if typ:
            return [k for k in self._keys if k.kty in _typs]
        else:
            return self._keys

    def keys(self):
        """
        Return all keys after having updated them
        
        :return: List of all keys 
        """
        self._uptodate()

        return self._keys

    def active_keys(self):
        _res = []
        for k in self._keys:
            try:
                ias = k.inactive_since
            except ValueError:
                _res.append(k)
            else:
                if ias == 0:
                    _res.append(k)
        return _res

    def remove_keys_by_type(self, typ):
        """
        Remove keys that are of a specific type.
        
        :param typ: Type of key (rsa, ec, oct, ..)
        """
        _typs = [typ.lower(), typ.upper()]
        self._keys = [k for k in self._keys if not k.kty in _typs]

    def __str__(self):
        return str(self.jwks())

    def jwks(self, private=False):
        """
        Create a JWKS
        
        :param private: Whether private key information should be included.
        :return: A JWKS JSON representation of the keys in this bundle
        """
        self._uptodate()
        keys = list()
        for k in self._keys:
            if private:
                key = k.serialize(private)
            else:
                key = k.to_dict()
                for k, v in key.items():
                    key[k] = as_unicode(v)
            keys.append(key)
        return json.dumps({"keys": keys})

    def append(self, key):
        """
        Add a key to list of keys in this bundle
        
        :param key: Key to be added 
        """
        self._keys.append(key)

    def remove(self, key):
        """
        Remove a specific key from this bundle
        
        :param key: The key that should be removed 
        """
        try:
            self._keys.remove(key)
        except ValueError:
            pass

    def __len__(self):
        """
        The number of keys
        
        :return: The number of keys
        """
        return len(self._keys)

    def get_key_with_kid(self, kid):
        """
        Return the key that has a specific key ID (kid)
        
        :param kid: The Key ID 
        :return: The key or None
        """
        for key in self._keys:
            if key.kid == kid:
                return key

        # Try updating since there might have been an update to the key file
        self.update()

        for key in self._keys:
            if key.kid == kid:
                return key

        return None

    def kids(self):
        """
        Return a list of key IDs. Note that this list may be shorter then
        the list of keys. The reason might be that there are some keys with
        no key ID.
        
        :return: A list of all the key IDs that exists in this bundle 
        """
        self._uptodate()
        return [key.kid for key in self._keys if key.kid != ""]

    def mark_as_inactive(self, kid):
        """
        Mark a specific key as inactive based on the keys KeyID
        
        :param kid: The Key Identifier 
        """
        k = self.get_key_with_kid(kid)
        k.inactive_since = time.time()

    def remove_outdated(self, after, when=0):
        """
        Remove keys that should not be available any more.
        Outdated means that the key was marked as inactive at a time
        that was longer ago then what is given in 'after'.

        :param after: The length of time the key will remain in the KeyBundle
            before it should be removed.
        :param when: To make it easier to test
        """
        if when:
            now = when
        else:
            now = time.time()

        if not isinstance(after, float):
            try:
                after = float(after)
            except TypeError:
                raise

        _kl = []
        for k in self._keys:
            if k.inactive_since and k.inactive_since + after < now:
                continue
            else:
                _kl.append(k)

        self._keys = _kl

    def __contains__(self, key):
        return key in self._keys

    def copy(self):
        """
        Make deep copy of this KeyBundle

        :return: The copy
        """
        kb = KeyBundle()
        kb._keys = self._keys[:]

        kb.cache_time = self.cache_time
        kb.verify_ssl = self.verify_ssl
        if self.source:
            kb.source = self.source
            kb.fileformat = self.fileformat
            kb.keytype = self.keytype
            kb.keyusage = self.keyusage
            kb.remote = self.remote

        return kb


def keybundle_from_local_file(filename, typ, usage):
    """
    Create a KeyBundle based on the content in a local file
    
    :param filename: Name of the file 
    :param typ: Type of content
    :param usage: What the key should be used for
    :return: The created KeyBundle
    """
    usage = harmonize_usage(usage)

    if typ.lower() == "jwks":
        kb = KeyBundle(source=filename, fileformat="jwks", keyusage=usage)
    elif typ.lower() == 'der':
        kb = KeyBundle(source=filename, fileformat="der", keyusage=usage)
    else:
        raise UnknownKeyType("Unsupported key type")

    return kb


def dump_jwks(kbl, target, private=False):
    """
    Write a JWK to a file. Will ignore symmetric keys !!

    :param kbl: List of KeyBundles
    :param target: Name of the file to which everything should be written
    :param private: Should also the private parts be exported
    """

    keys = []
    for kb in kbl:
        keys.extend([k.serialize(private) for k in kb.keys() if
                     k.kty != 'oct' and not k.inactive_since])
    res = {"keys": keys}

    try:
        f = open(target, 'w')
    except IOError:
        (head, tail) = os.path.split(target)
        os.makedirs(head)
        f = open(target, 'w')

    _txt = json.dumps(res)
    f.write(_txt)
    f.close()
