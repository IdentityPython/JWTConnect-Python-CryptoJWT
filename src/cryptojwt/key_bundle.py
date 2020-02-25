"""Implementation of a Key Bundle."""
import json
import logging
import os
import time
from functools import cmp_to_key

import requests
from cryptojwt.jwk.ec import NIST2SEC
from cryptojwt.jwk.hmac import new_sym_key

from .exception import DeSerializationNotPossible
from .exception import JWKException
from .exception import UnknownKeyType
from .exception import UpdateFailed
from .jwk.ec import ECKey
from .jwk.ec import import_private_key_from_file
from .jwk.ec import new_ec_key
from .jwk.hmac import SYMKey
from .jwk.jwk import dump_jwk
from .jwk.jwk import import_jwk
from .jwk.rsa import RSAKey
from .jwk.rsa import import_private_rsa_key_from_file
from .jwk.rsa import new_rsa_key
from .utils import as_unicode

__author__ = 'Roland Hedberg'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
REMOTE_FAILED = "Remote key update from '{}' failed, HTTP status {}"
MALFORMED = "Remote key update from {} failed, malformed JWKS."

LOGGER = logging.getLogger(__name__)

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

    if isinstance(use, list):
        _ul = list(MAP.keys())
        _us = {MAP[u] for u in use if u in _ul}
        return list(_us)

    return None


def rsa_init(spec):
    """
    Initiates a :py:class:`oidcmsg.keybundle.KeyBundle` instance
    containing newly minted RSA keys according to a spec.

    Example of specification::
        {'size':2048, 'use': ['enc', 'sig'] }

    Using the spec above 2 RSA keys would be minted, one for
    encryption and one for signing.
    :param spec:
    :return: KeyBundle
    """

    try:
        size = spec['size']
    except KeyError:
        size = 2048

    _kb = KeyBundle(keytype="RSA")
    if 'use' in spec:
        for use in harmonize_usage(spec["use"]):
            _key = new_rsa_key(use=use, key_size=size)
            _kb.append(_key)
    else:
        _key = new_rsa_key(key_size=size)
        _kb.append(_key)

    return _kb


def sym_init(spec):
    """
    Initiates a :py:class:`oidcmsg.keybundle.KeyBundle` instance
    containing newly minted SYM keys according to a spec.

    Example of specification::
        {'bytes':24, 'use': ['enc', 'sig'] }

    Using the spec above 2 SYM keys would be minted, one for
    encryption and one for signing.

    :param spec:
    :return: KeyBundle
    """

    try:
        size = int(spec['bytes'])
    except KeyError:
        size = 24

    _kb = KeyBundle(keytype="OCT")
    if 'use' in spec:
        for use in harmonize_usage(spec["use"]):
            _key = new_sym_key(use=use, bytes=size)
            _kb.append(_key)
    else:
        _key = new_sym_key(bytes=size)
        _kb.append(_key)

    return _kb


def ec_init(spec):
    """
    Initiate a key bundle with an elliptic curve key.

    :param spec: Key specifics of the form::
        {"type": "EC", "crv": "P-256", "use": ["sig"]}

    :return: A KeyBundle instance
    """
    curve = spec.get("crv", "P-256")

    _kb = KeyBundle(keytype="EC")
    if 'use' in spec:
        for use in spec["use"]:
            eck = new_ec_key(crv=curve, use=use)
            _kb.append(eck)
    else:
        eck = new_ec_key(crv=curve)
        _kb.append(eck)

    return _kb


class KeyBundle:
    """The Key Bundle"""

    def __init__(self, keys=None, source="", cache_time=300, verify_ssl=True,
                 fileformat="jwks", keytype="RSA", keyusage=None, kid='',
                 httpc=None, httpc_params=None):
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
        :param fileformat: For a local file either "jwks" or "der"
        :param keytype: Iff local file and 'der' format what kind of key it is.
            presently 'rsa' and 'ec' are supported.
        :param keyusage: What the key loaded from file should be used for.
            Only applicable for DER files
        :param httpc: A HTTP client function
        :param httpc_params: Additional parameters to pass to the HTTP client
            function
        """

        self._keys = []
        self.remote = False
        self.cache_time = cache_time
        self.time_out = 0
        self.etag = ""
        self.source = None
        self.fileformat = fileformat.lower()
        self.keytype = keytype
        self.keyusage = keyusage
        self.imp_jwks = None
        self.last_updated = 0

        if httpc:
            self.httpc = httpc
        else:
            self.httpc = requests.request

        self.httpc_params = httpc_params or {}

        if keys:
            self.source = None
            if isinstance(keys, dict):
                if 'keys' in keys:
                    self.do_keys(keys['keys'])
                else:
                    self.do_keys([keys])
            else:
                self.do_keys(keys)
        else:
            self._set_source(source, fileformat)

            if not self.remote and self.source:  # local file
                self._do_local(kid)

    def _set_source(self, source, fileformat):
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

    def _do_local(self, kid):
        if self.fileformat in ['jwks', "jwk"]:
            self.do_local_jwk(self.source)
        elif self.fileformat == "der":
            self.do_local_der(self.source, self.keytype, self.keyusage, kid)

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
                        LOGGER.warning('While loading keys: %s', err)
                    else:
                        if _key not in self._keys:
                            if not _key.kid:
                                _key.add_kid()
                            self._keys.append(_key)
                        flag = 1
                        break
            if not flag:
                LOGGER.warning(
                    'While loading keys, UnknownKeyType: %s', typ)

    def do_local_jwk(self, filename):
        """
        Load a JWKS from a local file

        :param filename: Name of the file from which the JWKS should be loaded
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

        :param filename: Name of the file
        :param keytype: Presently 'rsa' and 'ec' supported
        :param keyusage: encryption ('enc') or signing ('sig') or both
        """
        if keytype.lower() == 'rsa':
            _bkey = import_private_rsa_key_from_file(filename)
            _key = RSAKey().load_key(_bkey)
        elif keytype.lower() == 'ec':
            _bkey = import_private_key_from_file(filename)
            _key = ECKey().load_key(_bkey)
        else:
            raise NotImplementedError('No support for DER decoding of that key type')

        if not keyusage:
            keyusage = ["enc", "sig"]
        else:
            keyusage = harmonize_usage(keyusage)

        for use in keyusage:
            _key.use = use
            if kid:
                _key.kid = kid
            if not _key.kid:
                _key.add_kid()
            self._keys.append(_key)

        self.last_updated = time.time()

    def do_remote(self):
        """
        Load a JWKS from a webpage.

        :return: True or False if load was successful
        """
        # if self.verify_ssl is not None:
        #     self.httpc_params["verify"] = self.verify_ssl

        try:
            LOGGER.debug('KeyBundle fetch keys from: %s', self.source)
            _http_resp = self.httpc('GET', self.source, **self.httpc_params)
        except Exception as err:
            LOGGER.error(err)
            raise UpdateFailed(
                REMOTE_FAILED.format(self.source, str(err)))

        if _http_resp.status_code == 200:  # New content
            self.time_out = time.time() + self.cache_time

            self.imp_jwks = self._parse_remote_response(_http_resp)
            if not isinstance(self.imp_jwks,
                              dict) or "keys" not in self.imp_jwks:
                raise UpdateFailed(MALFORMED.format(self.source))

            LOGGER.debug("Loaded JWKS: %s from %s", _http_resp.text, self.source)
            try:
                self.do_keys(self.imp_jwks["keys"])
            except KeyError:
                LOGGER.error("No 'keys' keyword in JWKS")
                raise UpdateFailed(MALFORMED.format(self.source))

        else:
            raise UpdateFailed(
                REMOTE_FAILED.format(self.source, _http_resp.status_code))
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
                LOGGER.warning('Wrong Content_type (%s)', response.headers["Content-Type"])
        except KeyError:
            pass

        LOGGER.debug("Loaded JWKS: %s from %s", response.text, self.source)
        try:
            return json.loads(response.text)
        except ValueError:
            return None

    def _uptodate(self):
        res = False
        if not self._keys:
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
        Reload the keys if necessary.

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
                    if self.fileformat in ["jwks", "jwk"]:
                        self.do_local_jwk(self.source)
                    elif self.fileformat == "der":
                        self.do_local_der(self.source, self.keytype,
                                          self.keyusage)
                else:
                    res = self.do_remote()
            except Exception as err:
                LOGGER.error('Key bundle update failed: %s', err)
                self._keys = _keys  # restore
                return False

            now = time.time()
            for _key in _keys:
                if _key not in self._keys:
                    if not _key.inactive_since:  # If already marked don't mess
                        _key.inactive_since = now
                    self._keys.append(_key)

        return res

    def get(self, typ="", only_active=True):
        """
        Return a list of keys. Either all keys or only keys of a specific type

        :param typ: Type of key (rsa, ec, oct, ..)
        :return: If typ is undefined all the keys as a dictionary
            otherwise the appropriate keys in a list
        """
        self._uptodate()
        _typs = [typ.lower(), typ.upper()]

        if typ:
            _keys = [k for k in self._keys if k.kty in _typs]
        else:
            _keys = self._keys

        if only_active:
            return [k for k in _keys if not k.inactive_since]

        return _keys

    def keys(self):
        """
        Return all keys after having updated them

        :return: List of all keys
        """
        self._uptodate()

        return self._keys

    def active_keys(self):
        """Return the set of active keys."""
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
        Create a JWKS as a JSON document

        :param private: Whether private key information should be included.
        :return: A JWKS JSON representation of the keys in this bundle
        """
        self._uptodate()
        keys = list()
        for k in self._keys:
            if private:
                key = k.serialize(private)
            else:
                key = k.serialize()
                for _attr, _val in key.items():
                    key[_attr] = as_unicode(_val)
            keys.append(key)
        return json.dumps({"keys": keys})

    def append(self, key):
        """
        Add a key to list of keys in this bundle

        :param key: Key to be added
        """
        self._keys.append(key)

    def extend(self, keys):
        """Add a key to the list of keys."""
        self._keys.extend(keys)

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
        The number of keys.

        :return: The number of keys
        """
        return len(self._keys)

    def set(self, keys):
        """Set the keys to the set provided."""
        self._keys = keys

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
        Return a list of key IDs.

        Note that this list may be shorter then the list of keys.
        The reason might be that there are some keys with no key ID.
        :return: A list of all the key IDs that exists in this bundle
        """
        self._uptodate()
        return [key.kid for key in self._keys if key.kid != ""]

    def mark_as_inactive(self, kid):
        """
        Mark a specific key as inactive based on the keys KeyID.

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
            after = float(after)

        _kl = []
        for k in self._keys:
            if k.inactive_since and k.inactive_since + after < now:
                continue

            _kl.append(k)

        self._keys = _kl

    def __contains__(self, key):
        return key in self._keys

    def copy(self):
        """
        Make deep copy of this KeyBundle

        :return: The copy
        """
        _bundle = KeyBundle()
        _bundle.set(self._keys[:])

        _bundle.cache_time = self.cache_time
        _bundle.httpc_params = self.httpc_params.copy()
        if self.source:
            _bundle.source = self.source
            _bundle.fileformat = self.fileformat
            _bundle.keytype = self.keytype
            _bundle.keyusage = self.keyusage
            _bundle.remote = self.remote

        return _bundle

    def __iter__(self):
        return self._keys.__iter__()

    def difference(self, bundle):
        """
        Return a set of keys that appears in this key bundle but not in the other.

        :param bundle: A KeyBundle instance
        :return: A list of keys
        """
        if not isinstance(bundle, KeyBundle):
            return ValueError('Not a KeyBundle instance')

        return [k for k in self._keys if k not in bundle]


def keybundle_from_local_file(filename, typ, usage, keytype="RSA"):
    """
    Create a KeyBundle based on the content in a local file.

    :param filename: Name of the file
    :param typ: Type of content
    :param usage: What the key should be used for
    :param keytype: Type of key, e.g. "RSA", "EC". Only used with typ='der'
    :return: The created KeyBundle
    """
    usage = harmonize_usage(usage)

    if typ.lower() == "jwks":
        _bundle = KeyBundle(source=filename, fileformat="jwks", keyusage=usage)
    elif typ.lower() == "der":
        _bundle = KeyBundle(source=filename,
                            fileformat="der",
                            keyusage=usage,
                            keytype=keytype)
    else:
        raise UnknownKeyType("Unsupported key type")

    return _bundle


def dump_jwks(kbl, target, private=False):
    """
    Write a JWK to a file. Will ignore symmetric keys !!

    :param kbl: List of KeyBundles
    :param target: Name of the file to which everything should be written
    :param private: Should also the private parts be exported
    """

    keys = []
    for _bundle in kbl:
        keys.extend([k.serialize(private) for k in _bundle.keys() if
                     k.kty != 'oct' and not k.inactive_since])
    res = {"keys": keys}

    try:
        _fp = open(target, 'w')
    except IOError:
        head, _ = os.path.split(target)
        os.makedirs(head)
        _fp = open(target, 'w')

    _txt = json.dumps(res)
    _fp.write(_txt)
    _fp.close()


def _set_kid(spec, bundle, kid_template, kid):
    if 'kid' in spec and len(bundle) == 1:
        _keys = bundle.keys()
        _keys[0].kid = spec['kid']
    else:
        for k in bundle.keys():
            if kid_template:
                k.kid = kid_template % kid
                kid += 1
            else:
                k.add_kid()


def build_key_bundle(key_conf, kid_template=""):
    """
    Builds a :py:class:`oidcmsg.key_bundle.KeyBundle` instance based on a key
    specification.

    An example of such a specification::

        keys = [
            {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"], 'size': 2048},
            {"type": "EC", "crv": "P-256", "use": ["sig"], "kid": "ec.1"},
            {"type": "EC", "crv": "P-256", "use": ["enc"], "kid": "ec.2"},
            {"type": "OCT", "bytes":}
        ]

    Keys in this specification are:

    type
        The type of key. Presently only 'rsa', 'ec' and 'oct' supported.

    key
        A name of a file where a key can be found. Works with PEM encoded
        RSA and EC private keys.

    use
        What the key should be used for

    crv
        The elliptic curve that should be used. Only applies to elliptic curve
        keys :-)

    kid
        Key ID, can only be used with one usage type is specified. If there
        are more the one usage type specified 'kid' will just be ignored.

    :param key_conf: The key configuration
    :param kid_template: A template by which to build the key IDs. If no
        kid_template is given then the built-in function add_kid() will be used.
    :return: A KeyBundle instance
    """

    kid = 0

    complete_bundle = KeyBundle()
    for spec in key_conf:
        typ = spec["type"].upper()

        if typ == "RSA":
            if "key" in spec and spec["key"]:
                error_to_catch = (OSError, IOError,
                                  DeSerializationNotPossible)
                try:
                    _bundle = KeyBundle(source="file://%s" % spec["key"],
                                        fileformat="der",
                                        keytype=typ, keyusage=spec["use"])
                except error_to_catch:
                    _bundle = rsa_init(spec)
            else:
                _bundle = rsa_init(spec)
        elif typ == "EC":
            if "key" in spec and spec["key"]:
                error_to_catch = (OSError, IOError,
                                  DeSerializationNotPossible)
                try:
                    _bundle = KeyBundle(source="file://%s" % spec["key"],
                                        fileformat="der",
                                        keytype=typ, keyusage=spec["use"])
                except error_to_catch:
                    _bundle = ec_init(spec)
            else:
                _bundle = ec_init(spec)
        elif typ.upper() == "OCT":
            _bundle = sym_init(spec)
        else:
            continue

        _set_kid(spec, _bundle, kid_template, kid)

        complete_bundle.extend(_bundle.keys())

    return complete_bundle


def _cmp(kd1, kd2):
    """
    Compare 2 keys

    :param kd1: First key
    :param kd2: Second key
    :return: -1,0,1 depending on whether kd1 is le,eq or gt then kd2
    """
    if kd1 == kd2:
        return 0

    if kd1 < kd2:
        return -1

    return 1


def type_order(kd1, kd2):
    """Order the key descriptions by type."""
    _l = _cmp(kd1['type'], kd2['type'])
    if _l:
        return _l

    if kd1['type'] == 'EC':
        _l = _cmp(kd1['crv'], kd2['crv'])
        if _l:
            return _l

    _l = _cmp(kd1['type'], kd2['type'])
    if _l:
        return _l

    _l = _cmp(kd1['use'][0], kd2['use'][0])
    if _l:
        return _l

    return None


def kid_order(kd1, kd2):
    """Order key descriptions by kid."""
    try:
        _kid1 = kd1['kid']
    except KeyError:
        _kid1 = None

    try:
        _kid2 = kd2['kid']
    except KeyError:
        _kid2 = None

    if _kid1 and _kid2:
        return _cmp(_kid1, _kid2)

    if _kid1:
        return -1

    if _kid2:
        return 1

    return 0


def sort_func(kd1, kd2):
    """
    Compares 2 key descriptions
    :param kd1: First key description
    :param kd2: Second key description
    :return: -1,0,1 depending on whether kd1 le,eq or gt then kd2
    """

    _c = type_order(kd1, kd2)
    if _c is not None:
        return _c

    return kid_order(kd1, kd2)


def order_key_defs(key_def):
    """
    Sort a set of key definitions. A key definition that defines more then
    one usage type are splitted into as many definitions as the number of
    usage types specified. One key definition per usage type.

    :param key_def: A set of key definitions
    :return: The set of definitions as a sorted list
    """
    _int = []
    # First make sure all defs only reference one usage
    for _def in key_def:
        if len(_def['use']) > 1:
            for _use in _def['use']:
                _kd = _def.copy()
                _kd['use'] = _use
                _int.append(_kd)
        else:
            _int.append(_def)

    _int.sort(key=cmp_to_key(sort_func))

    return _int


def key_diff(key_bundle, key_defs):
    """
    Creates a difference dictionary with keys that should added and keys that
    should be deleted from a Key Bundle to get it updated to a state that
    mirrors What is in the key_defs specification.

    :param key_bundle: The original KeyBundle
    :param key_defs: A set of key definitions
    :return: A dictionary with possible keys 'add' and 'del'. The values
        for the keys are lists of :py:class:`cryptojwt.jwk.JWK` instances
    """

    keys = key_bundle.get()
    diff = {}

    # My own sorted copy
    key_defs = order_key_defs(key_defs)[:]
    used = []

    for key in keys:
        match = False
        for key_def in key_defs:
            if key.use not in key_def['use']:
                continue

            if key.kty != key_def['type']:
                continue

            if key.kty == 'EC':
                # special test only for EC keys
                if key.crv != key_def['crv']:
                    continue

            try:
                _kid = key_def['kid']
            except KeyError:
                pass
            else:
                if key.kid != _kid:
                    continue

            match = True
            used.append(key_def)
            key_defs.remove(key_def)
            break

        if not match:
            try:
                diff['del'].append(key)
            except KeyError:
                diff['del'] = [key]

    if key_defs:
        _kb = build_key_bundle(key_defs)
        diff['add'] = _kb.keys()

    return diff


def update_key_bundle(key_bundle, diff):
    """
    Apply a diff specification to a KeyBundle.
    The keys that are to be added are added.
    The keys that should be deleted are marked as inactive.

    :param key_bundle: The original KeyBundle
    :param diff: The difference specification
    :return: An updated key_bundle
    """
    try:
        _add = diff['add']
    except KeyError:
        pass
    else:
        key_bundle.extend(_add)

    try:
        _del = diff['del']
    except KeyError:
        pass
    else:
        _now = time.time()
        for k in _del:
            k.inactive_since = _now


def key_rollover(bundle):
    """
    A nifty function that lets you do a key rollover that encompasses creating
    a completely new set of keys. One new per every old one. With the same
    specifications as the old one.
    All the old ones are marked as inactive.

    :param bundle: Old KeyBundle
    :return: New KeyBundle
    """
    key_spec = []
    for key in bundle.get():
        _spec = {'type': key.kty, 'use': [key.use]}
        if key.kty == 'EC':
            _spec['crv'] = key.crv

        key_spec.append(_spec)

    diff = {'del': bundle.get()}
    _kb = build_key_bundle(key_spec)
    diff['add'] = _kb.keys()

    update_key_bundle(bundle, diff)
    return bundle


def unique_keys(keys):
    """
    From a list of given keys, return the unique keys.

    :param keys: List of keys
    :return: List of unique keys
    """

    unique = []

    for k in keys:
        if k not in unique:
            unique.append(k)

    return unique


DEFAULT_SYM_KEYSIZE = 32
DEFAULT_RSA_KEYSIZE = 2048
DEFAULT_RSA_EXP = 65537
DEFAULT_EC_CURVE = 'P-256'


def key_gen(type, **kwargs):
    """
    Create a key and return it as a JWK.

    :param type: Key type (RSA, EC, OCT)
    :param kid:
    :param kwargs: key specific keyword arguments
        RSA: size, exp
        EC: crv
        SYM: bytes
    """
    # common args are use, key_ops and alg
    kargs = {k: v for k, v in kwargs.items() if k in ["use", "key_ops", "alg", "kid"]}

    if type.upper() == 'RSA':
        keysize = kwargs.get("size", DEFAULT_RSA_KEYSIZE)
        public_exponent = kwargs.get("exp", DEFAULT_RSA_EXP)
        _key = new_rsa_key(public_exponent=public_exponent, key_size=keysize, **kargs)
    elif type.upper() == 'EC':
        crv = kwargs.get("crv", DEFAULT_EC_CURVE)
        if crv not in NIST2SEC:
            logging.error("Unknown curve: %s", crv)
            raise ValueError("Unknown curve: {}".format(crv))
        _key = new_ec_key(crv=crv, **kargs)
    elif type.upper() in ["SYM", "OCT"]:
        keysize = kwargs.get("bytes", 24)
        randomkey = os.urandom(keysize)
        _key = SYMKey(key=randomkey, **kargs)
    else:
        logging.error("Unknown key type: %s", type)
        raise ValueError("Unknown key type: %s".format(type))

    return _key


def init_key(filename, type, kid="", **kwargs):
    if os.path.isfile(filename):
        _old_key = import_jwk(filename)

        if _old_key.kty == type:
            if not kid or _old_key.kid == kid:
                return _old_key

    _new_key = key_gen(type, kid=kid, **kwargs)
    dump_jwk(filename, _new_key)
    return _new_key
