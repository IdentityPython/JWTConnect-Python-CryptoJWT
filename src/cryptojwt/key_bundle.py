import json
import logging
import os
import time
from functools import cmp_to_key

import requests

from cryptojwt.jwk.hmac import new_sym_key
from .exception import DeSerializationNotPossible
from .exception import JWKException
from .exception import UnknownKeyType
from .exception import UpdateFailed
from .jwk.ec import ECKey
from .jwk.ec import new_ec_key
from .jwk.hmac import SYMKey
from .jwk.rsa import RSAKey
from .jwk.rsa import import_private_rsa_key_from_file
from .jwk.rsa import new_rsa_key
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

    kb = KeyBundle(keytype="RSA")
    if 'use' in spec:
        for use in harmonize_usage(spec["use"]):
            _key = new_rsa_key(use=use, key_size=size)
            kb.append(_key)
    else:
        _key = new_rsa_key(key_size=size)
        kb.append(_key)

    return kb


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

    kb = KeyBundle(keytype="OCT")
    if 'use' in spec:
        for use in harmonize_usage(spec["use"]):
            _key = new_sym_key(use=use, bytes=size)
            kb.append(_key)
    else:
        _key = new_sym_key(bytes=size)
        kb.append(_key)

    return kb


def ec_init(spec):
    """
    Initiate a key bundle with an elliptic curve key.

    :param spec: Key specifics of the form::
        {"type": "EC", "crv": "P-256", "use": ["sig"]}

    :return: A KeyBundle instance
    """

    kb = KeyBundle(keytype="EC")
    if 'use' in spec:
        for use in spec["use"]:
            eck = new_ec_key(crv=spec['crv'], use=use)
            kb.append(eck)
    else:
        eck = new_ec_key(crv=spec['crv'])
        kb.append(eck)

    return kb


class KeyBundle(object):
    def __init__(self, keys=None, source="", cache_time=300, verify_ssl=True,
                 fileformat="jwks", keytype="RSA", keyusage=None, kid='',
                 httpc=None):
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
            presently only 'rsa' is supported.
        :param keyusage: What the key loaded from file should be used for.
            Only applicable for DER files
        :param httpc: A HTTP client function
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
            if httpc == requests.request:
                self.verify_ssl = verify_ssl
            else:
                self.verify_ssl = None
        else:
            self.httpc = requests.request
            self.verify_ssl = verify_ssl

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
                        if _key not in self._keys:
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
        _bkey = import_private_rsa_key_from_file(filename)

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
        if self.verify_ssl is not None:
            args = {"verify": self.verify_ssl}
        else:
            args = {}

        try:
            logging.debug('KeyBundle fetch keys from: {}'.format(self.source))
            r = self.httpc('GET', self.source, **args)
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
                    if self.fileformat in ["jwks", "jwk"]:
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
        else:
            return _keys

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

    def extend(self, keys):
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

    def __iter__(self):
        return self._keys.__iter__()


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


def build_key_bundle(key_conf, kid_template=""):
    """
    Builds a :py:class:`oidcmsg.key_bundle.KeyBundle` instance based on a key
    specification.

    An example of such a specification::

        keys = [
            {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"], "kid": "ec.1"},
            {"type": "EC", "crv": "P-256", "use": ["enc"], "kid": "ec.2"}
        ]

    Keys in this specification are:

    type
        The type of key. Presently only 'rsa' and 'ec' supported.

    key
        A name of a file where a key can be found. Only works with PEM encoded
        RSA keys

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

    tot_kb = KeyBundle()
    for spec in key_conf:
        typ = spec["type"].upper()

        if typ == "RSA":
            if "key" in spec:
                error_to_catch = (OSError, IOError,
                                  DeSerializationNotPossible)
                try:
                    kb = KeyBundle(source="file://%s" % spec["key"],
                                   fileformat="der",
                                   keytype=typ, keyusage=spec["use"])
                except error_to_catch:
                    kb = rsa_init(spec)
                except Exception:
                    raise
            else:
                kb = rsa_init(spec)
        elif typ == "EC":
            kb = ec_init(spec)
        elif typ.upper() == "OCT":
            kb = sym_init(spec)
        else:
            continue

        if 'kid' in spec and len(kb) == 1:
            ks = kb.keys()
            ks[0].kid = spec['kid']
        else:
            for k in kb.keys():
                if kid_template:
                    k.kid = kid_template % kid
                    kid += 1
                else:
                    k.add_kid()

        tot_kb.extend(kb.keys())

    return tot_kb


def _cmp(kd1, kd2):
    """
    Compare 2 keys

    :param kd1: First key
    :param kd2: Second key
    :return: -1,0,1 depending on whether kd1 is le,eq or gt then kd2
    """
    if kd1 == kd2:
        return 0
    elif kd1< kd2:
        return -1
    elif kd1 > kd2:
        return 1


def sort_func(kd1, kd2):
    """
    Compares 2 key descriptions
    :param kd1: First key description
    :param kd2: Second key description
    :return: -1,0,1 depending on whether kd1 le,eq or gt then kd2
    """
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
    elif _kid1:
        return -1
    elif _kid2:
        return 1

    return 0


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
    for kd in key_def:
        if len(kd['use']) > 1:
            for _use in kd['use']:
                _kd = kd.copy()
                _kd['use'] = _use
                _int.append(_kd)
        else:
            _int.append(kd)

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
        for kd in key_defs:
            if key.use not in kd['use']:
                continue

            if key.kty != kd['type']:
                continue

            if key.kty == 'EC':
                # special test only for EC keys
                if key.crv != kd['crv']:
                    continue

            try:
                _kid = kd['kid']
            except KeyError:
                pass
            else:
                if key.kid != _kid:
                    continue

            match = True
            used.append(kd)
            key_defs.remove(kd)
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


def key_rollover(kb):
    """
    A nifty function that lets you do a key rollover that encompasses creating
    a completely new set of keys. One new per every old one. With the same
    specifications as the old one.
    All the old ones are marked as inactive.

    :param kb:
    :return:
    """
    key_spec = []
    for key in kb.get():
        _spec = {'type': key.kty, 'use':[key.use]}
        if key.kty == 'EC':
            _spec['crv'] = key.crv

        key_spec.append(_spec)

    diff = {'del': kb.get()}
    _kb = build_key_bundle(key_spec)
    diff['add'] = _kb.keys()

    update_key_bundle(kb, diff)
    return kb
