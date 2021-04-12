"""Implementation of a Key Bundle."""
import copy
import json
import logging
import os
import time
from datetime import datetime
from functools import cmp_to_key
from typing import List
from typing import Optional

import requests
from readerwriterlock import rwlock

from cryptojwt.jwk.ec import NIST2SEC
from cryptojwt.jwk.hmac import new_sym_key
from cryptojwt.jwk.x509 import import_private_key_from_pem_file

from .exception import JWKException
from .exception import UnknownKeyType
from .exception import UnsupportedAlgorithm
from .exception import UnsupportedECurve
from .exception import UpdateFailed
from .jwk.ec import ECKey
from .jwk.ec import new_ec_key
from .jwk.hmac import SYMKey
from .jwk.jwk import dump_jwk
from .jwk.jwk import import_jwk
from .jwk.rsa import RSAKey
from .jwk.rsa import new_rsa_key
from .utils import as_unicode

__author__ = "Roland Hedberg"

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
REMOTE_FAILED = "Remote key update from '{}' failed, HTTP status {}"
MALFORMED = "Remote key update from {} failed, malformed JWKS."

LOGGER = logging.getLogger(__name__)

# def raise_exception(excep, descr, error='service_error'):
#     _err = json.dumps({'error': error, 'error_description': descr})
#     raise excep(_err, 'application/json')

# Make sure the keys are all uppercase
K2C = {"RSA": RSAKey, "EC": ECKey, "oct": SYMKey}

MAP = {"dec": "enc", "enc": "enc", "ver": "sig", "sig": "sig"}


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
        size = spec["size"]
    except KeyError:
        size = 2048

    _kb = KeyBundle(keytype="RSA")
    if "use" in spec:
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
        size = int(spec["bytes"])
    except KeyError:
        size = 24

    _kb = KeyBundle(keytype="oct")
    if "use" in spec:
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
    if "use" in spec:
        for use in spec["use"]:
            eck = new_ec_key(crv=curve, use=use)
            _kb.append(eck)
    else:
        eck = new_ec_key(crv=curve)
        _kb.append(eck)

    return _kb


def keys_reader(func):
    def wrapper(self, *args, **kwargs):
        with self._lock_reader:
            return func(self, *args, **kwargs)

    return wrapper


def keys_writer(func):
    def wrapper(self, *args, **kwargs):
        with self._lock_writer:
            return func(self, *args, **kwargs)

    return wrapper


class KeyBundle:
    """The Key Bundle"""

    params = {
        "cache_time": 0,
        "etag": "",
        "fileformat": "jwks",
        "httpc_params": {},
        "ignore_errors_period": 0,
        "ignore_errors_until": None,
        "ignore_invalid_keys": True,
        "imp_jwks": None,
        "keytype": "RSA",
        "keyusage": None,
        "last_local": None,
        "last_remote": None,
        "last_updated": 0,
        "local": False,
        "remote": False,
        "source": None,
        "time_out": 0,
    }

    def __init__(
        self,
        keys=None,
        source="",
        cache_time=300,
        ignore_errors_period=0,
        fileformat="jwks",
        keytype="RSA",
        keyusage=None,
        kid="",
        ignore_invalid_keys=True,
        httpc=None,
        httpc_params=None,
    ):
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
        :param fileformat: For a local file either "jwks" or "der"
        :param keytype: Iff local file and 'der' format what kind of key it is.
            presently 'rsa' and 'ec' are supported.
        :param keyusage: What the key loaded from file should be used for.
            Only applicable for DER files
        :param ignore_invalid_keys: Ignore invalid keys
        :param httpc: A HTTP client function
        :param httpc_params: Additional parameters to pass to the HTTP client
            function
        """

        self._keys = []
        self.cache_time = cache_time
        self.etag = ""
        self.fileformat = fileformat.lower()
        self.ignore_errors_period = ignore_errors_period
        self.ignore_errors_until = None  # UNIX timestamp of last error
        self.ignore_invalid_keys = ignore_invalid_keys
        self.imp_jwks = None
        self.keytype = keytype
        self.keyusage = keyusage
        self.last_local = None  # UNIX timestamp of last local update
        self.last_remote = None  # HTTP Date of last remote update
        self.last_updated = 0
        self.local = False
        self.remote = False
        self.source = None
        self.time_out = 0

        self._lock = rwlock.RWLockFairD()
        self._lock_reader = self._lock.gen_rlock()
        self._lock_writer = self._lock.gen_wlock()

        if httpc:
            self.httpc = httpc
        else:
            self.httpc = requests.request

        self.httpc_params = httpc_params or {}

        if keys:
            self.source = None
            if isinstance(keys, dict):
                if "keys" in keys:
                    self._do_keys(keys["keys"])
                else:
                    self._do_keys([keys])
            else:
                self._do_keys(keys)
        else:
            self._set_source(source, fileformat)
            if self.local:
                self._do_local(kid)

    def _set_source(self, source, fileformat):
        if source.startswith("file://"):
            self.source = source[7:]
            self.local = True
        elif source.startswith("http://") or source.startswith("https://"):
            self.source = source
            self.remote = True
        elif source == "":
            return
        else:
            if fileformat.lower() in ["rsa", "der", "jwks"]:
                if os.path.isfile(source):
                    self.source = source
                    self.local = True
                else:
                    raise ImportError("No such file")
            else:
                raise ImportError("Unknown source")

    def _do_local(self, kid):
        if self.fileformat in ["jwks", "jwk"]:
            self._do_local_jwk(self.source)
        elif self.fileformat == "der":
            self._do_local_der(self.source, self.keytype, self.keyusage, kid)

    def _local_update_required(self) -> bool:
        stat = os.stat(self.source)
        if self.last_local and stat.st_mtime < self.last_local:
            LOGGER.debug("%s not modfied", self.source)
            return False
        else:
            LOGGER.debug("%s modfied", self.source)
            self.last_local = stat.st_mtime
            return True

    @keys_writer
    def do_keys(self, keys):
        return self._do_keys(keys)

    def _do_keys(self, keys):
        """
        Go from JWK description to binary keys

        :param keys:
        :return:
        """
        _new_key = []

        for inst in keys:
            if inst["kty"].lower() in K2C:
                inst["kty"] = inst["kty"].lower()
            elif inst["kty"].upper() in K2C:
                inst["kty"] = inst["kty"].upper()
            else:
                if not self.ignore_invalid_keys:
                    raise UnknownKeyType(inst)
                LOGGER.warning("While loading keys, unknown key type: %s", inst["kty"])
                continue

            _typ = inst["kty"]
            try:
                _usage = harmonize_usage(inst["use"])
            except KeyError:
                _usage = [""]
            else:
                del inst["use"]

            _error = ""
            for _use in _usage:
                try:
                    _key = K2C[_typ](use=_use, **inst)
                except KeyError:
                    if not self.ignore_invalid_keys:
                        raise UnknownKeyType(inst)
                    _error = "UnknownKeyType: {}".format(_typ)
                    continue
                except (UnsupportedECurve, UnsupportedAlgorithm) as err:
                    if not self.ignore_invalid_keys:
                        raise err
                    _error = str(err)
                    break
                except JWKException as err:
                    if not self.ignore_invalid_keys:
                        raise err
                    LOGGER.warning("While loading keys: %s", err)
                    _error = str(err)
                else:
                    if _key not in self._keys:
                        if not _key.kid:
                            _key.add_kid()
                        _new_key.append(_key)
                    _error = ""

            if _error:
                LOGGER.warning("While loading keys, %s", _error)

        if _new_key:
            self._keys.extend(_new_key)

        self.last_updated = time.time()

    def _do_local_jwk(self, filename):
        """
        Load a JWKS from a local file

        :param filename: Name of the file from which the JWKS should be loaded
        :return: True if load was successful or False if file hasn't been modified
        """
        if not self._local_update_required():
            return False

        LOGGER.info("Reading local JWKS from %s", filename)
        with open(filename) as input_file:
            _info = json.load(input_file)
        if "keys" in _info:
            self._do_keys(_info["keys"])
        else:
            self._do_keys([_info])
        self.last_local = time.time()
        self.time_out = self.last_local + self.cache_time
        return True

    def _do_local_der(self, filename, keytype, keyusage=None, kid=""):
        """
        Load a DER encoded file amd create a key from it.

        :param filename: Name of the file
        :param keytype: Presently 'rsa' and 'ec' supported
        :param keyusage: encryption ('enc') or signing ('sig') or both
        :return: True if load was successful or False if file hasn't been modified
        """
        if not self._local_update_required():
            return False

        LOGGER.info("Reading local DER from %s", filename)
        key_args = {}
        _kty = keytype.lower()
        if _kty in ["rsa", "ec"]:
            key_args["kty"] = _kty
            _key = import_private_key_from_pem_file(filename)
            key_args["priv_key"] = _key
            key_args["pub_key"] = _key.public_key()
        else:
            raise NotImplementedError("No support for DER decoding of key type {}".format(_kty))

        if not keyusage:
            key_args["use"] = ["enc", "sig"]
        else:
            key_args["use"] = harmonize_usage(keyusage)

        if kid:
            key_args["kid"] = kid

        self._do_keys([key_args])
        self.last_local = time.time()
        self.time_out = self.last_local + self.cache_time
        return True

    def do_remote(self):
        """
        Load a JWKS from a webpage.

        :return: True if load was successful or False if remote hasn't been modified
        """
        # if self.verify_ssl is not None:
        #     self.httpc_params["verify"] = self.verify_ssl

        if self.ignore_errors_until and time.time() < self.ignore_errors_until:
            LOGGER.warning(
                "Not reading remote JWKS from %s (in error holddown until %s)",
                self.source,
                datetime.fromtimestamp(self.ignore_errors_until),
            )
            return False

        LOGGER.info("Reading remote JWKS from %s", self.source)
        try:
            LOGGER.debug("KeyBundle fetch keys from: %s", self.source)
            httpc_params = self.httpc_params.copy()
            if self.last_remote is not None:
                if "headers" not in httpc_params:
                    httpc_params["headers"] = {}
                httpc_params["headers"]["If-Modified-Since"] = self.last_remote
            _http_resp = self.httpc("GET", self.source, **httpc_params)
        except Exception as err:
            LOGGER.error(err)
            raise UpdateFailed(REMOTE_FAILED.format(self.source, str(err)))

        load_successful = _http_resp.status_code == 200
        not_modified = _http_resp.status_code == 304

        if load_successful:
            self.time_out = time.time() + self.cache_time

            self.imp_jwks = self._parse_remote_response(_http_resp)
            if not isinstance(self.imp_jwks, dict) or "keys" not in self.imp_jwks:
                raise UpdateFailed(MALFORMED.format(self.source))

            LOGGER.debug("Loaded JWKS: %s from %s", _http_resp.text, self.source)
            try:
                self._do_keys(self.imp_jwks["keys"])
            except KeyError:
                LOGGER.error("No 'keys' keyword in JWKS")
                self.ignore_errors_until = time.time() + self.ignore_errors_period
                raise UpdateFailed(MALFORMED.format(self.source))

            if hasattr(_http_resp, "headers"):
                headers = getattr(_http_resp, "headers")
                self.last_remote = headers.get("last-modified") or headers.get("date")
        elif not_modified:
            LOGGER.debug("%s not modified since %s", self.source, self.last_remote)
            self.time_out = time.time() + self.cache_time
        else:
            LOGGER.warning(
                "HTTP status %d reading remote JWKS from %s",
                _http_resp.status_code,
                self.source,
            )
            self.ignore_errors_until = time.time() + self.ignore_errors_period
            raise UpdateFailed(REMOTE_FAILED.format(self.source, _http_resp.status_code))

        self.last_updated = time.time()
        self.ignore_errors_until = None
        return load_successful

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
            if response.headers["Content-Type"] != "application/json":
                LOGGER.warning("Wrong Content_type (%s)", response.headers["Content-Type"])
        except KeyError:
            pass

        LOGGER.debug("Loaded JWKS: %s from %s", response.text, self.source)
        try:
            return json.loads(response.text)
        except ValueError:
            return None

    def _uptodate(self):
        if self.remote or self.local:
            if time.time() > self.time_out:
                return self.update()
        return False

    @keys_writer
    def update(self):
        """
        Reload the keys if necessary.

        This is a forced update, will happen even if cache time has not elapsed.
        Replaced keys will be marked as inactive and not removed.

        :return: True if update was ok or False if we encountered an error during update.
        """
        if self.source:
            _old_keys = self._keys  # just in case

            # reread everything
            self._keys = []
            updated = None

            try:
                if self.local:
                    if self.fileformat in ["jwks", "jwk"]:
                        updated = self._do_local_jwk(self.source)
                    elif self.fileformat == "der":
                        updated = self._do_local_der(self.source, self.keytype, self.keyusage)
                elif self.remote:
                    updated = self.do_remote()
            except Exception as err:
                LOGGER.error("Key bundle update failed: %s", err)
                self._keys = _old_keys  # restore
                return False

            if updated:
                now = time.time()
                for _key in _old_keys:
                    if _key not in self._keys:
                        if not _key.inactive_since:  # If already marked don't mess
                            _key.inactive_since = now
                        self._keys.append(_key)
            else:
                self._keys = _old_keys

        return True

    def get(self, typ="", only_active=True):
        """
        Return a list of keys. Either all keys or only keys of a specific type

        :param typ: Type of key (rsa, ec, oct, ..)
        :return: If typ is undefined all the keys as a dictionary
            otherwise the appropriate keys in a list
        """
        self._uptodate()

        with self._lock_reader:
            if typ:
                _typs = [typ.lower(), typ.upper()]
                _keys = [k for k in self._keys if k.kty in _typs]
            else:
                _keys = copy.copy(self._keys)

        if only_active:
            return [k for k in _keys if not k.inactive_since]

        return _keys

    def keys(self, update: bool = True):
        """
        Return all keys after having updated them

        :return: List of all keys
        """
        if update:
            self._uptodate()
        with self._lock_reader:
            return copy.copy(self._keys)

    def active_keys(self):
        """Return the set of active keys."""
        _res = []
        for k in self.keys():
            try:
                ias = k.inactive_since
            except ValueError:
                _res.append(k)
            else:
                if ias == 0:
                    _res.append(k)
        return _res

    @keys_writer
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
        keys = list()
        for k in self.keys():
            if private:
                key = k.serialize(private)
            else:
                key = k.serialize()
                for _attr, _val in key.items():
                    key[_attr] = as_unicode(_val)
            keys.append(key)
        return json.dumps({"keys": keys})

    @keys_writer
    def append(self, key):
        """
        Add a key to list of keys in this bundle

        :param key: Key to be added
        """
        self._keys.append(key)

    @keys_writer
    def extend(self, keys):
        """Add a key to the list of keys."""
        self._keys.extend(keys)

    @keys_writer
    def remove(self, key):
        """
        Remove a specific key from this bundle

        :param key: The key that should be removed
        """
        try:
            self._keys.remove(key)
        except ValueError:
            pass

    @keys_reader
    def __len__(self):
        """
        The number of keys.

        :return: The number of keys
        """
        return len(self._keys)

    @keys_writer
    def set(self, keys):
        """Set the keys to the set provided."""
        self._keys = keys

    def get_key_with_kid(self, kid):
        """
        Return the key that has a specific key ID (kid)

        :param kid: The Key ID
        :return: The key or None
        """
        self._uptodate()
        with self._lock_reader:
            return self._get_key_with_kid(kid)

    def _get_key_with_kid(self, kid):
        for key in self._keys:
            if key.kid == kid:
                return key

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
        return [key.kid for key in self.keys() if key.kid != ""]

    @keys_writer
    def mark_as_inactive(self, kid):
        """
        Mark a specific key as inactive based on the keys KeyID.

        :param kid: The Key Identifier
        """
        k = self._get_key_with_kid(kid)
        if k:
            self._keys.remove(k)
            k.inactive_since = time.time()
            self._keys.append(k)
            return True
        else:
            return False

    @keys_writer
    def mark_all_as_inactive(self):
        """
        Mark a specific key as inactive based on the keys KeyID.
        """
        _keys = self._keys
        _updated = []
        for k in _keys:
            k.inactive_since = time.time()
            _updated.append(k)
        self._keys = _updated

    @keys_writer
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
        changed = False
        for k in self._keys:
            if k.inactive_since and k.inactive_since + after < now:
                changed = True
                continue

            _kl.append(k)

        self._keys = _kl
        return changed

    def __contains__(self, key):
        return key in self.keys()

    @keys_reader
    def copy(self):
        """
        Make deep copy of this KeyBundle

        :return: The copy
        """
        _bundle = KeyBundle()
        _bundle._keys = self._keys[:]

        _bundle.cache_time = self.cache_time
        _bundle.httpc_params = copy.deepcopy(self.httpc_params)
        if self.source:
            _bundle.source = self.source
            _bundle.fileformat = self.fileformat
            _bundle.keytype = self.keytype
            _bundle.keyusage = self.keyusage
            _bundle.remote = self.remote

        return _bundle

    def __iter__(self):
        return self.keys().__iter__()

    def difference(self, bundle):
        """
        Return a set of keys that appears in this key bundle but not in the other.

        :param bundle: A KeyBundle instance
        :return: A list of keys
        """
        if not isinstance(bundle, KeyBundle):
            return ValueError("Not a KeyBundle instance")

        return [k for k in self.keys() if k not in bundle]

    def dump(self, exclude_attributes: Optional[List[str]] = None):
        if exclude_attributes is None:
            exclude_attributes = []

        res = {}

        if "keys" not in exclude_attributes:
            _keys = []
            for _k in self.keys(update=False):
                _ser = _k.to_dict()
                if _k.inactive_since:
                    _ser["inactive_since"] = _k.inactive_since
                _keys.append(_ser)
            res["keys"] = _keys

        for attr, default in self.params.items():
            if attr in exclude_attributes:
                continue
            val = getattr(self, attr)
            res[attr] = val

        return res

    @keys_writer
    def load(self, spec):
        """
        Sets attributes according to a specification.
        Does not overwrite an existing attributes value with a default value.

        :param spec: Dictionary with attributes and value to populate the instance with
        :return: The instance itself
        """
        _keys = spec.get("keys", [])
        if _keys:
            self._do_keys(_keys)

        for attr, default in self.params.items():
            val = spec.get(attr)
            if val:
                setattr(self, attr, val)

        return self

    @keys_writer
    def flush(self):
        self._keys = []
        self.cache_time = (300,)
        self.etag = ""
        self.fileformat = "jwks"
        # self.httpc=None,
        self.httpc_params = (None,)
        self.ignore_errors_period = 0
        self.ignore_errors_until = None
        self.ignore_invalid_keys = True
        self.imp_jwks = None
        self.keytype = ("RSA",)
        self.keyusage = (None,)
        self.last_local = None  # UNIX timestamp of last local update
        self.last_remote = None  # HTTP Date of last remote update
        self.last_updated = 0
        self.local = False
        self.remote = False
        self.source = None
        self.time_out = 0
        return self


def keybundle_from_local_file(filename, typ, usage=None, keytype="RSA"):
    """
    Create a KeyBundle based on the content in a local file.

    :param filename: Name of the file
    :param typ: Type of content
    :param usage: What the keys should be used for
    :param keytype: Type of key, e.g. "RSA", "EC". Only used with typ='der'
    :return: The created KeyBundle
    """
    usage = harmonize_usage(usage)

    if typ.lower() == "jwks":
        _bundle = KeyBundle(source=filename, fileformat="jwks", keyusage=usage)
    elif typ.lower() == "der":
        _bundle = KeyBundle(source=filename, fileformat="der", keyusage=usage, keytype=keytype)
    else:
        raise UnknownKeyType("Unsupported key type")

    return _bundle


def dump_jwks(kbl, target, private=False, symmetric_too=False):
    """
    Write a JWK to a file.

    :param kbl: List of KeyBundles
    :param target: Name of the file to which everything should be written
    :param private: Should also the private parts be exported
    :param symmetric_too: Include symmetric keys or not
    """

    keys = []
    for _bundle in kbl:
        if symmetric_too:
            keys.extend([k.serialize(private) for k in _bundle.keys() if not k.inactive_since])
        else:
            keys.extend(
                [
                    k.serialize(private)
                    for k in _bundle.keys()
                    if k.kty != "oct" and not k.inactive_since
                ]
            )

    res = {"keys": keys}

    try:
        _fp = open(target, "w")
    except IOError:
        head, _ = os.path.split(target)
        os.makedirs(head)
        _fp = open(target, "w")

    _txt = json.dumps(res)
    _fp.write(_txt)
    _fp.close()


def _set_kid(spec, bundle, kid_template, kid):
    if "kid" in spec and len(bundle) == 1:
        _keys = bundle.keys()
        _keys[0].kid = spec["kid"]
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
            {"type": "oct", "bytes":}
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

    _bundles = []
    for spec in key_conf:
        typ = spec["type"].upper()

        _bundle = None
        if typ == "RSA":
            if "key" in spec and spec["key"]:
                if os.path.isfile(spec["key"]):
                    _bundle = KeyBundle(
                        source="file://%s" % spec["key"],
                        fileformat="der",
                        keytype=typ,
                        keyusage=spec["use"],
                    )
            else:
                _bundle = rsa_init(spec)
        elif typ == "EC":
            if "key" in spec and spec["key"]:
                if os.path.isfile(spec["key"]):
                    _bundle = KeyBundle(
                        source="file://%s" % spec["key"],
                        fileformat="der",
                        keytype=typ,
                        keyusage=spec["use"],
                    )
            else:
                _bundle = ec_init(spec)
        elif typ.lower() == "oct":
            _bundle = sym_init(spec)
        else:
            continue

        if not _bundle:
            continue

        _set_kid(spec, _bundle, kid_template, kid)
        _bundles.append(_bundle)

    if _bundles:
        complete_bundle = KeyBundle()
        for _bundle in _bundles:
            complete_bundle.extend(_bundle.keys())

        return complete_bundle
    else:
        return None


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
    _l = _cmp(kd1["type"], kd2["type"])
    if _l:
        return _l

    if kd1["type"] == "EC":
        _l = _cmp(kd1["crv"], kd2["crv"])
        if _l:
            return _l

    _l = _cmp(kd1["type"], kd2["type"])
    if _l:
        return _l

    _l = _cmp(kd1["use"][0], kd2["use"][0])
    if _l:
        return _l

    return None


def kid_order(kd1, kd2):
    """Order key descriptions by kid."""
    try:
        _kid1 = kd1["kid"]
    except KeyError:
        _kid1 = None

    try:
        _kid2 = kd2["kid"]
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
        if len(_def["use"]) > 1:
            for _use in _def["use"]:
                _kd = _def.copy()
                _kd["use"] = _use
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
            if key.use not in key_def["use"]:
                continue

            if key.kty != key_def["type"]:
                continue

            if key.kty == "EC":
                # special test only for EC keys
                if key.crv != key_def["crv"]:
                    continue

            try:
                _kid = key_def["kid"]
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
                diff["del"].append(key)
            except KeyError:
                diff["del"] = [key]

    if key_defs:
        _kb = build_key_bundle(key_defs)
        diff["add"] = _kb.keys()

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
        _add = diff["add"]
    except KeyError:
        pass
    else:
        key_bundle.extend(_add)

    try:
        _del = diff["del"]
    except KeyError:
        pass
    else:
        _now = time.time()
        _keys = key_bundle.keys()
        for k in _del:
            _keys.remove(k)
            k.inactive_since = _now
            _keys.append(k)
        key_bundle.set(_keys)


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
        _spec = {"type": key.kty, "use": [key.use]}
        if key.kty == "EC":
            _spec["crv"] = key.crv

        key_spec.append(_spec)

    diff = {"del": bundle.get()}
    _kb = build_key_bundle(key_spec)
    diff["add"] = _kb.keys()

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
DEFAULT_EC_CURVE = "P-256"


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

    if type.upper() == "RSA":
        keysize = kwargs.get("size", DEFAULT_RSA_KEYSIZE)
        public_exponent = kwargs.get("exp", DEFAULT_RSA_EXP)
        _key = new_rsa_key(public_exponent=public_exponent, key_size=keysize, **kargs)
    elif type.upper() == "EC":
        crv = kwargs.get("crv", DEFAULT_EC_CURVE)
        if crv not in NIST2SEC:
            logging.error("Unknown curve: %s", crv)
            raise ValueError("Unknown curve: {}".format(crv))
        _key = new_ec_key(crv=crv, **kargs)
    elif type.lower() in ["sym", "oct"]:
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


def key_by_alg(alg: str):
    if alg.startswith("RS"):
        return key_gen("RSA", alg="RS256")
    elif alg.startswith("ES"):
        if alg == "ES256":
            return key_gen("EC", crv="P-256")
        elif alg == "ES384":
            return key_gen("EC", crv="P-384")
        elif alg == "ES512":
            return key_gen("EC", crv="P-521")
    elif alg.startswith("HS"):
        return key_gen("sym")

    raise ValueError("Don't know who to create a key to use with '{}'".format(alg))
