import json
import logging
import os
from typing import List
from typing import Optional

from requests import request

from .jwe.utils import alg2keytype as jwe_alg2keytype
from .jws.utils import alg2keytype as jws_alg2keytype
from .key_bundle import KeyBundle
from .key_bundle import build_key_bundle
from .key_bundle import key_diff
from .key_bundle import update_key_bundle
from .utils import importer
from .utils import qualified_name

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class KeyIssuer(object):
    """ A key issuer instance contains a number of KeyBundles. """

    params = {
        "ca_certs": None,
        "httpc_params": None,
        "keybundle_cls": KeyBundle,
        "name": "",
        "remove_after": 3600,
        "spec2key": None,
    }

    def __init__(
        self,
        ca_certs=None,
        keybundle_cls=KeyBundle,
        remove_after=3600,
        httpc=None,
        httpc_params=None,
        name="",
    ):
        """
        KeyIssuer init function

        :param ca_certs: CA certificates, to be used for HTTPS
        :param keybundle_cls: The KeyBundle class
        :param remove_after: How long keys marked as inactive will remain in the key Jar.
        :param httpc: A HTTP client to use. Default is Requests request.
        :param httpc_params: HTTP request parameters
        :param name: Issuer identifier
        :return: KeyIssuer instance
        """

        self._bundles = []

        self.ca_certs = ca_certs
        self.httpc = httpc or request
        self.httpc_params = httpc_params or {}
        self.keybundle_cls = keybundle_cls
        self.name = name
        self.remove_after = remove_after
        self.spec2key = {}

    def __repr__(self) -> str:
        return '<KeyIssuer "{}" {}>'.format(self.name, self.key_summary())

    def __getitem__(self, item):
        return self.get_bundles()[item]

    def set(self, items):
        self._bundles = items

    def get_bundles(self):
        return [kb for kb in self._bundles]

    def add_url(self, url, **kwargs):
        """
        Add a set of keys by url. This method will create a
        :py:class:`oidcmsg.key_bundle.KeyBundle` instance with the
        url as source specification. If no file format is given it's assumed
        that what's on the other side is a JWKS.

        :param url: Where can the key/-s be found
        :param kwargs: extra parameters for instantiating KeyBundle
        :return: A :py:class:`oidcmsg.oauth2.keybundle.KeyBundle` instance
        """

        if not url:
            raise KeyError("No url given")

        logger.debug("httpc_params: %s", self.httpc_params)

        if "/localhost:" in url or "/localhost/" in url:
            _params = self.httpc_params.copy()
            _params["verify"] = False
            kb = self.keybundle_cls(source=url, httpc=self.httpc, httpc_params=_params, **kwargs)
        else:
            kb = self.keybundle_cls(
                source=url, httpc=self.httpc, httpc_params=self.httpc_params, **kwargs
            )

        kb.update()
        self._bundles.append(kb)

        return kb

    def add_symmetric(self, key, usage=None):
        """
        Add a symmetric key. This is done by wrapping it in a key bundle
        cloak since KeyJar does not handle keys directly but only through
        key bundles.

        :param key: The key
        :param usage: What the key can be used for signing/signature
            verification (sig) and/or encryption/decryption (enc)
        """

        if usage is None:
            self._bundles.append(self.keybundle_cls([{"kty": "oct", "key": key}]))
        else:
            for use in usage:
                self._bundles.append(self.keybundle_cls([{"kty": "oct", "key": key, "use": use}]))

    def add_kb(self, kb):
        """
        Add a key bundle.

        :param kb: A :py:class:`oidcmsg.key_bundle.KeyBundle` instance
        """
        self._bundles.append(kb)

    def add(self, item, **kwargs):
        if isinstance(item, KeyBundle):
            self.add_kb(item)
        elif (
            item.startswith("http://") or item.startswith("file://") or item.startswith("https://")
        ):
            self.add_url(item, **kwargs)
        else:
            self.add_symmetric(item, **kwargs)
        return self

    def all_keys(self):
        """
        Get all the keys that belong to an entity.

        :return: A possibly empty list of keys
        """
        res = []
        for kb in self._bundles:
            res.extend(kb.keys())
        return res

    def __contains__(self, item):
        for kb in self._bundles:
            if item in kb:
                return True
        return False

    def items(self):
        _res = {}
        for kb in self._bundles:
            if kb.source in _res:
                _res[kb.source].append(kb)
            else:
                _res[kb.source] = [kb]
        return _res

    def load_keys(self, jwks_uri="", jwks=None):
        """
        Fetch keys from another server

        :param jwks_uri: A URL pointing to a site that will return a JWKS
        :param jwks: A dictionary representation of a JWKS
        :return: Dictionary with usage as key and keys as values
        """

        if jwks_uri:
            self.add_url(jwks_uri)
        elif jwks:
            # jwks should only be considered if no jwks_uri is present
            _keys = jwks["keys"]
            self._bundles.append(self.keybundle_cls(_keys))

    def find(self, source):
        """
        Find a key bundle based on the source of the keys

        :param source: A source url
        :return: A list of :py:class:`oidcmsg.key_bundle.KeyBundle` instances, possibly empty
        """
        return [kb for kb in self._bundles if kb.source == source]

    def export_jwks(self, private=False, usage=None):
        """
        Produces a dictionary that later can be easily mapped into a
        JSON string representing a JWKS.

        :param private: Whether it should be the private keys or the public
        :param usage: If only keys for a special usage should be included
        :return: A dictionary with one key: 'keys'
        """
        keys = []
        for kb in self._bundles:
            keys.extend(
                [
                    k.serialize(private)
                    for k in kb.keys()
                    if k.inactive_since == 0
                    and (usage is None or (hasattr(k, "use") and k.use == usage))
                ]
            )
        return {"keys": keys}

    def export_jwks_as_json(self, private=False, usage=None):
        """
        Export a JWKS as a JSON document.

        :param private: Whether it should be the private keys or the public
        :return: A JSON representation of a JWKS
        """
        return json.dumps(self.export_jwks(private, usage=usage))

    def import_jwks(self, jwks):
        """
        Imports all the keys that are represented in a JWKS

        :param jwks: Dictionary representation of a JWKS
        """
        try:
            _keys = jwks["keys"]
        except KeyError:
            raise ValueError("Not a proper JWKS")
        else:
            self._bundles.append(
                self.keybundle_cls(_keys, httpc=self.httpc, httpc_params=self.httpc_params)
            )

    def import_jwks_as_json(self, jwks):
        """
        Imports all the keys that are represented in a JWKS expressed as a
        JSON object

        :param jwks: JSON representation of a JWKS
        """
        return self.import_jwks(json.loads(jwks))

    def import_jwks_from_file(self, filename):
        with open(filename) as jwks_file:
            self.import_jwks_as_json(jwks_file.read())

    def remove_outdated(self, when=0):
        """
        Goes through the complete list of issuers and for each of them removes
        outdated keys.
        Outdated keys are keys that has been marked as inactive at a time that
        is longer ago then some set number of seconds (when). If when=0 the
        the base time is set to now.
        The number of seconds are carried in the remove_after parameter in the
        key jar.

        :param when: To facilitate testing
        """
        kbl = []
        changed = False
        for kb in self._bundles:
            if kb.remove_outdated(self.remove_after, when=when):
                changed = True
            kbl.append(kb)

        if changed:
            self._bundles = kbl

    def get(self, key_use, key_type="", kid=None, alg="", **kwargs):
        """
        Get all keys that matches a set of search criteria

        :param key_use: A key useful for this usage (enc, dec, sig, ver)
        :param key_type: Type of key (rsa, ec, oct, ..)
        :param kid: A Key Identifier
        :param alg: Algorithm
        :return: A possibly empty list of keys
        """

        if key_use in ["dec", "enc"]:
            use = "enc"
        else:
            use = "sig"

        if not key_type:
            if alg:
                if use == "sig":
                    key_type = jws_alg2keytype(alg)
                else:
                    key_type = jwe_alg2keytype(alg)

        lst = []
        for bundle in self._bundles:
            if key_type:
                if key_use in ["ver", "dec"]:
                    _bkeys = bundle.get(key_type, only_active=False)
                else:
                    _bkeys = bundle.get(key_type)
            else:
                _bkeys = bundle.keys()
            for key in _bkeys:
                if key.inactive_since and key_use != "sig":
                    # Skip inactive keys unless for signature verification
                    continue
                if not key.use or use == key.use:
                    if kid:
                        if key.kid == kid:
                            lst.append(key)
                            break
                        else:
                            continue
                    else:
                        lst.append(key)

        # If key algorithm is defined only return keys that can be used.
        if alg:
            lst = [key for key in lst if not key.alg or key.alg == alg]

        # if elliptic curve, have to check if I have a key of the right curve
        if key_type and key_type.upper() == "EC":
            if alg:
                name = "P-{}".format(alg[2:])  # the type
                _lst = []
                for key in lst:
                    if name != key.crv:
                        continue
                    _lst.append(key)
                lst = _lst
            else:
                _crv = kwargs.get("crv")
                if _crv:
                    _lst = [k for k in lst if k.crv == _crv]
                    lst = _lst
        return lst

    def copy(self):
        """
        Make deep copy of this key issuer.

        :return: A :py:class:`oidcmsg.key_issuer.KeyIssuer` instance
        """
        ki = KeyIssuer()
        ki._bundles = [kb.copy() for kb in self._bundles]
        ki.httpc_params = self.httpc_params
        ki.httpc = self.httpc
        ki.keybundle_cls = self.keybundle_cls
        return ki

    def __len__(self):
        nr = 0
        for kb in self._bundles:
            nr += len(kb)
        return nr

    def dump(self, exclude_attributes: Optional[List[str]] = None) -> dict:
        """
        Returns the content as a dictionary.

        :param exclude_attributes: List of attribute names for objects that should be ignored.
        :return: A dictionary
        """

        if exclude_attributes is None:
            exclude_attributes = []

        info = {}
        for attr, default in self.params.items():
            if attr in exclude_attributes:
                continue
            val = getattr(self, attr)
            if attr == "keybundle_cls":
                val = qualified_name(val)
            info[attr] = val

        if "bundles" not in exclude_attributes:
            _bundles = []
            for kb in self._bundles:
                _bundles.append(kb.dump(exclude_attributes=exclude_attributes))
            info["bundles"] = _bundles

        return info

    def load(self, info):
        """

        :param items: A dictionary with the information to load
        :return:
        """
        for attr, default in self.params.items():
            val = info.get(attr)
            if val:
                if attr == "keybundle_cls":
                    val = importer(val)
                setattr(self, attr, val)

        self._bundles = [KeyBundle().load(val) for val in info["bundles"]]
        return self

    def flush(self):
        for attr, default in self.params.items():
            setattr(self, attr, default)

        self._bundles = []
        return self

    def update(self):
        for kb in self._bundles:
            kb.update()

    def mark_as_inactive(self, kid):
        kbl = []
        changed = False
        for kb in self._bundles:
            if kb.mark_as_inactive(kid):
                changed = True
            kbl.append(kb)
        if changed:
            self._bundles = kbl

    def mark_all_keys_as_inactive(self):
        kbl = []
        for kb in self._bundles:
            kb.mark_all_as_inactive()
            kbl.append(kb)

        self._bundles = kbl

    def key_summary(self):
        """
        Return a text representation of all the keys.

        :return: A text representation of the keys
        """
        key_list = []
        for kb in self._bundles:
            for key in kb.keys():
                if key.inactive_since:
                    key_list.append("*{}:{}:{}".format(key.kty, key.use, key.kid))
                else:
                    key_list.append("{}:{}:{}".format(key.kty, key.use, key.kid))
        return ", ".join(key_list)

    def __iter__(self):
        for bundle in self._bundles:
            yield bundle

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        if len(other.all_keys()) != len(self.all_keys()):
            return False

        for k in self.all_keys():
            if k not in other:
                return False

        for k in other.all_keys():
            if k not in self:
                return False

        return True

    def rotate_keys(self, key_conf, kid_template=""):
        """

        :param key_conf: The configuration for the new keys
        :param issuer: KeyIssuer instance
        :param kid_template: A key id template
        :return:
        """
        new_keys = build_keyissuer(key_conf, kid_template)
        self.mark_all_keys_as_inactive()
        for kb in new_keys:
            self.add_kb(kb)
        return self


# =============================================================================


def build_keyissuer(key_conf, kid_template="", key_issuer=None, issuer_id=""):
    """
    Builds a :py:class:`oidcmsg.key_issuer.KeyIssuer` instance or adds keys to
    an existing KeyIssuer instance based on a key specification.

    An example of such a specification::

        keys = [
            {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"], "kid": "ec.1"},
            {"type": "EC", "crv": "P-256", "use": ["enc"], "kid": "ec.2"}
            {"type": "oct", "bytes": 32, "use":["sig"]}
        ]

    Keys in this specification are:

    type
        The type of key. Presently only 'rsa', 'oct' and 'ec' supported.

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
    :param key_issuer: If an keyIssuer instance the new keys are added to this key issuer.
    :param issuer_id: The identifier of the issuer
    :return: A KeyIssuer instance
    """

    bundle = build_key_bundle(key_conf, kid_template)
    if bundle is None:
        return None

    if key_issuer is None:
        key_issuer = KeyIssuer(name=issuer_id)

    key_issuer.add(bundle)

    return key_issuer


def init_key_issuer(public_path="", private_path="", key_defs="", read_only=True):
    """
    A number of cases here:

    1. A private path is given

       a. The file exists and a JWKS is found there.
          From that JWKS a KeyJar instance is built.
       b.
          If the private path file doesn't exit the key definitions are
          used to build a KeyJar instance. A JWKS with the private keys are
          written to the file named in private_path.

       If a public path is also provided a JWKS with public keys are written
       to that file.

    2. A public path is given but no private path.

       a. If the public path file exists then the JWKS in that file is used to
          construct a KeyJar.
       b. If no such file exists then a KeyJar will be built
          based on the key_defs specification and a JWKS with the public keys
          will be written to the public path file.

    3. If neither a public path nor a private path is given then a KeyJar is
       built based on the key_defs specification and no JWKS will be written
       to file.

    In all cases a KeyJar instance is returned

    The keys stored in the KeyJar will be stored under the '' identifier.

    :param public_path: A file path to a file that contains a JWKS with public
        keys
    :param private_path: A file path to a file that contains a JWKS with
        private keys.
    :param key_defs: A definition of what keys should be created if they are
        not already available
    :param read_only: This function should not attempt to write anything
        to a file system.
    :return: An instantiated :py:class;`oidcmsg.key_jar.KeyJar` instance
    """

    if private_path:
        if os.path.isfile(private_path):
            _jwks = open(private_path, "r").read()
            _issuer = KeyIssuer()
            _issuer.import_jwks(json.loads(_jwks))
            if key_defs:
                _kb = _issuer[0]
                _diff = key_diff(_kb, key_defs)
                if _diff:
                    update_key_bundle(_kb, _diff)
                    if read_only:
                        logger.error("Not allowed to write to disc!")
                    else:
                        _issuer.set([_kb])
                        jwks = _issuer.export_jwks(private=True)
                        fp = open(private_path, "w")
                        fp.write(json.dumps(jwks))
                        fp.close()
        else:
            _issuer = build_keyissuer(key_defs)
            if not read_only:
                jwks = _issuer.export_jwks(private=True)
                head, tail = os.path.split(private_path)
                if head and not os.path.isdir(head):
                    os.makedirs(head)
                fp = open(private_path, "w")
                fp.write(json.dumps(jwks))
                fp.close()

        if public_path and not read_only:
            jwks = _issuer.export_jwks()  # public part
            head, tail = os.path.split(public_path)
            if head and not os.path.isdir(head):
                os.makedirs(head)
            fp = open(public_path, "w")
            fp.write(json.dumps(jwks))
            fp.close()
    elif public_path:
        if os.path.isfile(public_path):
            _jwks = open(public_path, "r").read()
            _issuer = KeyIssuer()
            _issuer.import_jwks(json.loads(_jwks))
            if key_defs:
                _kb = _issuer[0]
                _diff = key_diff(_kb, key_defs)
                if _diff:
                    if read_only:
                        logger.error("Not allowed to write to disc!")
                    else:
                        update_key_bundle(_kb, _diff)
                        _issuer.set([_kb])
                        jwks = _issuer.export_jwks()
                        fp = open(public_path, "w")
                        fp.write(json.dumps(jwks))
                        fp.close()
        else:
            _issuer = build_keyissuer(key_defs)
            if not read_only:
                _jwks = _issuer.export_jwks()
                head, tail = os.path.split(public_path)
                if head and not os.path.isdir(head):
                    os.makedirs(head)
                fp = open(public_path, "w")
                fp.write(json.dumps(_jwks))
                fp.close()
    else:
        _issuer = build_keyissuer(key_defs)

    if _issuer is None:
        raise ValueError("Could not find any keys")

    return _issuer
