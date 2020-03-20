import json
import logging
import os

from requests import request

from .jwe.jwe import alg2keytype as jwe_alg2keytype
from .jws.utils import alg2keytype as jws_alg2keytype
from .key_bundle import KeyBundle
from .key_bundle import build_key_bundle
from .key_bundle import key_diff
from .key_bundle import update_key_bundle

__author__ = 'Roland Hedberg'

KEYLOADERR = "Failed to load %s key from '%s' (%s)"
REMOTE_FAILED = "Remote key update from '{}' failed, HTTP status {}"
MALFORMED = "Remote key update from {} failed, malformed JWKS."

logger = logging.getLogger(__name__)


class KeyIOError(Exception):
    pass


class UnknownKeyType(KeyIOError):
    pass


class UpdateFailed(KeyIOError):
    pass


class KeyJar(object):
    """ A keyjar contains a number of KeyBundles sorted by owner/issuer """

    def __init__(self, ca_certs=None, verify_ssl=True, keybundle_cls=KeyBundle,
                 remove_after=3600, httpc=None, httpc_params=None):
        """
        KeyJar init function

        :param ca_certs: CA certificates, to be used for HTTPS
        :param verify_ssl: Attempting SSL certificate verification
        :param keybundle_cls: The KeyBundle class
        :param remove_after: How long keys marked as inactive will remain in the key Jar.
        :param httpc: A HTTP client to use. Default is Requests request.
        :param httpc_params: HTTP request parameters
        :return: Keyjar instance
        """
        self.spec2key = {}
        self.issuer_keys = {}
        self.ca_certs = ca_certs
        self.keybundle_cls = keybundle_cls
        self.remove_after = remove_after
        self.httpc = httpc or request
        self.httpc_params = httpc_params or {}
        # Now part of httpc_params
        # self.verify_ssl = verify_ssl
        if not self.httpc_params: # backward compatibility
            self.httpc_params["verify"] = verify_ssl

    def __repr__(self):
        issuers = list(self.issuer_keys.keys())
        return '<KeyJar(issuers={})>'.format(issuers)

    def add_url(self, issuer, url, **kwargs):
        """
        Add a set of keys by url. This method will create a
        :py:class:`oidcmsg.key_bundle.KeyBundle` instance with the
        url as source specification. If no file format is given it's assumed
        that what's on the other side is a JWKS.

        :param issuer: Who issued the keys
        :param url: Where can the key/-s be found
        :param kwargs: extra parameters for instantiating KeyBundle
        :return: A :py:class:`oidcmsg.oauth2.keybundle.KeyBundle` instance
        """

        if not url:
            raise KeyError("No url given")

        if "/localhost:" in url or "/localhost/" in url:
            _params = self.httpc_params.copy()
            _params['verify'] = False
            kb = self.keybundle_cls(source=url, httpc=self.httpc,
                                    httpc_params=_params, **kwargs)
        else:
            kb = self.keybundle_cls(source=url, httpc=self.httpc,
                                    httpc_params=self.httpc_params, **kwargs)

        kb.update()
        self.add_kb(issuer, kb)

        return kb

    def add_symmetric(self, issuer, key, usage=None):
        """
        Add a symmetric key. This is done by wrapping it in a key bundle
        cloak since KeyJar does not handle keys directly but only through
        key bundles.

        :param issuer: Owner of the key
        :param key: The key
        :param usage: What the key can be used for signing/signature
            verification (sig) and/or encryption/decryption (enc)
        """
        if issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = []

        if usage is None:
            self.issuer_keys[issuer].append(
                self.keybundle_cls([{"kty": "oct", "key": key}]))
        else:
            for use in usage:
                self.issuer_keys[issuer].append(
                    self.keybundle_cls([{"kty": "oct", "key": key, "use": use}]))

    def add_kb(self, issuer, kb):
        """
        Add a key bundle and bind it to an identifier

        :param issuer: Owner of the keys in the key bundle
        :param kb: A :py:class:`oidcmsg.key_bundle.KeyBundle` instance
        """
        try:
            self.issuer_keys[issuer].append(kb)
        except KeyError:
            self.issuer_keys[issuer] = [kb]

    def __setitem__(self, issuer, val):
        """
        Bind one or a list of key bundles to a special identifier.
        Will overwrite whatever was there before !!

        :param issuer: The owner of the keys in the key bundle/-s
        :param val: A single or a list of KeyBundle instance
        """
        if not isinstance(val, list):
            val = [val]

        for kb in val:
            if not isinstance(kb, KeyBundle):
                raise ValueError('{} not an KeyBundle instance'.format(kb))

        self.issuer_keys[issuer] = val

    def items(self):
        """
        Get all owner ID's and their key bundles

        :return: list of 2-tuples (Owner ID., list of KeyBundles)
        """
        return self.issuer_keys.items()

    def get(self, key_use, key_type="", owner="", kid=None, **kwargs):
        """
        Get all keys that matches a set of search criteria

        :param key_use: A key useful for this usage (enc, dec, sig, ver)
        :param key_type: Type of key (rsa, ec, oct, ..)
        :param owner: Who is the owner of the keys, "" == me (default)
        :param kid: A Key Identifier
        :return: A possibly empty list of keys
        """

        if key_use in ["dec", "enc"]:
            use = "enc"
        else:
            use = "sig"

        _kj = None
        if owner != "":
            try:
                _kj = self.issuer_keys[owner]
            except KeyError:
                if owner.endswith("/"):
                    try:
                        _kj = self.issuer_keys[owner[:-1]]
                    except KeyError:
                        pass
                else:
                    try:
                        _kj = self.issuer_keys[owner + "/"]
                    except KeyError:
                        pass
        else:
            try:
                _kj = self.issuer_keys[owner]
            except KeyError:
                pass

        if _kj is None:
            return []

        lst = []
        for bundle in _kj:
            if key_type:
                if key_use in ['ver', 'dec']:
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

        # if elliptic curve, have to check if I have a key of the right curve
        if key_type == "EC" and "alg" in kwargs:
            name = "P-{}".format(kwargs["alg"][2:])  # the type
            _lst = []
            for key in lst:
                if name != key.crv:
                    continue
                _lst.append(key)
            lst = _lst

        if use == 'enc' and key_type == 'oct' and owner != '':
            # Add my symmetric keys
            for kb in self.issuer_keys['']:
                for key in kb.get(key_type):
                    if key.inactive_since:
                        continue
                    if not key.use or key.use == use:
                        lst.append(key)

        return lst

    def get_signing_key(self, key_type="", owner="", kid=None, **kwargs):
        """
        Shortcut to use for signing keys only.

        :param key_type: Type of key (rsa, ec, oct, ..)
        :param owner: Who is the owner of the keys, "" == me (default)
        :param kid: A Key Identifier
        :param kwargs: Extra key word arguments
        :return: A possibly empty list of keys
        """
        return self.get("sig", key_type, owner, kid, **kwargs)

    def get_verify_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("ver", key_type, owner, kid, **kwargs)

    def get_encrypt_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("enc", key_type, owner, kid, **kwargs)

    def get_decrypt_key(self, key_type="", owner="", kid=None, **kwargs):
        return self.get("dec", key_type, owner, kid, **kwargs)

    def keys_by_alg_and_usage(self, issuer, alg, usage):
        """
        Find all keys that can be used for a specific crypto algorithm and
        usage by key owner.

        :param issuer: Key owner
        :param alg: a crypto algorithm
        :param usage: What the key should be used for
        :return: A possibly empty list of keys
        """
        if usage in ["sig", "ver"]:
            ktype = jws_alg2keytype(alg)
        else:
            ktype = jwe_alg2keytype(alg)

        return self.get(usage, ktype, issuer)

    def get_issuer_keys(self, issuer):
        """
        Get all the keys that belong to an entity.

        :param issuer: The entity ID
        :return: A possibly empty list of keys
        """
        res = []
        for kbl in self.issuer_keys[issuer]:
            res.extend(kbl.keys())
        return res

    def __contains__(self, item):
        if item in self.issuer_keys:
            return True
        else:
            return False

    def __getitem__(self, owner=''):
        """
        Get all the key bundles that belong to an entity.

        :param owner: The entity ID
        :return: A possibly empty list of key bundles
        """
        try:
            return self.issuer_keys[owner]
        except KeyError:
            logger.debug(
                "Owner '{}' not found, available key owners: {}".format(
                    owner, list(self.issuer_keys.keys())))
            raise

    def owners(self):
        """
        Return a list of all the entities that has keys in this key jar.

        :return: A list of entity IDs
        """
        return list(self.issuer_keys.keys())

    def match_owner(self, url):
        """
        Finds the first entity, with keys in the key jar, with an
        identifier that matches the given URL. The match is a leading
        substring match.

        :param url: A URL
        :return: An issue entity ID that exists in the Key jar
        """
        for owner in self.issuer_keys.keys():
            if owner.startswith(url):
                return owner

        raise KeyError("No keys for '{}' in this keyjar".format(url))

    def __str__(self):
        _res = {}
        for _id, kbs in self.issuer_keys.items():
            _l = []
            for kb in kbs:
                _l.extend(json.loads(kb.jwks())["keys"])
            _res[_id] = {"keys": _l}
        return json.dumps(_res)

    def load_keys(self, issuer, jwks_uri='', jwks=None, replace=False):
        """
        Fetch keys from another server

        :param jwks_uri: A URL pointing to a site that will return a JWKS
        :param jwks: A dictionary representation of a JWKS
        :param issuer: The provider URL
        :param replace: If all previously gathered keys from this provider
            should be replace.
        :return: Dictionary with usage as key and keys as values
        """

        logger.debug("Initiating key bundle for issuer: %s" % issuer)

        if replace or issuer not in self.issuer_keys:
            self.issuer_keys[issuer] = []

        if jwks_uri:
            self.add_url(issuer, jwks_uri)
        elif jwks:
            # jwks should only be considered if no jwks_uri is present
            _keys = jwks['keys']
            self.issuer_keys[issuer].append(self.keybundle_cls(_keys))

    def find(self, source, issuer):
        """
        Find a key bundle based on the source of the keys

        :param source: A source url
        :param issuer: The issuer of keys
        :return: A :py:class:`oidcmsg.key_bundle.KeyBundle` instance or None
        """
        try:
            for kb in self.issuer_keys[issuer]:
                if kb.source == source:
                    return kb
        except KeyError:
            return None

        return None

    def export_jwks(self, private=False, issuer="", usage=None):
        """
        Produces a dictionary that later can be easily mapped into a
        JSON string representing a JWKS.

        :param private: Whether it should be the private keys or the public
        :param issuer: The entity ID.
        :return: A dictionary with one key: 'keys'
        """
        keys = []
        for kb in self.issuer_keys[issuer]:
            keys.extend([k.serialize(private) for k in kb.keys() if
                         k.inactive_since == 0 and (usage is None or (hasattr(k, 'use') and k.use == usage))])
        return {"keys": keys}

    def export_jwks_as_json(self, private=False, issuer=""):
        """
        Export a JWKS as a JSON document.

        :param private: Whether it should be the private keys or the public
        :param issuer: The entity ID.
        :return: A JSON representation of a JWKS
        """
        return json.dumps(self.export_jwks(private, issuer))

    def import_jwks(self, jwks, issuer):
        """
        Imports all the keys that are represented in a JWKS

        :param jwks: Dictionary representation of a JWKS
        :param issuer: Who 'owns' the JWKS
        """
        try:
            _keys = jwks["keys"]
        except KeyError:
            raise ValueError('Not a proper JWKS')
        else:
            try:
                self.issuer_keys[issuer].append(
                    self.keybundle_cls(_keys, httpc=self.httpc, httpc_params=self.httpc_params))
            except KeyError:
                self.issuer_keys[issuer] = [self.keybundle_cls(
                    _keys, httpc=self.httpc, httpc_params=self.httpc_params)]

    def import_jwks_as_json(self, jwks, issuer):
        """
        Imports all the keys that are represented in a JWKS expressed as a
        JSON object

        :param jwks: JSON representation of a JWKS
        :param issuer: Who 'owns' the JWKS
        """
        return self.import_jwks(json.loads(jwks), issuer)

    def import_jwks_from_file(self, filename, issuer):
        with open(filename) as jwks_file:
            self.import_jwks_as_json(jwks_file.read(), issuer)

    def __eq__(self, other):
        if not isinstance(other, KeyJar):
            return False

        # The set of issuers MUST be the same
        if set(self.owners()) != set(other.owners()):
            return False

        # Keys per issuer must be the same
        for iss in self.owners():
            sk = self.get_issuer_keys(iss)
            ok = other.get_issuer_keys(iss)
            if len(sk) != len(ok):
                return False

            if not any(k in ok for k in sk):
                return False

        return True

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
        for iss in list(self.owners()):
            _kbl = []
            for kb in self.issuer_keys[iss]:
                kb.remove_outdated(self.remove_after, when=when)
                if len(kb):
                    _kbl.append(kb)
            if _kbl:
                self.issuer_keys[iss] = _kbl
            else:
                del self.issuer_keys[iss]

    def _add_key(self, keys, issuer, use, key_type='', kid='',
                 no_kid_issuer=None, allow_missing_kid=False):

        if issuer not in self:
            logger.error('Issuer "{}" not in keyjar'.format(issuer))
            return keys

        logger.debug('Key set summary for {}: {}'.format(
            issuer, key_summary(self, issuer)))

        if kid:
            for _key in self.get(key_use=use, owner=issuer, kid=kid, key_type=key_type):
                if _key and _key not in keys:
                    keys.append(_key)
            return keys
        else:
            try:
                kl = self.get(key_use=use, owner=issuer, key_type=key_type)
            except KeyError:
                pass
            else:
                if len(kl) == 0:
                    return keys
                elif len(kl) == 1:
                    if kl[0] not in keys:
                        keys.append(kl[0])
                elif allow_missing_kid:
                    keys.extend(kl)
                elif no_kid_issuer:
                    try:
                        allowed_kids = no_kid_issuer[issuer]
                    except KeyError:
                        return keys
                    else:
                        if allowed_kids:
                            keys.extend(
                                [k for k in kl if k.kid in allowed_kids])
                        else:
                            keys.extend(kl)
        return keys

    def get_jwt_decrypt_keys(self, jwt, **kwargs):
        """
        Get decryption keys from this keyjar based on information carried
        in a JWE. These keys should be usable to decrypt an encrypted JWT.

        :param jwt: A cryptojwt.jwt.JWT instance
        :param kwargs: Other key word arguments
        :return: list of usable keys
        """

        try:
            _key_type = jwe_alg2keytype(jwt.headers['alg'])
        except KeyError:
            _key_type = ''

        try:
            _kid = jwt.headers['kid']
        except KeyError:
            logger.info('Missing kid')
            _kid = ''

        keys = self.get(key_use='enc', owner='', key_type=_key_type)

        try:
            _aud = kwargs['aud']
        except KeyError:
            _aud = ''

        if _aud:
            try:
                allow_missing_kid = kwargs['allow_missing_kid']
            except KeyError:
                allow_missing_kid = False

            try:
                nki = kwargs['no_kid_issuer']
            except KeyError:
                nki = {}

            keys = self._add_key(keys, _aud, 'enc', _key_type, _kid, nki,
                                 allow_missing_kid)

        # Only want the appropriate keys.
        keys = [k for k in keys if k.appropriate_for('decrypt')]
        return keys

    def get_jwt_verify_keys(self, jwt, **kwargs):
        """
        Get keys from this key jar based on information in a JWS. These keys
        should be usable to verify the signed JWT.

        :param jwt: A cryptojwt.jwt.JWT instance
        :param kwargs: Other key word arguments
        :return: list of usable keys
        """

        allow_missing_kid = kwargs.get('allow_missing_kid', False)

        _key_type = ''
        if jwt.headers.get('alg'):
            _key_type = jws_alg2keytype(jwt.headers['alg'])

        _kid = jwt.headers.get('kid', "")
        nki = kwargs.get('no_kid_issuer', {})

        _payload = jwt.payload()

        _iss = _payload.get('iss') or kwargs.get('iss') or ""

        if _iss:
            # First extend the key jar iff allowed
            if "jku" in jwt.headers and _iss:
                if not self.find(jwt.headers["jku"], _iss):
                    # This is really questionable
                    try:
                        if kwargs["trusting"]:
                            self.add_url(_iss, jwt.headers["jku"])
                    except KeyError:
                        pass

            keys = self._add_key([], _iss, 'sig', _key_type,
                                 _kid, nki, allow_missing_kid)

            if _key_type == 'oct':
                keys.extend(self.get(key_use='sig', owner='',
                                     key_type=_key_type))
        else:  # No issuer, just use all keys I have
            keys = self.get(key_use='sig', owner='', key_type=_key_type)

        # Only want the appropriate keys.
        keys = [k for k in keys if k.appropriate_for('verify')]
        return keys

    def copy(self):
        """
        Make deep copy of this key jar.

        :return: A :py:class:`oidcmsg.key_jar.KeyJar` instance
        """
        kj = KeyJar()
        for issuer in self.owners():
            kj[issuer] = [kb.copy() for kb in self[issuer]]

        kj.httpc_params = self.httpc_params
        kj.httpc = self.httpc
        return kj

    def __len__(self):
        keys = 0
        for iss in list(self.owners()):
            for kb in self.issuer_keys[iss]:
                if len(kb):
                    keys += len(kb)
        return keys


# =============================================================================


def build_keyjar(key_conf, kid_template="", keyjar=None, owner=''):
    """
    Builds a :py:class:`oidcmsg.key_jar.KeyJar` instance or adds keys to
    an existing KeyJar based on a key specification.

    An example of such a specification::

        keys = [
            {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
            {"type": "EC", "crv": "P-256", "use": ["sig"], "kid": "ec.1"},
            {"type": "EC", "crv": "P-256", "use": ["enc"], "kid": "ec.2"}
            {"type": "OCT", "bytes": 32, "use":["sig"]}
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
    :param keyjar: If an KeyJar instance the new keys are added to this key jar.
    :param owner: The default owner of the keys in the key jar.
    :return: A KeyJar instance
    """

    if keyjar is None:
        keyjar = KeyJar()

    bundle = build_key_bundle(key_conf, kid_template)

    keyjar.add_kb(owner, bundle)

    return keyjar


def update_keyjar(keyjar):
    """
    Go through the whole key jar, key bundle by key bundle and update them one
    by one.

    :param keyjar: The key jar to update
    """
    for iss, kbl in keyjar.items():
        for kb in kbl:
            kb.update()


def key_summary(keyjar, issuer):
    """
    Return a text representation of the keyjar.

    :param keyjar: A :py:class:`oidcmsg.key_jar.KeyJar` instance
    :param issuer: Which key owner that we are looking at
    :return: A text representation of the keys
    """
    try:
        kbl = keyjar[issuer]
    except KeyError:
        return ''
    else:
        key_list = []
        for kb in kbl:
            for key in kb.keys():
                if key.inactive_since:
                    key_list.append(
                        '*{}:{}:{}'.format(key.kty, key.use, key.kid))
                else:
                    key_list.append(
                        '{}:{}:{}'.format(key.kty, key.use, key.kid))
        return ', '.join(key_list)


def init_key_jar(public_path='', private_path='', key_defs='', owner='',
                 read_only=True):
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
    :param owner: The owner of the keys
    :param read_only: This function should not attempt to write anything
        to a file system.
    :return: An instantiated :py:class;`oidcmsg.key_jar.KeyJar` instance
    """

    if private_path:
        if os.path.isfile(private_path):
            _jwks = open(private_path, 'r').read()
            _kj = KeyJar()
            _kj.import_jwks(json.loads(_jwks), owner)
            if key_defs:
                _kb = _kj.issuer_keys[owner][0]
                _diff = key_diff(_kb, key_defs)
                if _diff:
                    update_key_bundle(_kb, _diff)
                    if read_only:
                        logger.error('Not allowed to write to disc!')
                    else:
                        _kj.issuer_keys[owner] = [_kb]
                        jwks = _kj.export_jwks(private=True, issuer=owner)
                        fp = open(private_path, 'w')
                        fp.write(json.dumps(jwks))
                        fp.close()
        else:
            _kj = build_keyjar(key_defs, owner=owner)
            if not read_only:
                jwks = _kj.export_jwks(private=True, issuer=owner)
                head, tail = os.path.split(private_path)
                if head and not os.path.isdir(head):
                    os.makedirs(head)
                fp = open(private_path, 'w')
                fp.write(json.dumps(jwks))
                fp.close()

        if public_path and not read_only:
            jwks = _kj.export_jwks(issuer=owner)  # public part
            head, tail = os.path.split(public_path)
            if head and not os.path.isdir(head):
                os.makedirs(head)
            fp = open(public_path, 'w')
            fp.write(json.dumps(jwks))
            fp.close()
    elif public_path:
        if os.path.isfile(public_path):
            _jwks = open(public_path, 'r').read()
            _kj = KeyJar()
            _kj.import_jwks(json.loads(_jwks), owner)
            if key_defs:
                _kb = _kj.issuer_keys[owner][0]
                _diff = key_diff(_kb, key_defs)
                if _diff:
                    if read_only:
                        logger.error('Not allowed to write to disc!')
                    else:
                        update_key_bundle(_kb, _diff)
                        _kj.issuer_keys[owner] = [_kb]
                        jwks = _kj.export_jwks(issuer=owner)
                        fp = open(public_path, 'w')
                        fp.write(json.dumps(jwks))
                        fp.close()
        else:
            _kj = build_keyjar(key_defs, owner=owner)
            if not read_only:
                _jwks = _kj.export_jwks(issuer=owner)
                head, tail = os.path.split(public_path)
                if head and not os.path.isdir(head):
                    os.makedirs(head)
                fp = open(public_path, 'w')
                fp.write(json.dumps(_jwks))
                fp.close()
    else:
        _kj = build_keyjar(key_defs, owner=owner)

    return _kj
