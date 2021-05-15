import json
import logging
from typing import List
from typing import Optional

from requests import request

from .exception import IssuerNotFound
from .jwe.jwe import alg2keytype as jwe_alg2keytype
from .jws.utils import alg2keytype as jws_alg2keytype
from .key_bundle import KeyBundle
from .key_issuer import KeyIssuer
from .key_issuer import build_keyissuer
from .key_issuer import init_key_issuer
from .utils import deprecated_alias
from .utils import importer
from .utils import qualified_name

__author__ = "Roland Hedberg"

logger = logging.getLogger(__name__)


class KeyJar(object):
    """ A keyjar contains a number of KeyBundles sorted by owner/issuer """

    def __init__(
        self,
        ca_certs=None,
        verify_ssl=True,
        keybundle_cls=KeyBundle,
        remove_after=3600,
        httpc=None,
        httpc_params=None,
    ):
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
        self._issuers = {}
        self.spec2key = {}
        self.ca_certs = ca_certs
        self.keybundle_cls = keybundle_cls
        self.remove_after = remove_after
        self.httpc = httpc or request
        self.httpc_params = httpc_params or {}
        # Now part of httpc_params
        # self.verify_ssl = verify_ssl
        if not self.httpc_params:  # backward compatibility
            self.httpc_params["verify"] = verify_ssl

    def _issuer_ids(self) -> List[str]:
        """
        Returns a list of issuer identifiers

        :return:
        """
        return list(self._issuers.keys())

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def _get_issuer(self, issuer_id: str) -> Optional[KeyIssuer]:
        """
        Return the KeyIssuer instance that has name == issuer_id

        :param issuer_id: The issuer identifiers
        :return: A KeyIssuer instance or None
        """

        return self._issuers.get(issuer_id)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def _add_issuer(self, issuer_id) -> KeyIssuer:
        _issuer = KeyIssuer(
            ca_certs=self.ca_certs,
            name=issuer_id,
            keybundle_cls=self.keybundle_cls,
            remove_after=self.remove_after,
            httpc=self.httpc,
            httpc_params=self.httpc_params,
        )
        self._issuers[issuer_id] = _issuer
        return _issuer

    def items(self):
        """
        Get all owner ID's and their keys

        :return: list of 2-tuples (Owner ID., list of KeyBundles)
        """
        return self._issuers.items()

    def __repr__(self):
        issuers = self._issuer_ids()
        return "<KeyJar(issuers={})>".format(issuers)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def return_issuer(self, issuer_id):
        """
        Return a KeyIssuer instance with name == issuer_id.
        If none such was already initiated, create one.

        :param issuer_id: The issuer ID
        :return: A KeyIssuer instance
        """
        _issuer = self._get_issuer(issuer_id)
        if _issuer is None:
            return self._add_issuer(issuer_id)
        return _issuer

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def add_url(self, issuer_id: str, url: str, **kwargs) -> KeyBundle:
        """
        Add a set of keys by url. This method will create a
        :py:class:`oidcmsg.key_bundle.KeyBundle` instance with the
        url as source specification. If no file format is given it's assumed
        that what's on the other side is a JWKS.

        :param issuer_id: Who issued the keys
        :param url: Where can the key/-s be found
        :param kwargs: extra parameters for instantiating KeyBundle
        :return: A :py:class:`oidcmsg.oauth2.keybundle.KeyBundle` instance
        """

        issuer = self.return_issuer(issuer_id)
        kb = issuer.add_url(url, **kwargs)
        return kb

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def add_symmetric(self, issuer_id, key, usage=None):
        """
        Add a symmetric key. This is done by wrapping it in a key bundle
        cloak since KeyJar does not handle keys directly but only through
        key bundles.

        :param issuer_id: Owner of the key
        :param key: The key
        :param usage: What the key can be used for signing/signature
            verification (sig) and/or encryption/decryption (enc)
        """
        issuer = self.return_issuer(issuer_id)
        issuer.add_symmetric(key, usage=usage)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def add_kb(self, issuer_id, kb):
        """
        Add a key bundle and bind it to an identifier

        :param issuer_id: Owner of the keys in the key bundle
        :param kb: A :py:class:`oidcmsg.key_bundle.KeyBundle` instance
        """
        issuer = self.return_issuer(issuer_id)
        issuer.add_kb(kb)
        self._issuers[issuer_id] = issuer

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def get(self, key_use, key_type="", issuer_id="", kid=None, **kwargs):
        """
        Get all keys that matches a set of search criteria

        :param key_use: A key useful for this usage (enc, dec, sig, ver)
        :param key_type: Type of key (rsa, ec, oct, ..)
        :param issuer_id: Who is the owner of the keys, "" == me (default)
        :param kid: A Key Identifier
        :return: A possibly empty list of keys
        """

        _issuer = None
        if issuer_id != "":
            _issuer = self._get_issuer(issuer_id)
            if _issuer is None:
                if issuer_id.endswith("/"):
                    _issuer = self._get_issuer(issuer_id[:-1])
                else:
                    _issuer = self._get_issuer(issuer_id + "/")
        else:
            _issuer = self._get_issuer(issuer_id)

        if _issuer is None:
            return []

        return _issuer.get(key_use=key_use, key_type=key_type, kid=kid, **kwargs)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def get_signing_key(self, key_type="", issuer_id="", kid=None, **kwargs):
        """
        Shortcut to use for signing keys only.

        :param key_type: Type of key (rsa, ec, oct, ..)
        :param issuer_id: Who is the owner of the keys, "" == me (default)
        :param kid: A Key Identifier
        :param kwargs: Extra key word arguments
        :return: A possibly empty list of keys
        """
        return self.get("sig", key_type, issuer_id, kid, **kwargs)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def get_verify_key(self, key_type="", issuer_id="", kid=None, **kwargs):
        return self.get("ver", key_type, issuer_id, kid, **kwargs)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def get_encrypt_key(self, key_type="", issuer_id="", kid=None, **kwargs):
        return self.get("enc", key_type, issuer_id, kid, **kwargs)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def get_decrypt_key(self, key_type="", issuer_id="", kid=None, **kwargs):
        return self.get("dec", key_type, issuer_id, kid, **kwargs)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def keys_by_alg_and_usage(self, issuer_id, alg, usage):
        """
        Find all keys that can be used for a specific crypto algorithm and
        usage by key owner.

        :param issuer_id: Key owner
        :param alg: a crypto algorithm
        :param usage: What the key should be used for
        :return: A possibly empty list of keys
        """
        if usage in ["sig", "ver"]:
            ktype = jws_alg2keytype(alg)
        else:
            ktype = jwe_alg2keytype(alg)

        return self.get(usage, ktype, issuer_id)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def get_issuer_keys(self, issuer_id):
        """
        Get all the keys that belong to an entity.

        :param issuer_id: The entity ID
        :return: A possibly empty list of keys
        """
        _issuer = self._get_issuer(issuer_id)
        if _issuer is None:
            raise IssuerNotFound(issuer_id)
        return _issuer.all_keys()

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def __contains__(self, issuer_id):
        _iss = self._get_issuer(issuer_id)
        if _iss is None:
            return False
        else:
            return True

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def __getitem__(self, issuer_id=""):
        """
        Get the KeyIssuer with the name == issuer_id

        :param issuer_id: The entity ID
        :return: A KeyIssuer instance
        """
        _issuer = self._get_issuer(issuer_id)
        if _issuer is None:
            raise IssuerNotFound(issuer_id)
        return _issuer

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def __setitem__(self, issuer_id, key_issuer):
        """
        Set a KeyIssuer with the name == issuer_id

        :param issuer_id: The entity ID
        :param key_issuer: KeyIssuer instance
        """
        self._issuers[issuer_id] = key_issuer

    def set(self, issuer_id, issuer):
        self[issuer_id] = issuer

    def owners(self):
        """
        Return a list of all the entities that has keys in this key jar.

        :return: A list of entity IDs
        """
        return list(self._issuers.keys())

    def match_owner(self, url):
        """
        Finds the first entity, with keys in the key jar, with an
        identifier that matches the given URL. The match is a leading
        substring match.

        :param url: A URL
        :return: An issue entity ID that exists in the Key jar
        """
        _iss = [i for i in self._issuers.keys() if i.startswith(url)]
        if _iss:
            return _iss[0]

        raise KeyError("No keys for '{}' in this keyjar".format(url))

    def __str__(self):
        _res = {}
        for _id, _issuer in self._issuers.items():
            _res[_id] = _issuer.key_summary()
        return json.dumps(_res)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def load_keys(self, issuer_id, jwks_uri="", jwks=None, replace=False):
        """
        Fetch keys from another server

        :param jwks_uri: A URL pointing to a site that will return a JWKS
        :param jwks: A dictionary representation of a JWKS
        :param issuer_id: The provider URL
        :param replace: If all previously gathered keys from this provider
            should be replace.
        :return: Dictionary with usage as key and keys as values
        """

        logger.debug("Initiating key bundle for issuer: %s" % issuer_id)

        _issuer = self.return_issuer(issuer_id)
        if replace:
            _issuer.set([])

        if jwks_uri:
            _issuer.add_url(jwks_uri)
        elif jwks:
            # jwks should only be considered if no jwks_uri is present
            _keys = jwks["keys"]
            _issuer.add_kb(self.keybundle_cls(_keys))

        self[issuer_id] = _issuer

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def find(self, source, issuer_id=None):
        """
        Find a key bundle based on the source of the keys

        :param source: A source url
        :param issuer_id: The issuer of keys
        :return: List of :py:class:`oidcmsg.key_bundle.KeyBundle` instances or None
        """
        if issuer_id is None:
            res = {}
            for _, _issuer in self._issuers.items():
                kbs = _issuer.find(source)
                if kbs:
                    res[_issuer.name] = kbs
        else:
            _issuer = self._get_issuer(issuer_id)
            if _issuer is None:
                return None
            else:
                res = _issuer.find(source)

        return res

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def export_jwks(self, private=False, issuer_id="", usage=None):
        """
        Produces a dictionary that later can be easily mapped into a
        JSON string representing a JWKS.

        :param private: Whether it should be the private keys or the public
        :param issuer_id: The entity ID.
        :return: A dictionary with one key: 'keys'
        """
        _issuer = self._get_issuer(issuer_id=issuer_id)
        if _issuer is None:
            return {"keys": []}

        keys = []
        for kb in _issuer:
            keys.extend(
                [
                    k.serialize(private)
                    for k in kb.keys()
                    if k.inactive_since == 0
                    and (usage is None or (hasattr(k, "use") and k.use == usage))
                ]
            )
        return {"keys": keys}

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def export_jwks_as_json(self, private=False, issuer_id=""):
        """
        Export a JWKS as a JSON document.

        :param private: Whether it should be the private keys or the public
        :param issuer_id: The entity ID.
        :return: A JSON representation of a JWKS
        """
        return json.dumps(self.export_jwks(private, issuer_id))

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def import_jwks(self, jwks, issuer_id):
        """
        Imports all the keys that are represented in a JWKS

        :param jwks: Dictionary representation of a JWKS
        :param issuer_id: Who 'owns' the JWKS
        """
        try:
            _keys = jwks["keys"]
        except KeyError:
            raise ValueError("Not a proper JWKS")

        if _keys:
            _issuer = self.return_issuer(issuer_id=issuer_id)
            _issuer.add(self.keybundle_cls(_keys, httpc=self.httpc, httpc_params=self.httpc_params))
            self[issuer_id] = _issuer

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def import_jwks_as_json(self, jwks, issuer_id):
        """
        Imports all the keys that are represented in a JWKS expressed as a
        JSON object

        :param jwks: JSON representation of a JWKS
        :param issuer_id: Who 'owns' the JWKS
        """
        return self.import_jwks(json.loads(jwks), issuer_id)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def import_jwks_from_file(self, filename, issuer_id):
        with open(filename) as jwks_file:
            self.import_jwks_as_json(jwks_file.read(), issuer_id)

    def __eq__(self, other):
        if not isinstance(other, KeyJar):
            return False

        # The set of issuers MUST be the same
        if set(self.owners()) != set(other.owners()):
            return False

        # Keys per issuer must be the same
        for iss in self.owners():
            if self[iss] != other[iss]:
                return False

        return True

    def __delitem__(self, key):
        del self._issuers[key]

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
        for _id, _issuer in self._issuers.items():
            _before = len(_issuer)
            _issuer.remove_outdated(when)

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def _add_key(
        self,
        keys,
        issuer_id,
        use,
        key_type="",
        kid="",
        no_kid_issuer=None,
        allow_missing_kid=False,
    ):

        _issuer = self._get_issuer(issuer_id)
        if _issuer is None:
            logger.error('Issuer "{}" not in keyjar'.format(issuer_id))
            raise IssuerNotFound(issuer_id)

        logger.debug("Key summary for {}: {}".format(issuer_id, _issuer.key_summary()))

        if kid:
            for _key in _issuer.get(use, kid=kid, key_type=key_type):
                if _key and _key not in keys:
                    keys.append(_key)
            return keys
        else:
            try:
                _add_keys = _issuer.get(use, key_type=key_type)
            except KeyError:
                pass
            else:
                if len(_add_keys) == 0:
                    return keys
                elif len(_add_keys) == 1:
                    if _add_keys[0] not in keys:
                        keys.append(_add_keys[0])
                elif allow_missing_kid:
                    keys.extend(_add_keys)
                elif no_kid_issuer:
                    try:
                        allowed_kids = no_kid_issuer[issuer_id]
                    except KeyError:
                        return keys
                    else:
                        if allowed_kids:
                            keys.extend([k for k in _add_keys if k.kid in allowed_kids])
                        else:
                            keys.extend(_add_keys)
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
            _key_type = jwe_alg2keytype(jwt.headers["alg"])
        except KeyError:
            _key_type = ""

        try:
            _kid = jwt.headers["kid"]
        except KeyError:
            logger.info("Missing kid")
            _kid = ""

        keys = self.get(key_use="enc", issuer_id="", key_type=_key_type)

        try:
            _aud = kwargs["aud"]
        except KeyError:
            _aud = ""

        if _aud:
            try:
                allow_missing_kid = kwargs["allow_missing_kid"]
            except KeyError:
                allow_missing_kid = False

            try:
                nki = kwargs["no_kid_issuer"]
            except KeyError:
                nki = {}

            keys = self._add_key(keys, _aud, "enc", _key_type, _kid, nki, allow_missing_kid)

        # Only want the appropriate keys.
        keys = [k for k in keys if k.appropriate_for("decrypt")]
        return keys

    def get_jwt_verify_keys(self, jwt, **kwargs):
        """
        Get keys from this key jar based on information in a JWS. These keys
        should be usable to verify the signed JWT.

        :param jwt: A cryptojwt.jwt.JWT instance
        :param kwargs: Other key word arguments
        :return: list of usable keys
        """

        allow_missing_kid = kwargs.get("allow_missing_kid", False)

        _key_type = ""
        if jwt.headers.get("alg"):
            _key_type = jws_alg2keytype(jwt.headers["alg"])

        _kid = jwt.headers.get("kid", "")
        nki = kwargs.get("no_kid_issuer", {})

        _payload = jwt.payload()

        _iss = _payload.get("iss") or kwargs.get("iss") or ""

        if not _iss:
            _iss = kwargs.get("issuer")

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

            keys = self._add_key([], _iss, "sig", _key_type, _kid, nki, allow_missing_kid)

            if _key_type == "oct":
                keys.extend(self.get(key_use="sig", issuer_id="", key_type=_key_type))
        else:
            # No issuer, just use all keys I have
            keys = self.get(key_use="sig", issuer_id="", key_type=_key_type)

        # Only want the appropriate keys.
        keys = [k for k in keys if k.appropriate_for("verify")]
        return keys

    def copy(self):
        """
        Make deep copy of the content of this key jar.

        :return: A :py:class:`oidcmsg.key_jar.KeyJar` instance
        """

        kj = KeyJar()
        for _id, _issuer in self._issuers.items():
            _issuer_copy = KeyIssuer()
            _issuer_copy.set([kb.copy() for kb in _issuer])
            kj[_id] = _issuer_copy

        kj.httpc_params = self.httpc_params
        kj.httpc = self.httpc
        return kj

    def __len__(self):
        return len(self._issuers)

    def _dump_issuers(
        self,
        exclude_issuers: Optional[List[str]] = None,
        exclude_attributes: Optional[List[str]] = None,
    ):
        _issuers = {}
        for _id, _issuer in self._issuers.items():
            if exclude_issuers and _issuer.name in exclude_issuers:
                continue
            _issuers[_id] = _issuer.dump(exclude_attributes=exclude_attributes)
        return _issuers

    def dump(
        self,
        exclude_issuers: Optional[List[str]] = None,
        exclude_attributes: Optional[List[str]] = None,
    ) -> dict:
        """
        Returns the key jar content as dictionary

        :param exclude_issuers: A list of issuers you don't want included.
        :param exclude_attributes: list of attribute names that should be ignored when dumping.
        :type exclude_attributes: list
        :return: A dictionary
        """

        info = {
            "ca_certs": self.ca_certs,
            "httpc_params": self.httpc_params,
            "keybundle_cls": qualified_name(self.keybundle_cls),
            "remove_after": self.remove_after,
            "spec2key": self.spec2key,
        }

        if exclude_attributes:
            for attr in exclude_attributes:
                try:
                    del info[attr]
                except KeyError:
                    pass

        if exclude_attributes is None:
            info["issuers"] = self._dump_issuers(
                exclude_issuers=exclude_issuers, exclude_attributes=exclude_attributes
            )
        elif "issuers" not in exclude_attributes:
            info["issuers"] = self._dump_issuers(
                exclude_issuers=exclude_issuers, exclude_attributes=exclude_attributes
            )

        return info

    def dumps(self, exclude_issuers: Optional[List[str]] = None):
        """
        Returns a JSON representation of the key jar

        :param exclude_issuers: Exclude these issuers
        :return: A string
        """
        _dict = self.dump(exclude_issuers=exclude_issuers)
        return json.dumps(_dict)

    def load(
        self,
        info: dict,
        init_args: Optional[dict] = None,
        load_args: Optional[dict] = None,
    ):
        """

        :param info: A dictionary with the information
        :return:
        """
        self.ca_certs = info.get("ca_certs", None)
        self.httpc_params = info.get("httpc_params", None)
        self.keybundle_cls = importer(info.get("keybundle_cls", KeyBundle))
        self.remove_after = info.get("remove_after", 3600)
        self.spec2key = info.get("spec2key", {})

        _issuers = info.get("issuers", None)
        if _issuers is None:
            self._issuers = {}
        else:
            for _issuer_id, _issuer_desc in _issuers.items():
                self._issuers[_issuer_id] = KeyIssuer().load(_issuer_desc)
        return self

    def loads(self, string):
        return self.load(json.loads(string))

    def flush(self):
        self.ca_certs = None
        self.httpc_params = None
        self._issuers = {}
        self.keybundle_cls = KeyBundle
        self.remove_after = 3600
        self.spec2key = {}
        # self.httpc=None,

        return self

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def key_summary(self, issuer_id):
        _issuer = self._get_issuer(issuer_id)
        if _issuer is not None:
            return _issuer.key_summary()

        raise IssuerNotFound(issuer_id)

    def update(self):
        """
        Go through the whole key jar, key issuer by key issuer and update them one
        by one.
        """
        ids = self._issuers.keys()
        for _id in ids:
            _issuer = self[_id]
            _issuer.update()
            self[_id] = _issuer

    @deprecated_alias(issuer="issuer_id", owner="issuer_id")
    def rotate_keys(self, key_conf, kid_template="", issuer_id=""):
        _issuer = self[issuer_id]
        _issuer.rotate_keys(key_conf=key_conf, kid_template=kid_template)
        self[issuer_id] = _issuer
        return self


# =============================================================================


def build_keyjar(key_conf, kid_template="", keyjar=None, issuer_id=""):
    """
    Builds a :py:class:`oidcmsg.key_jar.KeyJar` instance or adds keys to
    an existing KeyJar based on a key specification.

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
    :param keyjar: If an KeyJar instance the new keys are added to this key jar.
    :param issuer_id: The default owner of the keys in the key jar.
    :return: A KeyJar instance
    """

    _issuer = build_keyissuer(key_conf, kid_template, issuer_id=issuer_id)
    if _issuer is None:
        return None

    if keyjar is None:
        keyjar = KeyJar()

    keyjar[issuer_id] = _issuer

    return keyjar


@deprecated_alias(issuer="issuer_id", owner="issuer_id")
def init_key_jar(
    public_path="",
    private_path="",
    key_defs="",
    issuer_id="",
    read_only=True,
):
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

    :param public_path: A file path to a file that contains a JWKS with public keys
    :param private_path: A file path to a file that contains a JWKS with private keys.
    :param key_defs: A definition of what keys should be created if they are not already available
    :param issuer_id: The owner of the keys
    :param read_only: This function should not attempt to write anything to a file system.
    :return: An instantiated :py:class;`oidcmsg.key_jar.KeyJar` instance
    """

    _issuer = init_key_issuer(
        public_path=public_path,
        private_path=private_path,
        key_defs=key_defs,
        read_only=read_only,
    )

    if _issuer is None:
        raise ValueError("Could not find any keys")

    keyjar = KeyJar()
    keyjar[issuer_id] = _issuer
    return keyjar


def rotate_keys(key_conf, keyjar, kid_template="", issuer_id=""):
    new_keys = build_keyissuer(key_conf, kid_template, issuer_id=issuer_id)
    _issuer = keyjar[issuer_id]
    _issuer.mark_all_keys_as_inactive()
    for kb in new_keys:
        _issuer.add_kb(kb)
    keyjar[issuer_id] = _issuer
    return keyjar
