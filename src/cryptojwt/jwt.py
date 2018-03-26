import logging
import json
import uuid
from datetime import datetime
from json import JSONDecodeError

from cryptojwt import as_unicode
from cryptojwt import jwe
from cryptojwt import jws
from cryptojwt.exception import MissingValue
from cryptojwt.exception import VerificationError
from cryptojwt.jwe import JWE
from cryptojwt.jws import JWS
from cryptojwt.jws import NoSuitableSigningKeys

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


def utc_time_sans_frac():
    return int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())


def pick_key(keys, use, alg='', key_type='', kid=''):
    """

    :param keys: List of keys
    :param use: What the key is going to be used for
    :param alg: crypto algorithm
    :param key_type: Type of key
    :param kid: Ley ID
    :return: list of keys that match the pattern
    """
    res = []
    if not key_type:
        if use == 'sig':
            key_type = jws.alg2keytype(alg)
        else:
            key_type = jwe.alg2keytype(alg)
    for key in keys:
        if key.use != use:
            continue

        if key.kty == key_type:
            if key.alg == '' or key.alg == alg:
                if key.kid == '' or kid == '' or key.kid == kid:
                    res.append(key)
    return res


def get_jwt_keys(jwt, keys, use):
    try:
        if use == 'sig':
            _key_type = jws.alg2keytype(jwt.headers['alg'])
        else:
            _key_type = jwe.alg2keytype(jwt.headers['alg'])
    except KeyError:
        _key_type = ''

    try:
        _kid = jwt.headers['kid']
    except KeyError:
        _kid = ''  # Unknown

    # pick issuer keys
    if use == 'sig':
        payload = json.loads(as_unicode(jwt.part[1]))
        try:
            _keys = keys[payload['iss']]
        except KeyError:  # No issuer, not kosher
            raise MissingValue('iss')
        if not _kid:
            try:
                _kid = payload['kid']
            except KeyError:
                _kid = ''  # Unknown
    else:
        _keys = keys

    return pick_key(_keys, use, key_type=_key_type, kid=_kid)


class JWT(object):

    def __init__(self, own_keys=None, iss='', rec_keys=None, lifetime=0,
                 sign=True, sign_alg='RS256', encrypt=False,
                 enc_enc="A128CBC-HS256", enc_alg="RSA1_5", msg_cls=None,
                 iss2msg_cls=None, skew=15):
        self.own_keys = own_keys
        self.rec_keys = rec_keys or {}
        self.iss = iss
        self.lifetime = lifetime
        self.sign = sign
        self.sign_alg = sign_alg
        self.encrypt = encrypt
        self.enc_alg = enc_alg
        self.enc_enc = enc_enc
        self.msg_cls = msg_cls
        self.with_jti = False
        self.iss2msg_cls = iss2msg_cls or {}
        self.skew = skew

    def receiver_keys(self, recv):
        return self.rec_keys[recv]

    def receivers_keys(self):
        return self.rec_keys

    def my_keys(self, owner_id=''):
        return self.own_keys

    def _encrypt(self, payload, recv, cty='JWT'):
        kwargs = {"alg": self.enc_alg, "enc": self.enc_enc}

        if cty:
            kwargs["cty"] = cty

        # use the clients public key for encryption
        _jwe = JWE(payload, **kwargs)
        return _jwe.encrypt(self.receiver_keys(recv), context="public")

    def put_together_aud(self, recv, aud):
        if aud:
            if recv in aud:
                _aud = aud
            else:
                _aud = [recv]
                _aud.extend(aud)
        else:
            _aud = [recv]

        return _aud

    def pack_init(self, recv, aud):
        """
        Gather initial information for the payload.

        :return: A dictionary with claims and values
        """
        argv = {'iss': self.iss, 'iat': utc_time_sans_frac()}
        if self.lifetime:
            argv['exp'] = argv['iat'] + self.lifetime

        argv['aud'] = self.put_together_aud(recv, aud)

        return argv

    def pack_key(self, owner_id='', kid=''):
        """
        Find a key to be used for signing the Json Web Token

        :param owner_id: Owner of the keys to chose from
        :param kid: Key ID
        :return: One key
        """
        keys = pick_key(self.my_keys(owner_id), 'sig', alg=self.sign_alg,
                        kid=kid)

        if not keys:
            raise NoSuitableSigningKeys('kid={}'.format(kid))

        return keys[0]  # Might be more then one if kid == ''

    def pack(self, payload=None, kid='', owner='', recv='', aud=None, **kwargs):
        """

        :param payload: Information to be carried as payload in the JWT
        :param kid: Key ID
        :param owner: The owner of the the keys that are to be used for signing
        :param recv: The intended immediate receiver
        :param aud: Intended audience for this JWS/JWE, not expected to
            contain the recipient.
        :param kwargs: Extra keyword arguments
        :return: A signed or signed and encrypted JsonWebtoken
        """
        _args = self.pack_init(recv, aud)

        try:
            _encrypt = kwargs['encrypt']
        except KeyError:
            _encrypt = self.encrypt
        else:
            del kwargs['encrypt']

        if self.with_jti:
            try:
                _jti = kwargs['jti']
            except KeyError:
                _jti = uuid.uuid4().hex

            _args['jti'] = _jti

        if payload is not None:
            _args.update(payload)

        if self.sign:
            if self.sign_alg != 'none':
                _key = self.pack_key(owner, kid)
                _args['kid'] = _key.kid
            else:
                _key = None

            _jws = JWS(json.dumps(_args), alg=self.sign_alg)
            _sjwt = _jws.sign_compact([_key])
        else:
            _sjwt = json.dumps(_args)

        if _encrypt:
            if not self.sign:
                return self._encrypt(_sjwt, recv, cty='json')
            else:
                return self._encrypt(_sjwt, recv)
        else:
            return _sjwt

    def _verify(self, rj, token):
        keys = get_jwt_keys(rj.jwt, self.receivers_keys(), 'sig')
        return rj.verify_compact(token, keys)

    def _decrypt(self, rj, token):
        """
        Decrypt an encrypted JsonWebToken

        :param rj: :py:class:`jwkest.jwe.JWE` instance
        :param token: The encrypted JsonWebToken
        :return:
        """
        keys = get_jwt_keys(rj.jwt, self.my_keys(), 'enc')
        return rj.decrypt(token, keys=keys)

    def verify_profile(self, msg_cls, info, **kwargs):
        _msg = msg_cls(**info)
        if not _msg.verify(**kwargs):
            raise VerificationError()
        return _msg

    def unpack(self, token):
        """
        Unpack a received signed or signed and encrypted Json Web Token

        :param token: The Json Web Token
        :return: If decryption and signature verification work the payload
            will be returned as a Message instance if possible.
        """
        if not token:
            raise KeyError

        _content_type = 'jwt'
        _jwe_header = _jws_header = None

        # Check if it's an encrypted JWT
        _rj = jwe.factory(token)
        if _rj:
            # Yes, try to decode
            _info = self._decrypt(_rj, token)
            _jwe_header = _rj.jwt.headers
            # Try to find out if the information encrypted was a signed JWT
            try:
                _content_type = _rj.jwt.headers['cty']
            except KeyError:
                pass
        else:
            _info = token

        # If I have reason to believe the information I have is a signed JWT
        if _content_type.lower() == 'jwt':
            # Check that is a signed JWT
            _rj = jws.factory(_info)
            if _rj:
                _info = self._verify(_rj, _info)
            else:
                raise Exception()
            _jws_header = _rj.jwt.headers
        else:
            # So, not a signed JWT
            try:
                # A JSON document ?
                _info = json.loads(_info)
            except JSONDecodeError:  # Oh, no ! Not JSON
                return _info

        # If I know what message class the info should be mapped into
        if self.msg_cls:
            _msg_cls = self.msg_cls
        else:
            try:
                # try to find a issuer specific message class
                _msg_cls = self.iss2msg_cls[_info['iss']]
            except KeyError:
                _msg_cls = None

        if _msg_cls:
            vp_args = {'skew': self.skew}
            if self.iss:
                vp_args['aud'] = self.iss
            _info = self.verify_profile(_msg_cls, _info, **vp_args)
            _info.jwe_header = _jwe_header
            _info.jws_header = _jws_header
            return _info
        else:
            return _info
