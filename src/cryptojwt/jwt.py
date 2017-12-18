import logging
from datetime import datetime
import json
import uuid

from cryptojwt import jwe
from cryptojwt import jws
from cryptojwt.jwe import JWE
from cryptojwt.jws import alg2keytype
from cryptojwt.jws import JWS
from cryptojwt.jws import NoSuitableSigningKeys

__author__ = 'Roland Hedberg'

logger  = logging.getLogger(__name__)


def utc_time_sans_frac():
    return int((datetime.utcnow() - datetime(1970, 1, 1)).total_seconds())


def pick_key(keys, use, alg='', key_type='', kid=''):
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
        _kid = ''

    return pick_key(keys, use, key_type=_key_type, kid=_kid)


class JWT(object):
    def __init__(self, keys, iss='', lifetime=0, sign_alg='RS256',
                 encrypt=False, enc_enc="A128CBC-HS256",
                 enc_alg="RSA1_5"):
        self.keys = keys
        self.iss = iss
        self.lifetime = lifetime
        self.sign_alg = sign_alg
        self.encrypt = encrypt
        self.enc_alg = enc_alg
        self.enc_enc = enc_enc
        self.with_jti = False

    def _encrypt(self, payload, cty='JWT'):
        kwargs = {"alg": self.enc_alg, "enc": self.enc_enc}

        if cty:
            kwargs["cty"] = cty

        # use the clients public key for encryption
        _jwe = JWE(payload, **kwargs)
        return _jwe.encrypt(self.keys, context="public")

    def pack_init(self):
        """
        Gather initial information for the payload.

        :return: A dictionary with claims and values
        """
        argv = {'iss': self.iss, 'iat': utc_time_sans_frac()}
        if self.lifetime:
            argv['exp'] = argv['iat'] + self.lifetime
        return argv

    def pack_key(self, owner='', kid=''):
        """
        Find a key to be used for signing the Json Web Token

        :param owner: Owner of the keys to chose from
        :param kid: Key ID
        :return: One key
        """
        keys = pick_key(self.keys, 'sig', alg=self.sign_alg, kid=kid)

        if not keys:
            raise NoSuitableSigningKeys('kid={}'.format(kid))

        return keys[0]  # Might be more then one if kid == ''

    def pack(self, payload=None, kid='', owner='', cls_instance=None, **kwargs):
        """

        :param payload: Information to be carried as payload in the JWT
        :param kid: Key ID
        :param owner: The owner of the the keys that are to be used for signing
        :param cls_instance: This might be a instance of a class already
            prepared with information
        :param kwargs: Extra keyword arguments
        :return: A signed or signed and encrypted JsonWebtoken
        """
        _args = self.pack_init()

        if self.sign_alg != 'none':
            _key = self.pack_key(owner, kid)
            _args['kid'] = _key.kid
        else:
            _key = None

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

        _jws = JWS(json.dumps(payload), alg=self.sign_alg)
        _sjwt = _jws.sign_compact([_key])
        #_jws = _jwt.to_jwt([_key], self.sign_alg)
        if _encrypt:
            return self._encrypt(_sjwt)
        else:
            return _sjwt

    def _verify(self, rj, token):
        keys = get_jwt_keys(rj.jwt, self.keys, 'sig')
        return rj.verify_compact(token, keys)

    def _decrypt(self, rj, token):
        """
        Decrypt an encrypted JsonWebToken
        
        :param rj: :py:class:`jwkest.jwe.JWE` instance 
        :param token: The encrypted JsonWebToken
        :return: 
        """
        keys = get_jwt_keys(rj.jwt, self.keys, 'enc')
        return rj.decrypt(token, keys=keys)

    def unpack(self, token):
        """
        Unpack a received signed or signed and encrypted Json Web Token

        :param token: The Json Web Token
        :return: If decryption and signature verification work the payload
            will be returned as a Message instance.
        """
        if not token:
            raise KeyError

        _rj = jwe.factory(token)
        if _rj:
            token = self._decrypt(_rj, token)

        _rj = jws.factory(token)
        if _rj:
            info = self._verify(_rj, token)
        else:
            raise Exception()

        return info
