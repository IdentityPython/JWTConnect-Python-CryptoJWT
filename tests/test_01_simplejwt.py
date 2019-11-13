from cryptojwt.simple_jwt import SimpleJWT

__author__ = 'roland'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_pack_jwt():
    _jwt = SimpleJWT(**{"alg": "none", "cty": "jwt"})
    jwt = _jwt.pack(parts=[{"iss": "joe", "exp": 1300819380,
                            "http://example.com/is_root": True}, ""])

    p = jwt.split('.')
    assert len(p) == 3


def test_unpack_pack():
    _jwt = SimpleJWT(**{"alg": "none"})
    payload = {"iss": "joe", "exp": 1300819380,
               "http://example.com/is_root": True}
    jwt = _jwt.pack(parts=[payload, ""])
    repacked = SimpleJWT().unpack(jwt).pack()

    assert jwt == repacked


def test_pack_unpack():
    _jwt = SimpleJWT(**{"alg": "none"})
    payload = {"iss": "joe", "exp": 1300819380,
               "http://example.com/is_root": True}
    jwt = _jwt.pack(parts=[payload, ""])

    _jwt2 = SimpleJWT().unpack(jwt)

    assert _jwt2
    out_payload = _jwt2.payload()
    assert _eq(out_payload.keys(), ["iss", "exp", "http://example.com/is_root"])
    assert out_payload["iss"] == payload["iss"]
    assert out_payload["exp"] == payload["exp"]
    assert out_payload["http://example.com/is_root"] == payload[
        "http://example.com/is_root"]


def test_pack_with_headers():
    _jwt = SimpleJWT()
    jwt = _jwt.pack(parts=["", ""], headers={"foo": "bar"})
    assert SimpleJWT().unpack(jwt).headers["foo"] == "bar"


def test_unpack_str():
    _jwt = SimpleJWT(**{"alg": "none"})
    payload = {"iss": "joe", "exp": 1300819380,
               "http://example.com/is_root": True}
    jwt = _jwt.pack(parts=[payload, ""])

    _jwt2 = SimpleJWT().unpack(jwt)
    assert _jwt2
    _ = _jwt2.payload()
