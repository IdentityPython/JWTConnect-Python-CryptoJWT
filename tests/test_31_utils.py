import pytest

from cryptojwt.utils import check_content_type


def test_check_content_type():
    assert check_content_type(content_type="application/json", mime_type="application/json") is True
    assert (
        check_content_type(
            content_type="application/json; charset=utf-8", mime_type="application/json"
        )
        is True
    )
    assert (
        check_content_type(
            content_type="application/html; charset=utf-8", mime_type="application/json"
        )
        is False
    )
    assert (
        check_content_type(
            content_type="application/jwk-set+json;charset=UTF-8",
            mime_type="application/application/jwk-set+json",
        )
        is False
    )
    assert (
        check_content_type(
            content_type="application/jwk-set+json;charset=UTF-8",
            mime_type=set(["application/application/jwk-set+json", "application/json"]),
        )
        is False
    )
    with pytest.raises(ValueError):
        check_content_type(content_type="application/jwk-set+json;charset=UTF-8", mime_type=42)
