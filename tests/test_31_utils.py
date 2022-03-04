from cryptojwt.utils import check_content_type


def test_check_content_type():
    assert check_content_type(content_type="application/json", mime_type="application/json") == True
    assert (
        check_content_type(
            content_type="application/json; charset=utf-8", mime_type="application/json"
        )
        == True
    )
    assert (
        check_content_type(
            content_type="application/html; charset=utf-8", mime_type="application/json"
        )
        == False
    )
