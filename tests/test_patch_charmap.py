import pytest

from dfrus.patch_charmap import Encoder, get_encoder, get_supported_codepages, ord_utf16


@pytest.mark.parametrize(
    "codepage_data,input_string,expected",
    [({0x1E: ord_utf16("Ỵ"), 0x80: map(ord_utf16, "ẠẮẰẶẤẦẨẬẼẸẾỀỂỄỆỐ")}, "ẠẮẰỴ ", b"\x80\x81\x82\x1E ")],
)
def test_encoder(codepage_data, input_string, expected):
    encoder = Encoder(codepage_data)
    assert encoder.encode(input_string) == (expected, len(expected))


def test_combining_grave_accent():
    text = "ờ"
    assert get_encoder("viscii")(text)[0]


def test_get_codepages():
    for codepage in get_supported_codepages():
        assert (
            codepage in {"cp437", "viscii"}
            or "_" in codepage
            and int(codepage.partition("_")[2]) in range(1, 17)  # iso codepages
            or int(codepage[2:]) in range(700, 1253)
        )  # cp codepages


def can_be_encoded(text: str, encoding):
    try:
        text.encode(encoding)
    except UnicodeEncodeError:
        return False
    else:
        return True


def test_esperanto():
    text = " ĉirkaŭprenas "
    assert any(can_be_encoded(text, encoding) for encoding in get_supported_codepages())
