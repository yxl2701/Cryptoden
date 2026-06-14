from utils.text_tools import (
    decode_escaped_text,
    get_character_frequencies,
    get_text_statistics,
    keep_alphanumeric,
    keep_hex_characters,
    remove_all_whitespace,
    remove_spaces_only,
    reverse_text,
    split_text_by_length,
    url_decode_text,
)


def test_split_text_by_length_with_separator():
    assert split_text_by_length("abcdefg", 3, "-") == "abc-def-g"


def test_split_text_by_length_rejects_invalid_length():
    try:
        split_text_by_length("abc", 0)
    except ValueError:
        assert True
    else:
        assert False, "expected ValueError"


def test_text_tools_helpers():
    assert remove_all_whitespace("a b\nc\t d") == "abcd"
    assert remove_spaces_only("a b\nc d") == "ab\ncd"
    assert reverse_text("abc123") == "321cba"
    assert keep_hex_characters("ab cd-12:zz") == "abcd12"
    assert keep_alphanumeric("ab-_12 zz!") == "ab12zz"
    assert decode_escaped_text(r"\x41\n\u4f60") == "A\n你"
    assert url_decode_text("flag%7Btest%7D") == "flag{test}"

    stats = get_text_statistics("ab ca\nzz")
    assert stats["characters"] == 8
    assert stats["lines"] == 2
    assert stats["non_whitespace_characters"] == 6
    assert stats["words"] == 3
    assert stats["unique_characters"] >= 4
    assert stats["letters"] == 6
    assert stats["digits"] == 0
    assert stats["whitespace"] == 2
    assert stats["hex_characters"] == 4
    assert stats["is_probably_hex"] is False


def test_hex_statistics_and_frequency():
    stats = get_text_statistics("41 42 43 44")
    assert stats["is_probably_hex"] is True

    frequencies = get_character_frequencies("aabc")
    assert frequencies[0] == ("a", 2)
