"""The JSONPath subset used for response extraction.

A malformed *path* is an operator config error and must raise; a path that
simply does not match a response returns None, because that is a legitimate
runtime outcome when a target answers in an unexpected shape.
"""

import pytest

from app.core.targets.jsonpath import JsonPathError, extract, validate_path

DATA = {
    "choices": [{"message": {"content": "hi"}}],
    "items": [1, 2, 3],
    "quoted key": {"x": 1},
    "empty": {},
}


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("$", DATA),
        ("$.choices[0].message.content", "hi"),
        ("$.items[2]", 3),
        ("$.items[-1]", 3),
        ("$['quoted key'].x", 1),
        ('$["quoted key"].x', 1),
    ],
)
def test_extracts_supported_paths(path: str, expected: object) -> None:
    assert extract(DATA, path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "$.missing",
        "$.choices[5]",
        "$.items[9]",
        "$.items[-9]",
        "$.choices.message",  # indexing a list with a key
        "$.empty.x.y",
    ],
)
def test_missing_values_return_none_rather_than_raising(path: str) -> None:
    assert extract(DATA, path) is None


@pytest.mark.parametrize(
    "path",
    [
        "choices[0]",  # no leading $
        "$.items[*]",  # wildcard
        "$..content",  # recursive descent
        "$.items[",  # unclosed bracket
        "$.items[a:b]",  # slice
        "$.",  # empty key
        "$items",  # unexpected character
    ],
)
def test_malformed_paths_raise(path: str) -> None:
    with pytest.raises(JsonPathError):
        validate_path(path)
