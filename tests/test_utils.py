import pytest

from breachlens.utils import mask_email, redact_possible_secret, validate_domain, validate_email


def test_validate_domain_normalizes_url():
    assert validate_domain("https://www.Example.com/path") == "example.com"


def test_validate_email_lowercases():
    assert validate_email("USER@Example.COM") == "user@example.com"


def test_invalid_domain_raises():
    with pytest.raises(ValueError):
        validate_domain("not a domain")


def test_mask_email():
    assert mask_email("lucas@example.com") == "lu***@example.com"


def test_redact_possible_secret():
    assert redact_possible_secret("abcdefghijklmnop") == "abcd********mnop"
