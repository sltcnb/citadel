from services.elasticsearch import _substring_variant


def test_bare_word():
    assert _substring_variant("gallot") == "*gallot*"


def test_ioc():
    assert _substring_variant("192.168.1.1") == "*192.168.1.1*"


def test_boolean_keeps_operators():
    assert _substring_variant("signal  AND NOT SignalBot") == "*signal*  AND NOT *SignalBot*"


def test_field_qualified_untouched():
    assert _substring_variant("user.name:gallot") is None
    assert _substring_variant("user.name:gallot AND signal") == "user.name:gallot AND *signal*"


def test_skips_short_wildcard_phrase_regex():
    assert _substring_variant("ab") is None
    assert _substring_variant("*gal*") is None
    assert _substring_variant('"signal bot"') is None
    assert _substring_variant("/sig.*/") is None
