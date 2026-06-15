from services.elasticsearch import escape_lucene_query


def test_escapes_stray_slash():
    assert escape_lucene_query("message:*HTTP/2*") == r"message:*HTTP\/2*"


def test_escapes_path():
    assert escape_lucene_query("http.request_path:*/app/129/*") == r"http.request_path:*\/app\/129\/*"


def test_leaves_already_escaped():
    # already-escaped slash is not double-escaped
    assert escape_lucene_query(r"message:*HTTP\/2*") == r"message:*HTTP\/2*"


def test_no_slash_unchanged():
    q = "artifact_type:access_log AND message:*reset*"
    assert escape_lucene_query(q) == q


def test_empty():
    assert escape_lucene_query("") == ""


def test_preserve_regex_keeps_balanced_token():
    q = "message:/HTTP.2/"
    assert escape_lucene_query(q, preserve_regex=True) == q


def test_preserve_regex_still_escapes_when_no_regex():
    # single stray slash is not a balanced /regex/ — escape it
    assert escape_lucene_query("message:*a/b*", preserve_regex=True) == r"message:*a\/b*"
