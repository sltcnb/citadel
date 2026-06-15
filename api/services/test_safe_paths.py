import pytest

from services.safe_paths import UnsafePathError, safe_join


def test_simple_name_within_base(tmp_path):
    p = safe_join(tmp_path, "foo_ingester.py")
    assert p == (tmp_path / "foo_ingester.py").resolve()


def test_subdir_allowed(tmp_path):
    p = safe_join(tmp_path, "sub/foo_plugin.py")
    assert p == (tmp_path / "sub" / "foo_plugin.py").resolve()


@pytest.mark.parametrize("evil", ["../escape.py", "a/../../escape", "/etc/passwd", "sub/../../x"])
def test_traversal_rejected(tmp_path, evil):
    with pytest.raises(UnsafePathError):
        safe_join(tmp_path, evil)


def test_base_itself_allowed(tmp_path):
    assert safe_join(tmp_path) == tmp_path.resolve()
