"""Tests for core.codefix_tools path-safety helpers."""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.codefix_tools import _validate_path  # noqa: E402


class TestValidatePath:
    def test_path_inside_base_allowed(self):
        base = tempfile.mkdtemp()
        p = _validate_path(os.path.join(base, "sub", "f.py"), base)
        assert str(p).startswith(base)

    def test_base_itself_allowed(self):
        base = tempfile.mkdtemp()
        assert _validate_path(base, base) is not None

    def test_sibling_prefix_escape_blocked(self):
        # `<base>-evil` shares the string prefix but is NOT contained by base.
        base = tempfile.mkdtemp()
        sib = base + "-evil"
        os.makedirs(sib, exist_ok=True)
        with pytest.raises(ValueError):
            _validate_path(os.path.join(sib, "secret"), base)

    def test_parent_traversal_blocked(self):
        base = tempfile.mkdtemp()
        with pytest.raises(ValueError):
            _validate_path(os.path.join(base, "..", "etc", "passwd"), base)

    def test_no_base_skips_check(self):
        # Without a base_path, any resolvable path is returned as-is.
        assert _validate_path(__file__) is not None
