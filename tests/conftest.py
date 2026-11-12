"""Shared helpers. Fake secrets are assembled at runtime so that no secret-shaped
string is ever committed to this repository (keeps secret scanners quiet)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from webhook_check.js_scan import scan_js
from webhook_check.py_scan import scan_python

FIXTURES = Path(__file__).parent / "fixtures"

FAKE = {
    "whsec": "whsec" + "_" + "FAKEfakeFAKEfake0123456789abcdefAB",
    "generic": "Zq8" + "vN2pLr5Tx9WmK4c",
}


@pytest.fixture
def fake():
    return FAKE


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content", ...}) -> Path"""

    def _make(files: dict) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        return root

    return _make


@pytest.fixture
def copy_fixture(tmp_path):
    def _copy(name: str) -> Path:
        dst = tmp_path / name
        shutil.copytree(FIXTURES / name, dst)
        return dst

    return _copy


def js(code: str, rel: str = "server/app.ts"):
    """-> (findings, handlers) for one JS/TS source string."""
    return scan_js(rel, code)


def py(code: str, rel: str = "app.py"):
    return scan_python(rel, code)


def rules(findings) -> list[str]:
    return sorted(f.rule_id for f in findings)
