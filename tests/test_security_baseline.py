"""Baseline security regression checks.

These checks are intentionally small; TASK-002 will expand this suite into
federation authentication, authorization, replay, and injection tests.
"""

from pathlib import Path


def test_no_private_key_material_is_checked_in() -> None:
    root = Path(__file__).resolve().parents[2]
    forbidden_suffixes = {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
    }
    candidates = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in forbidden_suffixes
    ]
    assert candidates == []
