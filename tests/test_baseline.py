"""Baseline tests used by CI before feature work begins."""

import importlib


def test_package_imports() -> None:
    module = importlib.import_module("decemsg")
    assert module is not None


def test_package_version_is_declared() -> None:
    module = importlib.import_module("decemsg")
    assert getattr(module, "__version__", None) == "0.1.0"
