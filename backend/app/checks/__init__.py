"""Importing this package registers every check module in it automatically.

To add a check: write a function with @register in any new module here
(files starting with '_' are skipped). Nothing else needs editing.
"""

import importlib
import pkgutil

from .registry import REGISTRY, SEVERITIES, STATUSES, CannotScan, Check, Context, register

for _mod in pkgutil.iter_modules(__path__):
    if not _mod.name.startswith("_") and _mod.name != "registry":
        importlib.import_module(f"{__name__}.{_mod.name}")

__all__ = ["REGISTRY", "SEVERITIES", "STATUSES", "Check", "CannotScan", "Context", "register"]
