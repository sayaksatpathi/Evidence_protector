"""Backward-compatible launcher for the engine maintained in Log-Guardian.

The actual `evidence_protector` package is installed from the pinned GitHub
archive declared by this repository's pyproject.toml and requirements.txt.
This shim avoids keeping a second copy of the engine source in this repository.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def _load_installed_engine():
    """Load the installed engine package under its canonical import name."""
    repository_root = Path(__file__).resolve().parent
    package_init = None

    for entry in sys.path:
        try:
            base = Path(entry or os.curdir).resolve()
        except (OSError, RuntimeError):
            continue

        # Never resolve this compatibility module back to itself.
        if base == repository_root:
            continue

        candidate = base / "evidence_protector" / "__init__.py"
        if candidate.is_file():
            package_init = candidate.resolve()
            break

    if package_init is None:
        raise ImportError(
            "The shared Evidence Protector engine is not installed. "
            "Install the project dependencies with "
            "`python -m pip install -r requirements.txt`."
        )

    spec = importlib.util.spec_from_file_location(
        "evidence_protector",
        str(package_init),
        submodule_search_locations=[str(package_init.parent)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load the shared engine from {package_init}")

    module = importlib.util.module_from_spec(spec)
    sys.modules["evidence_protector"] = module
    spec.loader.exec_module(module)
    return module


_engine = _load_installed_engine()

if __name__ == "__main__":
    _engine.main()
else:
    # Export the canonical package API for legacy imports. The entry in
    # sys.modules is replaced with the canonical package, so submodules such
    # as evidence_protector.core also resolve to the same module instances.
    globals().update(_engine.__dict__)
