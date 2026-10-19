"""Compatibility bridge to the canonical Log-Guardian package.

The shared implementation is installed as the evidence-protector distribution.
This file preserves imports from the repository root and the legacy
python evidence_protector.py ... invocation without copying the package source.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path


if __name__ == "__main__":
    # Import the installed package by its canonical package name and invoke its
    # CLI. The repository-local file is only the backwards-compatible launcher.
    from evidence_protector.cli import main

    main()
else:
    try:
        _distribution = distribution("evidence-protector")
    except PackageNotFoundError as exc:
        raise ImportError(
            "The shared Evidence Protector engine is not installed. "
            "Install this application with 'python -m pip install -e .' first."
        ) from exc

    _package_dir = Path(
        _distribution.locate_file("evidence_protector")
    ).resolve()
    _initializer = _package_dir / "__init__.py"
    if not _initializer.is_file():
        raise ImportError(
            "The installed evidence-protector distribution does not contain "
            "evidence_protector/__init__.py."
        )

    # Load the installed initializer as a genuine package. Executing __init__.py
    # directly with exec() breaks relative imports; a package spec supplies the
    # correct __package__, __path__, and submodule search locations.
    _spec = importlib.util.spec_from_file_location(
        __name__,
        str(_initializer),
        submodule_search_locations=[str(_package_dir)],
    )
    if _spec is None or _spec.loader is None:
        raise ImportError("Unable to load the installed evidence-protector package")

    _package = importlib.util.module_from_spec(_spec)
    sys.modules[__name__] = _package
    _spec.loader.exec_module(_package)
    globals().update(_package.__dict__)
