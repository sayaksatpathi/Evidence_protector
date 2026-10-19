"""Compatibility bridge to the canonical Log-Guardian package.

The shared implementation is installed as the evidence-protector distribution.
This file preserves imports from the repository root and the legacy
python evidence_protector.py ... invocation without copying the package source.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path


if __name__ == "__main__":
    # Importing by package name makes Python load this bridge once as the
    # evidence_protector package, then forward to the installed CLI.
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

    # Turn this module into a regular package backed by the installed core so
    # both import evidence_protector and import evidence_protector.core resolve
    # to the canonical implementation.
    __path__ = [str(_package_dir)]  # type: ignore[name-defined]
    if __spec__ is not None:
        __spec__.origin = str(_initializer)
        __spec__.submodule_search_locations = __path__

    __file__ = str(_initializer)
    exec(compile(_initializer.read_bytes(), str(_initializer), "exec"), globals(), globals())
