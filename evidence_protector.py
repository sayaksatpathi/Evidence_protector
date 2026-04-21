"""Evidence Protector compatibility module.

The canonical implementation lives under `src/evidence_protector/` as a proper
Python package.

This top-level module exists to preserve backwards compatibility for:
  - `import evidence_protector`
  - `python evidence_protector.py ...`

It dynamically loads the `src/` package under an internal module name and
re-exports its public API.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING


_REPO_ROOT = Path(__file__).resolve().parent
_PKG_DIR = _REPO_ROOT / "src" / "evidence_protector"

# Allow `import evidence_protector.<submodule>` even though this is a single-file
# compatibility shim. When `__path__` is present, Python treats the module as a
# package for submodule resolution.
__path__ = [str(_PKG_DIR)]  # type: ignore[name-defined]
if __spec__ is not None:
  __spec__.submodule_search_locations = [str(_PKG_DIR)]  # type: ignore[assignment]


def _load_impl_package():
  pkg_dir = _PKG_DIR
  init_py = _PKG_DIR / "__init__.py"
  if not init_py.exists():
    raise ImportError("Expected src/evidence_protector/__init__.py to exist")

  spec = importlib.util.spec_from_file_location(
    "_evidence_protector_impl",
    str(init_py),
    submodule_search_locations=[str(pkg_dir)],
  )
  if spec is None or spec.loader is None:
    raise ImportError("Unable to load Evidence Protector implementation package")

  module = importlib.util.module_from_spec(spec)
  sys.modules[spec.name] = module
  spec.loader.exec_module(module)
  return module


_impl = _load_impl_package()


if TYPE_CHECKING:
  # Static type checkers can't follow the dynamic re-export below.
  # Import the public surface here so `import evidence_protector as ep` gets
  # correct symbols/types in editors.
  from evidence_protector.core import (  # noqa: F401
    SIGNATURE_SCHEME,
    CheckpointEntry,
    HashEntry,
    SuspiciousGap,
    TamperResult,
    build_hash_chain,
    compute_manifest_signature,
    extract_timestamp,
    fingerprint_phrase,
    format_duration,
    scan_log,
    sign_log,
    verify_log,
    verify_manifest_signature,
  )
  from evidence_protector.ghost_protocol import (  # noqa: F401
    GhostBaseline,
    GhostConfig,
    GhostEvent,
    GhostReport,
    analyze_log,
    build_baseline,
    load_baseline,
    load_report,
    save_baseline,
    save_report,
  )

__all__ = list(getattr(_impl, "__all__", []))
for name in __all__:
  globals()[name] = getattr(_impl, name)


if __name__ == "__main__":
  main()

