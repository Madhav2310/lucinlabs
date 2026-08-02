"""Shared filesystem helpers.

Single source of truth for *which directories Lucin never walks*.

Vendored / build / VCS directories (``venv``, ``node_modules``, ``.git``,
``site-packages``, ``*.dist-info``, ``dist``, ``build``, ``__pycache__`` ...)
contain third-party and compiled artifacts, not first-party agent code.
Walking them was the root cause of the "0% FP" credibility defect: running
``lucin scan .`` on any real project with a virtualenv flagged every
``.so``/``.dll`` under ``venv/`` as a HIGH "binary payload", producing a wall
of false positives in the field. Every file walk in the scanner and parsers
routes through :func:`iter_files` so the exclusion is applied uniformly.
"""

from pathlib import Path

# Directory *names* that are excluded anywhere in a scanned tree.
EXCLUDED_DIR_NAMES = {
    # Python virtual environments
    "venv", ".venv", "env", ".env", "virtualenv", "venvs",
    # Installed packages
    "site-packages", "dist-packages",
    # JS / other package managers
    "node_modules", "bower_components", "vendor",
    # Version control
    ".git", ".hg", ".svn",
    # Build / packaging output
    "dist", "build", "__pycache__", ".eggs",
    # Tool caches
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".cache", ".idea", ".vscode",
}

# Directory *suffixes* that are excluded (package metadata dirs).
_EXCLUDED_DIR_SUFFIXES = (".dist-info", ".egg-info")


def is_excluded(path: Path, root: Path) -> bool:
    """True if ``path`` lives inside a vendored/build/VCS directory under ``root``.

    Only path components *below* ``root`` are considered, so a deliberate
    ``lucin scan ./venv`` (root == venv) still scans that tree — the
    exclusion is about incidental vendored subtrees, not explicit targets.
    """
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    for part in parts:
        if part in EXCLUDED_DIR_NAMES:
            return True
        if part.endswith(_EXCLUDED_DIR_SUFFIXES):
            return True
    return False


def iter_files(target: Path, pattern: str = "*") -> list[Path]:
    """``rglob`` that skips vendored/build/VCS directories.

    If ``target`` is a file it is returned as-is (a single explicit file is
    never subject to directory exclusion). If it is a directory, its tree is
    walked with :data:`EXCLUDED_DIR_NAMES` pruned out.
    """
    if target.is_file():
        return [target]
    if not target.exists():
        return []
    return [p for p in target.rglob(pattern) if not is_excluded(p, target)]
