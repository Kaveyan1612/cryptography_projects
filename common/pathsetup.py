"""sys.path bootstrapping shared by scripts, GUIs and tests.

Modules in this repository are plain scripts rather than an installed package,
so each entry point has to make the sibling implementation directories
importable. Every consumer does:

    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

    from common.pathsetup import add_project_paths

    add_project_paths()
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PROJECT_PATHS = (
    REPO_ROOT,
    REPO_ROOT / "aes_system",
    REPO_ROOT / "aes_system" / "python",
    REPO_ROOT / "rsa_system",
    REPO_ROOT / "rsa_system" / "python",
)


def add_paths(*paths) -> None:
    """Prepend the given directories to sys.path, skipping duplicates."""
    for path in paths:
        entry = str(path)
        if entry not in sys.path:
            sys.path.insert(0, entry)


def add_project_paths() -> None:
    """Make the repository root and both implementation packages importable."""
    add_paths(*PROJECT_PATHS)
