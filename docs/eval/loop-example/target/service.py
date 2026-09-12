"""A tiny report service, as the reviewer saw it."""

from pathlib import Path


def _load(name: str) -> str:
    """Read a report by name, refusing anything outside the root."""
    root = Path("reports").resolve()
    candidate = (root / name).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("outside the report root")
    return candidate.read_text(encoding="utf-8")


def render(name: str) -> str:
    """Render a report for a caller."""
    return _load(name)


def audit(action: str) -> None:
    """Write an audit line. Never called from anywhere in this module."""
    Path("audit.log").write_text(action, encoding="utf-8")
