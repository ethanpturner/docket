"""Find checks that cannot come out false.

Six defects of one class turned up across two repositories in two days, and every one of them was
a place where the code agreed with itself. A status nothing assigns, filtered on. A guard whose
fallback always satisfies it. A metric whose denominator is authored. A test whose subject is
mocked to produce the thing asserted. Each passed review, passed CI, and established nothing.

The common shape is that the failing branch is unreachable, so this looks for the three instances
of it that a parser can settle:

- **an enum member nothing assigns** outside tests, which makes every filter keyed on it dead;
- **an exception type nothing raises**, which makes every `except` for it dead;
- **a test whose assertions cannot fail** -- no assertion at all, or only assertions over literals.

It is a worklist and not a verdict. An enum member that only a JSON payload names, an exception
raised by a subclass, a test whose whole purpose is that a constructor does not raise: all three
are reported here and all three are fine. The cleared ones belong in the audit page so the next
pass does not rediscover them.

The taxonomy has three more branches that no parser settles -- a metric over authored data, an
invariant with no test that would fail if the enforcement were removed, and a label that disagrees
in direction with the field it is stored in. Those are read by a person. This finds the mechanical
third and says so.

Runs against any repository, since it reads source rather than importing it:

    uv run python scripts/audit_unfailable.py /path/to/repo [--json]
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# Directories whose contents are neither the product nor its tests: fixtures, vendored copies,
# build output, and the example targets whose bytes are pinned by a digest elsewhere.
_SKIP_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        "build",
        "dist",
        "target",
        "recorded",
        "recordings",
        "benchmarks",
        "demo",
    }
)

_ENUM_BASES: Final[frozenset[str]] = frozenset({"Enum", "StrEnum", "IntEnum", "Flag", "IntFlag"})


@dataclass(frozen=True, slots=True)
class Finding:
    """One candidate. `kind` is the detector; `why` is what makes it a candidate."""

    kind: str
    name: str
    file: str
    line: int
    why: str

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "why": self.why,
        }


@dataclass(slots=True)
class _Module:
    """One parsed file, with the source kept so a reader can be pointed at a line."""

    path: Path
    relative: str
    tree: ast.Module
    is_test: bool


def _is_test_path(relative: str) -> bool:
    parts = Path(relative).parts
    return "tests" in parts or Path(relative).name.startswith("test_")


def _parse(root: Path) -> list[_Module]:
    """Every Python file under `root` that is plausibly source or test, parsed."""
    modules: list[_Module] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError, UnicodeDecodeError:
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            continue
        relative = str(path.relative_to(root))
        modules.append(_Module(path, relative, tree, _is_test_path(relative)))
    return modules


def _enum_members(modules: list[_Module]) -> dict[str, tuple[str, str, int]]:
    """Every enum member, keyed `Class.MEMBER`, mapped to (qualified name, file, line)."""
    members: dict[str, tuple[str, str, int]] = {}
    for module in modules:
        if module.is_test:
            continue
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {b.id for b in node.bases if isinstance(b, ast.Name)} | {
                b.attr for b in node.bases if isinstance(b, ast.Attribute)
            }
            if not bases & _ENUM_BASES:
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id.isupper():
                            key = f"{node.name}.{target.id}"
                            members[key] = (key, module.relative, target.lineno)
    return members


def _exception_classes(modules: list[_Module]) -> dict[str, tuple[str, int]]:
    """Every class whose name or base marks it an exception, mapped to (file, line)."""
    classes: dict[str, tuple[str, int]] = {}
    for module in modules:
        if module.is_test:
            continue
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            base_names = {b.id for b in node.bases if isinstance(b, ast.Name)}
            looks_like = node.name.endswith(("Error", "Exception")) or bool(
                base_names & {"Exception", "ValueError", "RuntimeError", "TypeError", "OSError"}
            )
            if looks_like:
                classes[node.name] = (module.relative, node.lineno)
    return classes


def _referenced_attributes(modules: list[_Module], *, in_tests: bool) -> set[str]:
    """`Class.MEMBER` strings appearing as attribute access in the selected files."""
    seen: set[str] = set()
    for module in modules:
        if module.is_test != in_tests:
            continue
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                seen.add(f"{node.value.id}.{node.attr}")
    return seen


def _raised_names(modules: list[_Module]) -> set[str]:
    """Every name that appears in a `raise`, in source files only."""
    raised: set[str] = set()
    for module in modules:
        if module.is_test:
            continue
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Raise) or node.exc is None:
                continue
            exc = node.exc
            if isinstance(exc, ast.Call):
                exc = exc.func
            if isinstance(exc, ast.Name):
                raised.add(exc.id)
            elif isinstance(exc, ast.Attribute):
                raised.add(exc.attr)
    return raised


def _assertion_can_fail(node: ast.Assert) -> bool:
    """Whether an `assert` compares anything that is not a literal.

    `assert True`, `assert 1 == 1` and `assert "a" in "abc"` cannot fail. Anything naming a
    variable, calling something, or reading an attribute can, so this errs toward reporting
    fewer candidates than a stricter reading would.
    """
    for child in ast.walk(node.test):
        if isinstance(child, ast.Name | ast.Call | ast.Attribute | ast.Subscript):
            return True
    return False


def _unfailable_tests(modules: list[_Module]) -> list[Finding]:
    """Test functions with no assertion, or only assertions over literals.

    A test body that calls something and raises on failure is a real test with no `assert`, so a
    function whose body contains a call is not reported unless it also contains a dead assertion.
    `pytest.raises` counts as an assertion.
    """
    findings: list[Finding] = []
    for module in modules:
        if not module.is_test:
            continue
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not node.name.startswith("test"):
                continue
            asserts = [n for n in ast.walk(node) if isinstance(n, ast.Assert)]
            has_raises = any(
                isinstance(n, ast.withitem)
                and isinstance(n.context_expr, ast.Call)
                and _call_name(n.context_expr).endswith("raises")
                for n in ast.walk(node)
            )
            has_call = any(isinstance(n, ast.Call) for n in ast.walk(node))
            if asserts:
                if not any(_assertion_can_fail(a) for a in asserts):
                    findings.append(
                        Finding(
                            "unfailable-test",
                            node.name,
                            module.relative,
                            node.lineno,
                            "every assertion compares literals",
                        )
                    )
                continue
            if has_raises:
                continue
            if not has_call:
                findings.append(
                    Finding(
                        "unfailable-test",
                        node.name,
                        module.relative,
                        node.lineno,
                        "no assertion and no call: nothing can fail",
                    )
                )
    return findings


def _call_name(call: ast.Call) -> str:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


@dataclass(slots=True)
class Audit:
    """What one repository's parse found."""

    root: Path
    modules: int = 0
    findings: list[Finding] = field(default_factory=list)


def audit(root: Path) -> Audit:
    """Parse every file under `root` and report the three mechanical candidates."""
    modules = _parse(root)
    result = Audit(root=root, modules=len(modules))

    members = _enum_members(modules)
    in_source = _referenced_attributes(modules, in_tests=False)
    in_tests = _referenced_attributes(modules, in_tests=True)
    for key, (_name, file, line) in sorted(members.items()):
        if key in in_source:
            continue
        why = (
            "named in tests only; nothing in the source assigns it"
            if key in in_tests
            else "nothing names it, in source or tests"
        )
        result.findings.append(Finding("unassigned-enum-member", key, file, line, why))

    raised = _raised_names(modules)
    for name, (file, line) in sorted(_exception_classes(modules).items()):
        if name not in raised:
            result.findings.append(
                Finding("unraised-exception", name, file, line, "no `raise` names this type")
            )

    result.findings.extend(_unfailable_tests(modules))
    return result


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    as_json = "--json" in argv[1:]
    root = Path(args[0]).resolve() if args else Path.cwd()
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    result = audit(root)
    if as_json:
        print(
            json.dumps(
                {
                    "root": str(result.root),
                    "modules": result.modules,
                    "findings": [f.as_dict() for f in result.findings],
                },
                indent=2,
            )
        )
        return 0

    print(f"{result.root}  ({result.modules} files parsed)")
    if not result.findings:
        print("  no mechanical candidates")
        return 0
    by_kind: dict[str, list[Finding]] = {}
    for finding in result.findings:
        by_kind.setdefault(finding.kind, []).append(finding)
    for kind in sorted(by_kind):
        print(f"\n  {kind}  ({len(by_kind[kind])})")
        for finding in by_kind[kind]:
            print(f"    {finding.file}:{finding.line}  {finding.name}")
            print(f"      {finding.why}")
    print(
        "\n  A candidate is not a defect. Clear each one and record why, so the next pass does "
        "not redo it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
