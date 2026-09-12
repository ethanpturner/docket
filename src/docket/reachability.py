"""Can the cited code be reached, and from where?

This answers the third question with the standard library's `ast` and nothing else. It builds a
crude call graph over the repository's Python files, finds the functions that look like entry
points, and reports whether the function containing the cited line is called from anywhere.

**The verdict `no_caller_found` is not `unreachable`, and the distinction is the product.** A call
graph built from source text loses every dynamic call: a framework registering a handler by
decorator, a dispatch table keyed by string, `getattr`, a signal, a plugin loaded by entry point,
a caller in another repository. Any of those makes a function that no static caller references run
on every request. So this module reports what it found and refuses to convert an absence of
evidence into evidence of absence, which is the same rule the disposition applies one level up.

The analysis is deliberately shallow. Name resolution across modules is approximated by function
name rather than by import binding, so two functions with the same name in different modules are
treated as one target. That over-connects the graph, which is the safe direction: it produces
`reachable_from` where a precise analysis might say nothing, and the cost of the imprecision is a
weaker `supports_justification` rather than a false one.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "ENTRY_POINT_DECORATORS",
    "CallGraph",
    "Reachability",
    "ReachabilityFinding",
    "build_call_graph",
    "reachability_of",
]

# Decorator name fragments that mark a function as called by something outside this repository.
# Matched against the decorator's dotted source text, so `@app.route(...)`, `@router.get(...)`,
# and `@celery.task` all hit. The list is short on purpose: a missed framework yields
# `no_caller_found` with its caveat, not a wrong answer.
ENTRY_POINT_DECORATORS: Final[tuple[str, ...]] = (
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "websocket",
    "task",
    "command",
    "handler",
    "on_event",
    "middleware",
    "subscribe",
    "listener",
    "app.",
    "router.",
    "celery",
    "lambda_handler",
)

# Names that are entry points by convention, whatever decorates them.
#
# There is deliberately no rule about *filenames*. An earlier version treated every module-level
# function in `app.py`, `main.py`, or `cli.py` as an entry point, which marked a module's private
# helpers as reachable because of the file they sat in. That error runs in the safe direction --
# it produces `reachable_from`, which withholds a dismissal candidate rather than offering a bad
# one -- and it is still wrong, and it suppresses the signal this analysis exists to produce.
_ENTRY_POINT_NAMES: Final[frozenset[str]] = frozenset({"main", "handler", "lambda_handler"})

_MAX_FILE_BYTES: Final = 1_000_000
"""Files larger than this are skipped rather than parsed. A generated megabyte of Python is not
what this analysis is for, and parsing it costs seconds per call."""


class Reachability(StrEnum):
    """What the call graph says about the function containing the cited line."""

    REACHABLE_FROM = "reachable_from"
    """A caller was found, or the function is itself an entry point."""

    NO_CALLER_FOUND = "no_caller_found"
    """No static caller and no entry-point marker. **Not** a finding of unreachability."""

    NOT_DETERMINABLE = "not_determinable"
    """The analysis could not run: the file is not Python, does not parse, or the cited line is
    not inside a function."""


@dataclass(frozen=True, slots=True)
class FunctionSite:
    """One function definition, and where it is."""

    name: str
    path: str
    start_line: int
    end_line: int
    is_entry_point: bool = False
    entry_point_reason: str = ""


@dataclass(frozen=True, slots=True)
class CallGraph:
    """Every function in the repository, and which names each one calls.

    `callers_of` is keyed by bare function name, which is the approximation described in the
    module docstring: precise enough to answer "does anything call this", imprecise about which
    definition of an overloaded name is meant.
    """

    functions: tuple[FunctionSite, ...] = ()
    calls: dict[str, frozenset[str]] = field(default_factory=dict)
    """Caller key (`path::name`) to the set of bare names it calls."""

    parse_failures: tuple[str, ...] = ()
    """Paths that could not be parsed. Reported so a reviewer knows the graph has holes."""

    def callers_of(self, name: str) -> tuple[str, ...]:
        """Every caller key whose body names `name`. Excludes the function itself."""
        return tuple(
            sorted(
                caller
                for caller, called in self.calls.items()
                if name in called and not caller.endswith(f"::{name}")
            )
        )

    def enclosing(self, path: str, line: int) -> FunctionSite | None:
        """The innermost function containing `line` in `path`, if any."""
        candidates = [
            site
            for site in self.functions
            if site.path == path and site.start_line <= line <= site.end_line
        ]
        if not candidates:
            return None
        # Innermost wins: a nested function's range is inside its parent's.
        return min(candidates, key=lambda site: site.end_line - site.start_line)


@dataclass(frozen=True, slots=True)
class ReachabilityFinding:
    """The answer for one cited position, with the evidence behind it."""

    verdict: Reachability
    function: str | None = None
    """The enclosing function's name, when the cited line is inside one."""

    callers: tuple[str, ...] = ()
    """Caller keys found, capped for readability. Empty for an entry point with no callers."""

    entry_point_reason: str = ""
    """Why the function counts as an entry point, when it does."""

    detail: str = ""
    """Why the analysis could not run, for `not_determinable`."""

    parse_failures: int = 0
    """How many repository files failed to parse, so the graph's holes are visible."""


def _decorator_text(node: ast.expr) -> str:
    """A decorator's dotted source text, best effort."""
    try:
        return ast.unparse(node)
    except Exception:  # pragma: no cover - unparse is total on parsed trees in practice
        return ""


def _entry_point_reason(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Why this function is reachable from outside, or an empty string."""
    for decorator in node.decorator_list:
        text = _decorator_text(decorator)
        lowered = text.lower()
        if any(fragment in lowered for fragment in ENTRY_POINT_DECORATORS):
            return f"decorated `@{text}`"
    if node.name in _ENTRY_POINT_NAMES and node.col_offset == 0:
        return f"named `{node.name}`, which is an entry point by convention"
    return ""


class _Collector(ast.NodeVisitor):
    """Walks one module, recording function definitions and the names each body calls."""

    def __init__(self, relative: str, path: Path) -> None:
        self.relative = relative
        self.path = path
        self.functions: list[FunctionSite] = []
        self.calls: dict[str, set[str]] = {}
        self._stack: list[str] = []

    def _enter(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        reason = _entry_point_reason(node)
        self.functions.append(
            FunctionSite(
                name=node.name,
                path=self.relative,
                start_line=node.lineno,
                end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                is_entry_point=bool(reason),
                entry_point_reason=reason,
            )
        )
        key = f"{self.relative}::{node.name}"
        self.calls.setdefault(key, set())
        self._stack.append(key)
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _called_name(node.func)
        if name and self._stack:
            self.calls[self._stack[-1]].add(name)
        elif name:
            # A call at module level: attribute it to the module, which is executed on import.
            self.calls.setdefault(f"{self.relative}::<module>", set()).add(name)
        self.generic_visit(node)


def _called_name(func: ast.expr) -> str | None:
    """The bare name a call targets: `f()` and `obj.f()` both yield `f`."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def build_call_graph(repo: Path) -> CallGraph:
    """Walk every Python file under `repo` and build the approximate graph."""
    root = repo.resolve()
    functions: list[FunctionSite] = []
    calls: dict[str, frozenset[str]] = {}
    failures: list[str] = []

    for path in sorted(root.rglob("*.py")):
        if any(part in {".venv", "site-packages", "__pycache__", ".git"} for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except OSError, SyntaxError, UnicodeDecodeError, ValueError:
            failures.append(str(path.relative_to(root)))
            continue
        collector = _Collector(str(path.relative_to(root)), path)
        collector.visit(tree)
        functions.extend(collector.functions)
        for key, names in collector.calls.items():
            calls[key] = frozenset(names)

    return CallGraph(
        functions=tuple(functions), calls=calls, parse_failures=tuple(sorted(failures))
    )


def reachability_of(
    graph: CallGraph, path: str, line: int, *, max_callers: int = 8
) -> ReachabilityFinding:
    """Whether the function containing `path:line` has a caller or is an entry point."""
    failures = len(graph.parse_failures)

    if not path.endswith(".py"):
        return ReachabilityFinding(
            verdict=Reachability.NOT_DETERMINABLE,
            detail="the cited file is not Python, and this analysis reads Python only",
            parse_failures=failures,
        )
    if path in graph.parse_failures:
        return ReachabilityFinding(
            verdict=Reachability.NOT_DETERMINABLE,
            detail="the cited file could not be parsed",
            parse_failures=failures,
        )

    site = graph.enclosing(path, line)
    if site is None:
        return ReachabilityFinding(
            verdict=Reachability.NOT_DETERMINABLE,
            detail=(
                "the cited line is not inside a function definition, so there is no call site to "
                "look for. Module-level code runs on import."
            ),
            parse_failures=failures,
        )

    if site.is_entry_point:
        return ReachabilityFinding(
            verdict=Reachability.REACHABLE_FROM,
            function=site.name,
            entry_point_reason=site.entry_point_reason,
            parse_failures=failures,
        )

    callers = graph.callers_of(site.name)
    if callers:
        return ReachabilityFinding(
            verdict=Reachability.REACHABLE_FROM,
            function=site.name,
            callers=callers[:max_callers],
            parse_failures=failures,
        )

    return ReachabilityFinding(
        verdict=Reachability.NO_CALLER_FOUND,
        function=site.name,
        parse_failures=failures,
    )
