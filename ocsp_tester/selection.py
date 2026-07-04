"""Fine-grained test selection for the engine.

The web executor (or any embedding application) calls :func:`set_active`
with the list of test names that should run before invoking a category's
``run_*_tests`` function, and clears it afterwards. Engine modules guard
each individual test block with :func:`should_run`. When no selection is
active (the default, and always the case for the CLI) every test runs.

Test names with a dynamic suffix (e.g. ``"Fetch and parse CRL: <url>"``)
match a selected base name by prefix.
"""

from __future__ import annotations

from typing import Iterable, Optional, Set

_active: Optional[Set[str]] = None


def set_active(names: Optional[Iterable[str]]) -> None:
    """Restrict which tests run. ``None`` removes any restriction."""
    global _active
    _active = None if names is None else {str(n) for n in names}


def is_active() -> bool:
    return _active is not None


def matches(name: str, selected: Set[str]) -> bool:
    if name in selected:
        return True
    return any(name.startswith(base) for base in selected)


def should_run(name: str) -> bool:
    if _active is None:
        return True
    return matches(name, _active)


def any_selected(*names: str) -> bool:
    """True when at least one of the given tests would run.

    Used to decide whether shared setup work (e.g. a network fetch feeding
    several tests) is still needed.
    """
    return any(should_run(n) for n in names)
