"""Policy registry — maps policy_version strings to evaluator functions."""

from collections.abc import Callable

from . import chml, epss_v5
from .definitions import POLICY_VERSION

_POLICIES: dict[str, Callable] = {
    "chml-v0.2": chml.evaluate,
    "epss-v5": epss_v5.evaluate,
}

DEFAULT_POLICY: str = POLICY_VERSION  # "chml-v0.2"
AVAILABLE_POLICIES: list[str] = list(_POLICIES)


def get_evaluator(policy_version: str | None) -> Callable:
    """Return the evaluator function for *policy_version*.

    Raises ValueError with a helpful message if the version is unknown.
    """
    key = policy_version or DEFAULT_POLICY
    if key not in _POLICIES:
        available = ", ".join(sorted(_POLICIES))
        raise ValueError(f"Unknown policy: {key!r}. Available: {available}")
    return _POLICIES[key]
