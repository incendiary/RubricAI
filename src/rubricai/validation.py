"""Turn Pydantic validation errors into messages an MCP client can act on.

Raw Pydantic errors say "extra inputs are not permitted" without saying what *is*
permitted, which sends a client into trial and error. These messages name the
fields that are allowed at the point of failure. Input values are never echoed.
"""

from types import UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel, ValidationError

# Keys that intel_lookup puts in ``derived_finding_context`` for the assistant's
# benefit but that are not Finding fields.
_CONTEXT_ONLY_KEYS = frozenset({"cvss_av", "confidence", "description"})


def _models_in(annotation: Any) -> list[type[BaseModel]]:
    """BaseModel subclasses inside an annotation (unwraps Optional, list, ...)."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return [annotation]
    if get_origin(annotation) in (Union, UnionType, list, tuple, dict):
        return [m for arg in get_args(annotation) for m in _models_in(arg)]
    return []


def _model_at(model: type[BaseModel], path: tuple) -> type[BaseModel] | None:
    """The model that owns ``path`` (list indexes are skipped); None if unknown."""
    for part in path:
        if isinstance(part, int):
            continue
        field = model.model_fields.get(part)
        models = _models_in(field.annotation) if field else []
        if len(models) != 1:
            return None
        model = models[0]
    return model


def _explain(model: type[BaseModel], label: str, exc: ValidationError) -> str:
    errors = exc.errors(include_url=False, include_input=False)
    lines = [f"Invalid {label}: {len(errors)} problem(s)."]
    for err in errors:
        loc = tuple(err["loc"])
        where = ".".join([label, *map(str, loc)])
        if err["type"] == "extra_forbidden":
            owner = _model_at(model, loc[:-1])
            allowed = ", ".join(owner.model_fields) if owner else "see tool description"
            line = f"- {where}: unknown field. Allowed here: {allowed}"
            if len(loc) == 1 and loc[0] in _CONTEXT_ONLY_KEYS:
                line += (
                    ". This key comes from intel_lookup's derived_finding_context; "
                    "copy only attacker_utility, entry_point and preconditions"
                )
        elif err["type"] == "missing":
            line = f"- {where}: required field is missing"
        else:
            line = f"- {where}: {err['msg']}"
            expected = _model_at(model, loc)
            if expected is not None and expected is not model:
                line += f" (an object with fields: {', '.join(expected.model_fields)})"
        lines.append(line)
    return "\n".join(lines)


def validate_model(model: type[BaseModel], data: Any, label: str) -> Any:
    """``model.model_validate(data)`` raising a ValueError that lists allowed fields."""
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise ValueError(_explain(model, label, exc)) from None
