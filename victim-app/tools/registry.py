import math
from collections.abc import Callable
from typing import Any, Literal, TypedDict

ToolFunction = Callable[..., str]
Description = str | Callable[[], str]


class ToolEntry(TypedDict):
    fn: ToolFunction
    kind: Literal["source", "sink"]
    description: Description
    schema: dict[str, Any]
    trust: str
    sensitivity: str
    channel: str | None


REGISTRY: dict[str, ToolEntry] = {}


def validate_tool_arguments(arguments: object, schema: dict[str, Any]) -> str | None:
    if not isinstance(arguments, dict):
        return "arguments must be an object"

    properties = schema.get("properties", {})
    required = schema.get("required", [])
    missing = [key for key in required if key not in arguments]
    unexpected = [key for key in arguments if key not in properties]
    errors = []
    if missing:
        errors.append(f"missing required arguments: {', '.join(missing)}")
    if unexpected:
        errors.append(f"unexpected arguments: {', '.join(unexpected)}")
    if errors:
        return "; ".join(errors)

    for key, value in arguments.items():
        expected = properties[key].get("type")
        if expected == "string":
            valid = isinstance(value, str)
        elif expected == "number":
            valid = (
                not isinstance(value, bool)
                and (
                    isinstance(value, int)
                    or (isinstance(value, float) and math.isfinite(value))
                )
            )
        elif expected == "integer":
            valid = isinstance(value, int) and not isinstance(value, bool)
        elif expected == "boolean":
            valid = isinstance(value, bool)
        elif expected == "object":
            valid = isinstance(value, dict)
        elif expected == "array":
            valid = isinstance(value, list)
        elif expected == "null":
            valid = value is None
        else:
            return f"unsupported schema type for argument {key}"
        if not valid:
            return f"argument {key} must be {expected}"

    return None


def tool(
    name: str,
    kind: Literal["source", "sink"],
    description: Description,
    schema: dict[str, Any],
    trust: str = "internal",
    sensitivity: str = "normal",
    channel: str | None = None,
) -> Callable[[ToolFunction], ToolFunction]:
    def wrap(fn: ToolFunction) -> ToolFunction:
        REGISTRY[name] = {
            "fn": fn,
            "kind": kind,
            "description": description,
            "schema": schema,
            "trust": trust,
            "sensitivity": sensitivity,
            "channel": channel,
        }
        return fn

    return wrap
