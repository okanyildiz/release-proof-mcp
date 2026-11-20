from __future__ import annotations

import json
import math
from typing import Any

MAX_JSON_DEPTH = 64


class StrictJSONError(ValueError):
    pass


def strict_json_loads(raw: bytes) -> Any:
    if not isinstance(raw, bytes):
        raise StrictJSONError("Strict JSON input must be bytes.")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonfinite,
            parse_float=_finite_float,
        )
        _check_depth(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as error:
        raise StrictJSONError("Input is not strict, bounded, finite UTF-8 JSON.") from error


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> Any:
    raise StrictJSONError("Non-finite JSON number.")


def _finite_float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise StrictJSONError("Non-finite JSON number.")
    return result


def _check_depth(value: Any) -> None:
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise StrictJSONError("JSON nesting exceeds the depth limit.")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
