"""The audit log: one JSON line per event on the `lightdash_mcp.audit` logger. Never give it a token or a secret."""

import json
import logging
from typing import Any

logger = logging.getLogger("lightdash_mcp.audit")

MAX_VALUE = 200  # characters of one value, once serialized
MAX_ITEMS = 30  # arguments of one tool call


def record(event: str, level: int = logging.INFO, **fields: Any) -> None:
    # Serialized whole, so a client-controlled value, such as a tool name with a newline, can't forge a line.
    logger.log(level, json.dumps({"event": event, **fields}, default=str))


def clip(value: Any) -> Any:
    """The value, or the start of its JSON when that is longer than MAX_VALUE."""
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return value if len(text) <= MAX_VALUE else text[:MAX_VALUE] + "..."


def clip_arguments(arguments: Any) -> Any:
    if not isinstance(arguments, dict):
        return clip(arguments)
    return {clip(str(key)): clip(value) for key, value in list(arguments.items())[:MAX_ITEMS]}
