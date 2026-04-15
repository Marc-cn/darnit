from typing import Any


def _parse_context_value(val: Any) -> Any:
    # helper for load_context
    from darnit.config.context_schema import ContextSource, ContextValue

    if val is None:
        return None
    if isinstance(val, dict) and "value" in val and "source" in val:
        try:
            return ContextValue.model_validate(val)
        except Exception:
            pass
    return ContextValue(
        source=ContextSource.FILE_REFERENCE,
        value=val,
        confidence=1.0,
    )
