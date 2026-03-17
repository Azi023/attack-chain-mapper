"""Adapter registry — maps format names to adapter classes."""
from src.ingestion.adapters.generic import GenericAdapter
from src.ingestion.adapters.strike7 import Strike7Adapter

ADAPTER_REGISTRY: dict = {
    "generic": GenericAdapter,
    "strike7": Strike7Adapter,
}


def get_adapter(format_name: str):
    """Return adapter class for the given format name."""
    adapter_cls = ADAPTER_REGISTRY.get(format_name)
    if adapter_cls is None:
        raise ValueError(
            f"Unknown adapter format: {format_name!r}. Available: {list(ADAPTER_REGISTRY)}"
        )
    return adapter_cls
