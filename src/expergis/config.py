"""Configuration loader for Expergis."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("expergis.config")

CONFIG_FILE = Path(__file__).parent.parent.parent / "expergis.json"

_DEFAULTS: dict[str, Any] = {
    "velle_endpoint": "http://127.0.0.1:7839/velle_prompt",
    "rate_limit": {
        "min_interval_ms": 5000,
        "max_events_per_minute": 6,
        "burst_size": 2,
    },
    "dedup_window_ms": 10000,
    "watchers": [],
}


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load configuration from expergis.json, falling back to defaults."""
    config_path = path or CONFIG_FILE
    config = json.loads(json.dumps(_DEFAULTS))  # deep copy

    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            # Merge top-level keys
            for key, val in user_config.items():
                if key == "rate_limit" and isinstance(val, dict):
                    config["rate_limit"].update(val)
                else:
                    config[key] = val
            logger.info(f"Loaded config from {config_path}")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")

    return config
