"""Tests for expergis.config — configuration loading."""

import json
import tempfile
from pathlib import Path

from expergis.config import load_config


class TestLoadConfig:
    def test_load_defaults(self, tmp_path):
        """No config file → all defaults applied."""
        config = load_config(path=tmp_path / "nonexistent.json")
        assert config["velle_endpoint"] == "http://127.0.0.1:7839/velle_prompt"
        assert config["dedup_window_ms"] == 10000
        assert config["rate_limit"]["burst_size"] == 2
        assert config["watchers"] == []

    def test_load_custom_config(self, tmp_path):
        """Custom config file overrides defaults."""
        config_file = tmp_path / "expergis.json"
        config_file.write_text(json.dumps({
            "velle_endpoint": "http://localhost:9999/prompt",
            "dedup_window_ms": 20000,
        }))
        config = load_config(path=config_file)
        assert config["velle_endpoint"] == "http://localhost:9999/prompt"
        assert config["dedup_window_ms"] == 20000
        # Defaults for unset keys preserved
        assert config["rate_limit"]["burst_size"] == 2

    def test_rate_limit_merge(self, tmp_path):
        """Partial rate_limit in config merges with defaults."""
        config_file = tmp_path / "expergis.json"
        config_file.write_text(json.dumps({
            "rate_limit": {"burst_size": 5},
        }))
        config = load_config(path=config_file)
        assert config["rate_limit"]["burst_size"] == 5
        # Other rate_limit defaults preserved
        assert config["rate_limit"]["min_interval_ms"] == 5000
        assert config["rate_limit"]["max_events_per_minute"] == 6
