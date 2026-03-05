"""
Configuration loader and validator for the Motorola Firmware Downloader.
"""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Any, Optional

from motorola_firmware.logger import get_logger
from motorola_firmware.validators import validate_guid, validate_url

_REQUIRED_FIELDS = {
    "motorola_server": ["base_url", "guid", "jwt_token"],
    "download": ["output_directory", "max_concurrent_downloads"],
    "logging": ["level", "log_file"],
    "authentication": ["auto_refresh", "expiry_threshold_seconds"],
}


class InvalidConfigurationError(ValueError):
    """Raised when the config file is missing required values."""


class Settings:
    """Load, validate and update ``config.ini`` values."""

    def __init__(self, path: str | Path = "config.ini") -> None:
        """Create a new settings instance.

        Args:
            path: Path to the INI configuration file.
        """
        self._path = Path(path)
        self._config = configparser.ConfigParser()
        self.logger = get_logger(__name__)

    def load_from_file(self) -> None:
        """Load configuration from disk and validate required fields.

        Raises:
            FileNotFoundError: If the INI file does not exist.
            InvalidConfigurationError: If required fields are missing or invalid.
        """
        if not self._path.exists():
            raise FileNotFoundError(f"Config file not found at {self._path}")

        self._config.read(self._path)
        self._apply_defaults()
        self.validate_config()
        self.logger.info("Configuration loaded from %s", self._path)

    def validate_config(self) -> None:
        """Validate presence and format of required values."""
        missing: list[str] = []
        for section, keys in _REQUIRED_FIELDS.items():
            if section not in self._config:
                missing.append(section)
                continue
            for key in keys:
                if self._config.get(section, key, fallback="").strip() == "":
                    missing.append(f"{section}.{key}")
        if missing:
            raise InvalidConfigurationError(
                f"Missing required configuration values: {', '.join(missing)}",
            )

        base_url = self.get("motorola_server", "base_url")
        if not validate_url(base_url, allow_http=False):
            raise InvalidConfigurationError("base_url must be a valid HTTPS URL")

        guid = self.get("motorola_server", "guid")
        if not validate_guid(guid):
            raise InvalidConfigurationError("guid must follow Motorola GUID format")

        concurrency = self.get_int("download", "max_concurrent_downloads", 3)
        if concurrency < 1 or concurrency > 5:
            raise InvalidConfigurationError(
                "max_concurrent_downloads must be between 1 and 5",
            )

        output_dir = Path(self.get("download", "output_directory"))
        output_dir.mkdir(parents=True, exist_ok=True)

    def get(self, section: str, key: str, default: Optional[str] = None) -> str:
        """Return a configuration value."""
        return self._config.get(section, key, fallback=default or "").strip()

    def get_int(self, section: str, key: str, default: int = 0) -> int:
        """Return a configuration value as int."""
        try:
            return self._config.getint(section, key, fallback=default)
        except ValueError:
            return default

    def get_bool(self, section: str, key: str, default: bool = False) -> bool:
        """Return a configuration value as bool."""
        return self._config.getboolean(section, key, fallback=default)

    def update(self, section: str, key: str, value: Any) -> None:
        """Persist a configuration value to disk."""
        if section not in self._config:
            self._config.add_section(section)
        self._config.set(section, key, str(value))
        with self._path.open("w", encoding="utf-8") as config_file:
            self._config.write(config_file)
        self.logger.info("Updated configuration value %s.%s", section, key)

    def _apply_defaults(self) -> None:
        """Apply safe defaults for optional fields."""
        self._config.setdefault("search", {})
        search_section = self._config["search"]
        search_section.setdefault("default_limit", "25")
        search_section.setdefault("region", "us")
        search_section.setdefault("cache_ttl_seconds", "300")

        auth_section = self._config.setdefault("authentication", {})
        auth_section.setdefault("expiry_threshold_seconds", "300")
        auth_section.setdefault("auto_refresh", "true")

        download_section = self._config.setdefault("download", {})
        download_section.setdefault("max_concurrent_downloads", "3")
        download_section.setdefault("timeout_seconds", "30")

        logging_section = self._config.setdefault("logging", {})
        logging_section.setdefault("level", "INFO")
        logging_section.setdefault("log_file", "logs/motorola_downloader.log")
        logging_section.setdefault("max_bytes", "1048576")
        logging_section.setdefault("backup_count", "5")
