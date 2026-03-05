"""
Configuration management for the Motorola Firmware Downloader.

Loads, validates, and persists configuration from ``config.ini`` files.
Uses ``configparser`` from stdlib.  Provides typed accessors (str, int,
bool) and automatic write-back on updates.
"""

import configparser
import os
from typing import Any, Dict, Optional

from motorola_firmware.config import (
    DEFAULT_CONFIG_FILE,
    DEFAULT_CONCURRENT_DOWNLOADS,
    DEFAULT_LOG_DIR,
    DEFAULT_LOG_FILE,
    DEFAULT_OUTPUT_DIR,
    DEFAULT_SEARCH_LIMIT,
    MAX_CONCURRENT_DOWNLOADS,
    MIN_CONCURRENT_DOWNLOADS,
    MOTOROLA_BASE_URL,
    REQUEST_TIMEOUT,
)
from motorola_firmware.exceptions import ConfigurationError
from motorola_firmware.utils.logger import log

# ── Default configuration values ───────────────────────────────────
_DEFAULTS: Dict[str, Dict[str, str]] = {
    "motorola_server": {
        "base_url": MOTOROLA_BASE_URL,
        "guid": "",
        "jwt_token": "",
        "refresh_token": "",
    },
    "download": {
        "output_directory": DEFAULT_OUTPUT_DIR,
        "max_concurrent_downloads": str(DEFAULT_CONCURRENT_DOWNLOADS),
        "timeout": str(REQUEST_TIMEOUT),
        "chunk_size": "8192",
        "max_retries": "3",
    },
    "search": {
        "default_limit": str(DEFAULT_SEARCH_LIMIT),
        "default_region": "global",
        "include_beta": "false",
    },
    "logging": {
        "level": "INFO",
        "log_file": DEFAULT_LOG_FILE,
        "log_dir": DEFAULT_LOG_DIR,
        "max_size_mb": "5",
    },
    "authentication": {
        "auto_refresh": "true",
        "expiry_threshold_seconds": "300",
    },
}

# Required fields that must have non-empty values for the app to work
_REQUIRED_FIELDS: Dict[str, list] = {
    "motorola_server": ["base_url"],
    "download": ["output_directory"],
}


class Settings:
    """Configuration manager that loads and validates ``config.ini``.

    Provides typed accessors for all configuration values and persists
    changes back to the INI file when :meth:`update` is called.

    Args:
        config_path: Path to the configuration file.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_FILE) -> None:
        """Initialize settings with defaults and optional file loading.

        Args:
            config_path: Path to the ``config.ini`` file.
        """
        self._config_path = config_path
        self._config = configparser.ConfigParser()
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Populate the config parser with default values."""
        for section, values in _DEFAULTS.items():
            if not self._config.has_section(section):
                self._config.add_section(section)
            for key, value in values.items():
                self._config.set(section, key, value)

    def load_from_file(self, config_path: Optional[str] = None) -> bool:
        """Load configuration from an INI file.

        If the file does not exist, defaults are used and a new
        config file is created.

        Args:
            config_path: Optional override for the config file path.

        Returns:
            True if the file was loaded, False if defaults were used.

        Raises:
            ConfigurationError: If the file exists but cannot be parsed.
        """
        path = config_path or self._config_path
        if not os.path.isfile(path):
            log.warning("[CONFIG] Config file not found at '%s', using defaults", path)
            self._save_to_file(path)
            return False

        try:
            self._config.read(path, encoding="utf-8")
            log.info("[CONFIG] Configuration loaded from '%s'", path)
            return True
        except configparser.Error as error:
            log.error("[CONFIG] Failed to parse config file: %s", error)
            raise ConfigurationError(
                f"Invalid config file '{path}': {error}"
            ) from error

    def validate_config(self) -> bool:
        """Validate that all required fields are present and valid.

        Returns:
            True if configuration is valid.

        Raises:
            ConfigurationError: If required fields are missing or invalid.
        """
        missing_fields: list = []
        for section, keys in _REQUIRED_FIELDS.items():
            if not self._config.has_section(section):
                missing_fields.append(f"[{section}]")
                continue
            for key in keys:
                value = self._config.get(section, key, fallback="").strip()
                if not value:
                    missing_fields.append(f"[{section}].{key}")

        if missing_fields:
            message = "Missing required config: " + ", ".join(missing_fields)
            log.error("[CONFIG] %s", message)
            raise ConfigurationError(message)

        concurrent = self.get_int("download", "max_concurrent_downloads",
                                  DEFAULT_CONCURRENT_DOWNLOADS)
        if concurrent < MIN_CONCURRENT_DOWNLOADS or concurrent > MAX_CONCURRENT_DOWNLOADS:
            raise ConfigurationError(
                f"max_concurrent_downloads must be between "
                f"{MIN_CONCURRENT_DOWNLOADS} and {MAX_CONCURRENT_DOWNLOADS}"
            )

        log.info("[CONFIG] Configuration validated successfully")
        return True

    def get(self, section: str, key: str, fallback: Optional[str] = None) -> str:
        """Get a configuration value as a string.

        Args:
            section: The INI section name.
            key: The configuration key.
            fallback: Default value if key is not found.

        Returns:
            The configuration value as a string.
        """
        default = fallback if fallback is not None else ""
        return self._config.get(section, key, fallback=default)

    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """Get a configuration value as an integer.

        Args:
            section: The INI section name.
            key: The configuration key.
            fallback: Default integer if key is not found or invalid.

        Returns:
            The configuration value as an integer.
        """
        try:
            return self._config.getint(section, key, fallback=fallback)
        except ValueError:
            log.warning("[CONFIG] Invalid integer for [%s].%s, using %d",
                        section, key, fallback)
            return fallback

    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """Get a configuration value as a boolean.

        Args:
            section: The INI section name.
            key: The configuration key.
            fallback: Default boolean if key is not found.

        Returns:
            The configuration value as a boolean.
        """
        try:
            return self._config.getboolean(section, key, fallback=fallback)
        except ValueError:
            log.warning("[CONFIG] Invalid boolean for [%s].%s, using %s",
                        section, key, fallback)
            return fallback

    def update(self, section: str, key: str, value: str) -> None:
        """Update a configuration value and persist to file.

        Args:
            section: The INI section name.
            key: The configuration key.
            value: The new value to set.
        """
        if not self._config.has_section(section):
            self._config.add_section(section)
        self._config.set(section, key, value)
        self._save_to_file(self._config_path)
        log.debug("[CONFIG] Updated [%s].%s", section, key)

    def _save_to_file(self, path: str) -> None:
        """Write the current configuration to a file.

        Args:
            path: The file path to write to.
        """
        try:
            with open(path, "w", encoding="utf-8") as config_file:
                self._config.write(config_file)
        except OSError as error:
            log.error("[CONFIG] Failed to save config to '%s': %s", path, error)

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Get all configuration sections and values.

        Returns:
            Dictionary mapping section names to key-value dictionaries.
        """
        result: Dict[str, Dict[str, Any]] = {}
        for section in self._config.sections():
            result[section] = dict(self._config.items(section))
        return result
