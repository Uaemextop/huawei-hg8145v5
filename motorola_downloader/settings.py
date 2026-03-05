"""Configuration management for Motorola Firmware Downloader.

Loads, validates, and persists application configuration from a config.ini file.
Uses Python's configparser with custom validation and default values.

Environment variable overrides (take precedence over config.ini):
  MOTOROLA_GUID       → [motorola_server] guid
  MOTOROLA_JWT        → [motorola_server] jwt_token
  MOTOROLA_DEBUG      → [logging] debug   (true/false)
"""

import configparser
import os
from pathlib import Path
from typing import Any, Dict, Optional

from motorola_downloader.exceptions import ConfigurationError
from motorola_downloader.utils.logger import get_logger

_logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_PATH = "config.ini"

REQUIRED_SECTIONS = [
    "motorola_server",
    "download",
    "search",
    "logging",
    "authentication",
]

REQUIRED_FIELDS: Dict[str, list[str]] = {
    "motorola_server": ["guid", "jwt_token"],
    "download": ["output_directory"],
}

# Environment variable → (section, key) mapping.
# These take precedence over config.ini values so that credentials
# never need to be written to the file.
_ENV_OVERRIDES: Dict[str, tuple[str, str]] = {
    "MOTOROLA_GUID":  ("motorola_server", "guid"),
    "MOTOROLA_JWT":   ("motorola_server", "jwt_token"),
    "MOTOROLA_DEBUG": ("logging", "debug"),
}

DEFAULT_VALUES: Dict[str, Dict[str, str]] = {
    "motorola_server": {
        "guid": "00000000-0000-0000-0000-000000000000",
        "jwt_token": "",
        "refresh_token": "",
        "client_version": "7.5.4.2",
        "language": "en-US",
        "windows_info": "Microsoft Windows 11 Pro, x64-based PC",
    },
    "download": {
        "output_directory": "downloads",
        "max_concurrent_downloads": "3",
        "chunk_size": "8192",
        "timeout": "60",
        "max_retries": "3",
    },
    "search": {
        "default_limit": "50",
        "default_region": "US",
        "include_beta": "false",
        "cache_enabled": "true",
        "cache_ttl_seconds": "300",
    },
    "logging": {
        "level": "INFO",
        "log_file": "logs/motorola_downloader.log",
        "max_file_size_mb": "5",
        "backup_count": "5",
        "debug": "false",
    },
    "authentication": {
        "auto_refresh": "true",
        "expiration_threshold_seconds": "300",
        "max_auth_retries": "3",
    },
}


class Settings:
    """Application configuration manager.

    Loads configuration from a config.ini file, validates required fields,
    provides typed getters, and persists changes back to disk.

    Args:
        config_path: Path to the config.ini file.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH) -> None:
        """Initialize the Settings manager.

        Args:
            config_path: Path to the configuration file.
        """
        self._config_path = config_path
        self._config = configparser.ConfigParser()
        self.logger = get_logger(__name__)

    def load_from_file(self, create_if_missing: bool = True) -> bool:
        """Load configuration from the config.ini file.

        If the file does not exist and create_if_missing is True,
        a default configuration file will be created.

        Args:
            create_if_missing: Whether to create a default config file if missing.

        Returns:
            True if configuration was loaded successfully.

        Raises:
            ConfigurationError: If the file cannot be read or parsed.
        """
        config_file = Path(self._config_path)

        if not config_file.exists():
            if create_if_missing:
                self.logger.info(
                    "Config file not found at '%s', creating with defaults",
                    self._config_path,
                )
                self._create_default_config()
                return True
            raise ConfigurationError(
                f"Configuration file not found: {self._config_path}"
            )

        try:
            files_read = self._config.read(self._config_path, encoding="utf-8")
            if not files_read:
                raise ConfigurationError(
                    f"Failed to read configuration file: {self._config_path}"
                )
            self.logger.info("Configuration loaded from '%s'", self._config_path)
            return True
        except configparser.Error as exc:
            self.logger.error("Failed to parse config file: %s", exc)
            raise ConfigurationError(f"Config parse error: {exc}") from exc

    def _create_default_config(self) -> None:
        """Create a default configuration file with all sections and defaults.

        Raises:
            ConfigurationError: If the file cannot be written.
        """
        for section, values in DEFAULT_VALUES.items():
            if not self._config.has_section(section):
                self._config.add_section(section)
            for key, value in values.items():
                self._config.set(section, key, value)

        try:
            config_path = Path(self._config_path)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_path, "w", encoding="utf-8") as config_file:
                self._config.write(config_file)
            self.logger.info("Default configuration written to '%s'", self._config_path)
        except IOError as exc:
            self.logger.error("Failed to write default config: %s", exc)
            raise ConfigurationError(f"Cannot write config: {exc}") from exc

    def validate_config(self) -> bool:
        """Validate that all required sections and fields are present.

        Returns:
            True if configuration is valid.

        Raises:
            ConfigurationError: If required sections or fields are missing.
        """
        missing_sections = []
        for section in REQUIRED_SECTIONS:
            if not self._config.has_section(section):
                missing_sections.append(section)

        if missing_sections:
            raise ConfigurationError(
                f"Missing required sections: {', '.join(missing_sections)}"
            )

        missing_fields = []
        for section, fields in REQUIRED_FIELDS.items():
            for field in fields:
                value = self._config.get(section, field, fallback="")
                if not value.strip():
                    missing_fields.append(f"[{section}] {field}")

        if missing_fields:
            self.logger.warning(
                "Missing required configuration fields: %s",
                ", ".join(missing_fields),
            )

        self.logger.info("Configuration validation completed")
        return True

    def _env_override(self, section: str, key: str) -> Optional[str]:
        """Check if an environment variable overrides a config value.

        Args:
            section: The configuration section name.
            key: The configuration key.

        Returns:
            Environment variable value, or None if not set.
        """
        for env_var, (sec, k) in _ENV_OVERRIDES.items():
            if sec == section and k == key:
                value = os.environ.get(env_var, "")
                if value:
                    return value
        return None

    def get(self, section: str, key: str, fallback: str = "") -> str:
        """Get a string configuration value.

        Environment variables (MOTOROLA_GUID, MOTOROLA_JWT, MOTOROLA_DEBUG)
        take precedence over config.ini values when set.

        Args:
            section: The configuration section name.
            key: The configuration key.
            fallback: Default value if key is not found.

        Returns:
            The configuration value as a string.
        """
        env_val = self._env_override(section, key)
        if env_val is not None:
            return env_val
        return self._config.get(section, key, fallback=fallback)

    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """Get an integer configuration value.

        Args:
            section: The configuration section name.
            key: The configuration key.
            fallback: Default value if key is not found or invalid.

        Returns:
            The configuration value as an integer.
        """
        env_val = self._env_override(section, key)
        if env_val is not None:
            try:
                return int(env_val)
            except ValueError:
                pass
        try:
            return self._config.getint(section, key, fallback=fallback)
        except (ValueError, configparser.Error):
            self.logger.warning(
                "Invalid integer for [%s] %s, using fallback %d",
                section, key, fallback,
            )
            return fallback

    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """Get a boolean configuration value.

        Args:
            section: The configuration section name.
            key: The configuration key.
            fallback: Default value if key is not found or invalid.

        Returns:
            The configuration value as a boolean.
        """
        env_val = self._env_override(section, key)
        if env_val is not None:
            return env_val.lower() in ("true", "1", "yes", "on")
        try:
            return self._config.getboolean(section, key, fallback=fallback)
        except (ValueError, configparser.Error):
            self.logger.warning(
                "Invalid boolean for [%s] %s, using fallback %s",
                section, key, fallback,
            )
            return fallback

    def is_env_override(self, section: str, key: str) -> bool:
        """Check if a configuration value is currently overridden by an environment variable.

        Args:
            section: The configuration section name.
            key: The configuration key.

        Returns:
            True if an environment variable override is active for this key.
        """
        return self._env_override(section, key) is not None

    def update(self, section: str, key: str, value: str) -> None:
        """Update a configuration value and persist to disk.

        Skips writing to disk when the key is overridden by an environment
        variable to prevent secrets from being persisted to config.ini.

        Args:
            section: The configuration section name.
            key: The configuration key.
            value: The new value to set.

        Raises:
            ConfigurationError: If the section does not exist or write fails.
        """
        if self.is_env_override(section, key):
            self.logger.info(
                "Skipping disk write for [%s] %s (env var override active)",
                section, key,
            )
            return

        if not self._config.has_section(section):
            self._config.add_section(section)

        self._config.set(section, key, value)
        self.logger.info("Configuration updated: [%s] %s", section, key)

        try:
            with open(self._config_path, "w", encoding="utf-8") as config_file:
                self._config.write(config_file)
        except IOError as exc:
            self.logger.error("Failed to persist config change: %s", exc)
            raise ConfigurationError(f"Config write error: {exc}") from exc

    def get_all_sections(self) -> list[str]:
        """Get all configuration section names.

        Returns:
            List of section names.
        """
        return self._config.sections()

    def get_section_items(self, section: str) -> Dict[str, str]:
        """Get all key-value pairs in a configuration section.

        Args:
            section: The configuration section name.

        Returns:
            Dictionary of key-value pairs.
        """
        if not self._config.has_section(section):
            return {}
        return dict(self._config.items(section))
