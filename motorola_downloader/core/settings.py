"""Configuration management module for Motorola Firmware Downloader.

Handles loading, validation, and updating of configuration from config.ini file.
"""

import configparser
from pathlib import Path
from typing import Any, Optional

from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.validators import (
    validate_directory_path,
    validate_guid,
    validate_integer_range,
    validate_url,
)


class ConfigurationError(Exception):
    """Exception raised when configuration is invalid."""
    pass


class Settings:
    """Configuration manager for config.ini file.

    Loads, validates, and provides access to configuration settings.
    Supports reading different data types and updating configuration.
    """

    def __init__(self, config_file: str = "config.ini") -> None:
        """Initialize settings manager.

        Args:
            config_file: Path to configuration file

        Raises:
            ConfigurationError: If configuration file cannot be loaded
        """
        self.config_file = config_file
        self.logger = get_logger(__name__)
        self.config = configparser.ConfigParser()

        # Load configuration
        self.load_from_file()

        # Validate critical fields
        self.validate_config()

    def load_from_file(self) -> None:
        """Load configuration from config.ini file.

        Raises:
            ConfigurationError: If file doesn't exist or cannot be read
        """
        config_path = Path(self.config_file)

        if not config_path.exists():
            self.logger.error(f"Configuration file not found: {self.config_file}")
            raise ConfigurationError(
                f"Configuration file not found: {self.config_file}. "
                "Please create config.ini from config.ini.template"
            )

        try:
            self.config.read(config_path, encoding="utf-8")
            self.logger.info(f"Configuration loaded from {self.config_file}")
        except Exception as e:
            self.logger.error(f"Failed to read configuration file: {e}")
            raise ConfigurationError(f"Failed to read configuration file: {e}")

    def validate_config(self) -> None:
        """Validate that all required configuration fields are present and valid.

        Raises:
            ConfigurationError: If required fields are missing or invalid
        """
        # Check required sections
        required_sections = [
            "motorola_server",
            "download",
            "search",
            "logging",
            "authentication"
        ]

        for section in required_sections:
            if not self.config.has_section(section):
                raise ConfigurationError(
                    f"Required configuration section missing: [{section}]"
                )

        # Validate motorola_server section
        base_url = self.get("motorola_server", "base_url")
        if not base_url:
            raise ConfigurationError("motorola_server.base_url is required")
        if not validate_url(base_url):
            raise ConfigurationError(f"Invalid base_url: {base_url}")

        guid = self.get("motorola_server", "guid")
        if not guid:
            raise ConfigurationError("motorola_server.guid is required")
        if not validate_guid(guid):
            raise ConfigurationError(f"Invalid GUID format: {guid}")

        # Validate download section
        output_dir = self.get("download", "output_directory")
        if not output_dir:
            raise ConfigurationError("download.output_directory is required")

        max_concurrent = self.get_int("download", "max_concurrent_downloads")
        if max_concurrent is None or not (1 <= max_concurrent <= 5):
            raise ConfigurationError(
                "download.max_concurrent_downloads must be between 1 and 5"
            )

        self.logger.info("Configuration validation passed")

    def get(self, section: str, key: str, fallback: Optional[str] = None) -> Optional[str]:
        """Get string value from configuration.

        Args:
            section: Configuration section name
            key: Configuration key name
            fallback: Default value if key not found

        Returns:
            Configuration value or fallback
        """
        try:
            value = self.config.get(section, key, fallback=fallback)
            return value if value else fallback
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_int(self, section: str, key: str, fallback: Optional[int] = None) -> Optional[int]:
        """Get integer value from configuration.

        Args:
            section: Configuration section name
            key: Configuration key name
            fallback: Default value if key not found

        Returns:
            Configuration value as integer or fallback
        """
        try:
            return self.config.getint(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def get_float(self, section: str, key: str, fallback: Optional[float] = None) -> Optional[float]:
        """Get float value from configuration.

        Args:
            section: Configuration section name
            key: Configuration key name
            fallback: Default value if key not found

        Returns:
            Configuration value as float or fallback
        """
        try:
            return self.config.getfloat(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def get_bool(self, section: str, key: str, fallback: Optional[bool] = None) -> Optional[bool]:
        """Get boolean value from configuration.

        Args:
            section: Configuration section name
            key: Configuration key name
            fallback: Default value if key not found

        Returns:
            Configuration value as boolean or fallback
        """
        try:
            return self.config.getboolean(section, key, fallback=fallback)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return fallback

    def update(self, section: str, key: str, value: Any) -> None:
        """Update configuration value and save to file.

        Args:
            section: Configuration section name
            key: Configuration key name
            value: New value to set

        Raises:
            ConfigurationError: If update fails
        """
        try:
            # Ensure section exists
            if not self.config.has_section(section):
                self.config.add_section(section)

            # Update value
            self.config.set(section, key, str(value))

            # Save to file
            config_path = Path(self.config_file)
            with open(config_path, "w", encoding="utf-8") as f:
                self.config.write(f)

            self.logger.info(f"Updated configuration: [{section}] {key} = {value}")

        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            raise ConfigurationError(f"Failed to update configuration: {e}")

    def get_all_sections(self) -> list[str]:
        """Get list of all configuration sections.

        Returns:
            List of section names
        """
        return self.config.sections()

    def get_section_keys(self, section: str) -> list[str]:
        """Get all keys in a configuration section.

        Args:
            section: Configuration section name

        Returns:
            List of key names in section
        """
        if not self.config.has_section(section):
            return []
        return list(self.config[section].keys())

    def has_section(self, section: str) -> bool:
        """Check if configuration section exists.

        Args:
            section: Configuration section name

        Returns:
            True if section exists, False otherwise
        """
        return self.config.has_section(section)

    def has_option(self, section: str, key: str) -> bool:
        """Check if configuration option exists.

        Args:
            section: Configuration section name
            key: Configuration key name

        Returns:
            True if option exists, False otherwise
        """
        return self.config.has_option(section, key)
