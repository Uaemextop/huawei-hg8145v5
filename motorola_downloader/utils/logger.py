"""Centralized logging module for Motorola Firmware Downloader.

Provides a singleton logger with file and console handlers, rotating logs,
and configurable log levels.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


# Singleton logger instances
_loggers: dict[str, logging.Logger] = {}

# Default configuration
DEFAULT_LOG_DIR = "logs"
DEFAULT_LOG_FILE = "motorola_downloader.log"
DEFAULT_LOG_LEVEL = logging.INFO
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BACKUP_COUNT = 5


class Logger:
    """Centralized logger with file and console handlers.

    Implements singleton pattern to ensure consistent logging across modules.
    Automatically creates log directory and configures rotating file handler.
    """

    def __init__(
        self,
        name: str,
        log_dir: str = DEFAULT_LOG_DIR,
        log_file: str = DEFAULT_LOG_FILE,
        level: int = DEFAULT_LOG_LEVEL,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> None:
        """Initialize logger with specified configuration.

        Args:
            name: Logger name (usually __name__ from calling module)
            log_dir: Directory to store log files
            log_file: Name of the log file
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            max_bytes: Maximum size of log file before rotation
            backup_count: Number of backup log files to keep
        """
        self.name = name
        self.log_dir = log_dir
        self.log_file = log_file
        self.level = level
        self.max_bytes = max_bytes
        self.backup_count = backup_count

        # Get or create logger instance
        if name in _loggers:
            self.logger = _loggers[name]
        else:
            self.logger = self._create_logger()
            _loggers[name] = self.logger

    def _create_logger(self) -> logging.Logger:
        """Create and configure a new logger instance.

        Returns:
            Configured logging.Logger instance
        """
        # Create logger
        logger = logging.getLogger(self.name)
        logger.setLevel(self.level)

        # Avoid duplicate handlers
        if logger.handlers:
            return logger

        # Create log directory if it doesn't exist
        log_path = Path(self.log_dir)
        log_path.mkdir(parents=True, exist_ok=True)

        # Create formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Create and configure file handler (rotating)
        log_file_path = log_path / self.log_file
        file_handler = RotatingFileHandler(
            filename=log_file_path,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8"
        )
        file_handler.setLevel(self.level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Create and configure console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def debug(self, message: str) -> None:
        """Log a debug message.

        Args:
            message: Message to log
        """
        self.logger.debug(message)

    def info(self, message: str) -> None:
        """Log an info message.

        Args:
            message: Message to log
        """
        self.logger.info(message)

    def warning(self, message: str) -> None:
        """Log a warning message.

        Args:
            message: Message to log
        """
        self.logger.warning(message)

    def error(self, message: str) -> None:
        """Log an error message.

        Args:
            message: Message to log
        """
        self.logger.error(message)

    def critical(self, message: str) -> None:
        """Log a critical message.

        Args:
            message: Message to log
        """
        self.logger.critical(message)

    def set_level(self, level: int) -> None:
        """Update logging level.

        Args:
            level: New logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)


def get_logger(
    name: str,
    log_dir: str = DEFAULT_LOG_DIR,
    log_file: str = DEFAULT_LOG_FILE,
    level: int = DEFAULT_LOG_LEVEL,
) -> Logger:
    """Get or create a logger instance.

    Args:
        name: Logger name (usually __name__ from calling module)
        log_dir: Directory to store log files
        log_file: Name of the log file
        level: Logging level

    Returns:
        Logger instance
    """
    return Logger(name=name, log_dir=log_dir, log_file=log_file, level=level)
