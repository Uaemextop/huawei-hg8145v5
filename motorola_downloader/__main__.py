"""Entry point for Motorola Firmware Downloader.

Initializes all application components and starts the interactive CLI.
Handles global exception catching and graceful shutdown.

Usage:
    python -m motorola_downloader
"""

import sys
from pathlib import Path
from typing import Optional

from motorola_downloader.auth.session_manager import SessionManager
from motorola_downloader.cli import CLI
from motorola_downloader.download.download_manager import DownloadManager
from motorola_downloader.exceptions import ConfigurationError, MotorolaDownloaderError
from motorola_downloader.search.search_engine import SearchEngine
from motorola_downloader.settings import Settings
from motorola_downloader.utils.http_client import HTTPClient
from motorola_downloader.utils.logger import get_logger, setup_logging

# Default configuration path relative to the package directory
_DEFAULT_CONFIG = str(Path(__file__).parent / "config.ini")


def main(config_path: Optional[str] = None) -> int:
    """Initialize and run the Motorola Firmware Downloader application.

    Loads configuration, sets up logging, initializes all modules,
    and starts the interactive CLI.

    Args:
        config_path: Optional path to config.ini file.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    try:
        # 1. Load configuration
        config_file = config_path or _DEFAULT_CONFIG
        settings = Settings(config_file)
        settings.load_from_file(create_if_missing=True)
        settings.validate_config()

        # 2. Initialize logging from config
        log_level = settings.get("logging", "level", fallback="INFO")
        log_file = settings.get("logging", "log_file", fallback="logs/motorola_downloader.log")
        max_size_mb = settings.get_int("logging", "max_file_size_mb", fallback=5)
        backup_count = settings.get_int("logging", "backup_count", fallback=5)

        setup_logging(
            level=log_level,
            log_file=log_file,
            max_bytes=max_size_mb * 1024 * 1024,
            backup_count=backup_count,
        )

        logger = get_logger("main")
        logger.info("Motorola Firmware Downloader starting...")

        # 3. Create shared HTTP client
        http_client = HTTPClient(
            timeout=settings.get_int("download", "timeout", fallback=30),
            max_retries=settings.get_int("download", "max_retries", fallback=3),
        )

        # 4. Initialize session manager
        session = SessionManager(settings, http_client)

        # 5. Attempt session start (non-fatal if no credentials yet)
        guid = settings.get("motorola_server", "guid", fallback="")
        if guid:
            try:
                session.start_session()
                logger.info("Session started successfully")
            except MotorolaDownloaderError as exc:
                logger.warning("Session start failed (manual auth may be needed): %s", exc)
        else:
            logger.info("No GUID configured — manual authentication required")

        # 6. Initialize search engine
        search_engine = SearchEngine(session, settings)

        # 7. Initialize download manager
        download_manager = DownloadManager(settings, http_client)

        # 8. Start CLI
        cli = CLI(settings, session, search_engine, download_manager)
        cli.run()

        logger.info("Application exited normally")
        return 0

    except ConfigurationError as exc:
        print(f"\n Configuration Error: {exc}", file=sys.stderr)
        print(" Please check your config.ini file.\n", file=sys.stderr)
        return 1

    except MotorolaDownloaderError as exc:
        print(f"\n Application Error: {exc}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\n\n Interrupted by user. Goodbye!")
        return 0

    except Exception as exc:
        print(f"\n Fatal Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
