"""
Interactive CLI for the Motorola Firmware Downloader.

Provides a menu-driven interface for searching, downloading, and
configuring the firmware downloader.  Connects all modules together.

Modelled after ``web_crawler.cli.main()`` — the single entry point
that wires up settings → auth → session → search → download.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional

from motorola_firmware.authenticator import Authenticator
from motorola_firmware.config import (
    DEFAULT_CONFIG_FILE,
    DEFAULT_LOG_FILE,
    FIRMWARE_REGIONS,
    VALID_CONTENT_TYPES,
    auto_concurrency,
)
from motorola_firmware.download_manager import DownloadManager
from motorola_firmware.exceptions import (
    AuthenticationError,
    ConfigurationError,
    DownloadError,
    MotorolaFirmwareError,
    SearchError,
    SessionError,
)
from motorola_firmware.http_client import HttpClient
from motorola_firmware.search_engine import SearchEngine, SearchResult, format_file_size
from motorola_firmware.session_manager import SessionManager
from motorola_firmware.settings import Settings
from motorola_firmware.utils.logger import log, setup_logging
from motorola_firmware.utils.validators import validate_guid


class CLI:
    """Interactive command-line interface for the firmware downloader.

    Wires together all modules (settings, auth, session, search, download)
    and presents a menu-driven interface to the user.
    """

    def __init__(self) -> None:
        """Initialize CLI with empty module references (set up in run)."""
        self._settings: Optional[Settings] = None
        self._http_client: Optional[HttpClient] = None
        self._authenticator: Optional[Authenticator] = None
        self._session_manager: Optional[SessionManager] = None
        self._search_engine: Optional[SearchEngine] = None
        self._download_manager: Optional[DownloadManager] = None
        self._last_results: List[SearchResult] = []

    # ── Bootstrap ──────────────────────────────────────────────────

    def _bootstrap(self) -> None:
        """Initialize all modules and wire dependencies.

        Flow (mirrors web_crawler/cli.py main()):
          1. Load settings from config.ini
          2. Setup logging from settings
          3. Create HttpClient
          4. Create Authenticator (loads stored JWT if available)
          5. Create SessionManager (wraps Authenticator)
          6. Create SearchEngine (uses Session + HttpClient)
          7. Create DownloadManager (uses Session + HttpClient)
        """
        # 1. Settings
        self._settings = Settings(DEFAULT_CONFIG_FILE)
        self._settings.load_from_file()
        try:
            self._settings.validate_config()
        except ConfigurationError as error:
            log.warning("[CONFIG] %s — using defaults", error)

        # 2. Logging
        log_level = self._settings.get("logging", "level", "INFO")
        log_file = self._settings.get("logging", "log_file", DEFAULT_LOG_FILE)
        log_dir = self._settings.get("logging", "log_dir", "logs")
        setup_logging(
            debug=(log_level.upper() == "DEBUG"),
            log_file=log_file,
            log_dir=log_dir,
        )

        # 3. HTTP Client
        timeout = self._settings.get_int("download", "timeout", 30)
        self._http_client = HttpClient(timeout=timeout)

        # 4. Authenticator
        self._authenticator = Authenticator(self._settings, self._http_client)

        # 5. Session Manager
        self._session_manager = SessionManager(
            self._settings, self._authenticator, self._http_client
        )

        # 6. Search Engine
        self._search_engine = SearchEngine(
            self._settings, self._session_manager, self._http_client
        )

        # 7. Download Manager
        self._download_manager = DownloadManager(
            self._settings, self._session_manager, self._http_client
        )

        log.info("[CLI] All modules initialised")

    # ── Main loop ──────────────────────────────────────────────────

    def run(self) -> None:
        """Main entry point — bootstrap modules and run the menu loop."""
        print("\n╔══════════════════════════════════════════════════╗")
        print("║     Motorola Firmware Downloader v1.0.0         ║")
        print("╚══════════════════════════════════════════════════╝\n")

        self._bootstrap()

        # Auto-start session if stored token is valid
        if self._authenticator and self._authenticator.is_authenticated:
            try:
                if self._session_manager and self._session_manager.start_session():
                    print("  ✓ Session resumed with stored credentials\n")
                else:
                    print("  ⚠ Stored token expired — please authenticate\n")
            except SessionError:
                print("  ⚠ Could not resume session — please authenticate\n")

        try:
            while True:
                self._show_main_menu()
        except KeyboardInterrupt:
            print("\n\n  Goodbye!\n")
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources on exit."""
        if self._session_manager:
            self._session_manager.end_session()
        if self._http_client:
            self._http_client.close()

    # ── Menus ──────────────────────────────────────────────────────

    def _show_main_menu(self) -> None:
        """Display the main menu and handle user choice."""
        session_status = "Active ✓" if (
            self._session_manager and self._session_manager.is_active()
        ) else "Inactive ✗"

        print(f"  Session: {session_status}")
        print("  ─────────────────────────────────")
        print("  1. Authenticate / Login")
        print("  2. Search Firmware")
        print("  3. Download Firmware")
        print("  4. Configuration")
        print("  5. Session Info")
        print("  0. Exit")
        print()

        choice = self._get_input("  Select option: ").strip()

        if choice == "1":
            self._auth_menu()
        elif choice == "2":
            self._search_menu()
        elif choice == "3":
            self._download_menu()
        elif choice == "4":
            self._config_menu()
        elif choice == "5":
            self._session_info()
        elif choice == "0":
            print("\n  Goodbye!\n")
            self._cleanup()
            sys.exit(0)
        else:
            print("  ⚠ Invalid option\n")

    def _auth_menu(self) -> None:
        """Authentication submenu."""
        print("\n  ── Authentication ──")
        print("  1. Login with GUID + Password")
        print("  2. Login with JWT token (from HAR capture)")
        print("  0. Back\n")

        choice = self._get_input("  Select: ").strip()

        if choice == "1":
            guid = self._get_input("  GUID (UUID format): ").strip()
            if not validate_guid(guid):
                print("  ⚠ Invalid GUID format\n")
                return
            password = self._get_input("  Password: ").strip()
            if not password:
                print("  ⚠ Password cannot be empty\n")
                return

            try:
                if self._session_manager:
                    success = self._session_manager.start_session_with_credentials(
                        guid, password
                    )
                    if success:
                        print("  ✓ Authentication successful!\n")
                    else:
                        print("  ✗ Authentication failed\n")
            except (SessionError, AuthenticationError) as error:
                print(f"  ✗ Error: {error}\n")

        elif choice == "2":
            jwt_raw = self._get_input("  JWT token (GUID:TOKEN format): ").strip()
            if ":" not in jwt_raw:
                print("  ⚠ Format must be GUID:JWT_TOKEN\n")
                return
            sep_idx = jwt_raw.index(":")
            guid = jwt_raw[:sep_idx]
            token = jwt_raw[sep_idx + 1:]

            if self._settings and self._authenticator:
                self._settings.update("motorola_server", "guid", guid)
                self._settings.update("motorola_server", "jwt_token", token)
                # Re-create authenticator to pick up new token
                self._authenticator = Authenticator(self._settings, self._http_client)
                self._session_manager = SessionManager(
                    self._settings, self._authenticator, self._http_client
                )
                try:
                    if self._session_manager.start_session():
                        print("  ✓ Session started with injected JWT\n")
                    else:
                        print("  ⚠ Token may be expired\n")
                except SessionError:
                    print("  ⚠ Could not start session with provided token\n")

    def _search_menu(self) -> None:
        """Search submenu."""
        if not self._session_manager or not self._session_manager.is_active():
            print("\n  ⚠ Please authenticate first\n")
            return

        print("\n  ── Search Firmware ──")
        print("  1. Quick Search (by model)")
        print("  2. Advanced Search")
        print("  0. Back\n")

        choice = self._get_input("  Select: ").strip()

        if choice == "1":
            query = self._get_input("  Device model (e.g. moto g84): ").strip()
            if not query:
                print("  ⚠ Query cannot be empty\n")
                return

            print(f"\n  Content types: {', '.join(VALID_CONTENT_TYPES)}")
            content_type = self._get_input("  Type [all]: ").strip() or "all"

            try:
                results = self._search_engine.search(query, content_type)
                self._last_results = results
                self._display_results(results)
            except SearchError as error:
                print(f"  ✗ Search error: {error}\n")

        elif choice == "2":
            self._advanced_search_flow()

    def _advanced_search_flow(self) -> None:
        """Run the advanced search interactive flow."""
        query = self._get_input("  Search query: ").strip()
        if not query:
            print("  ⚠ Query cannot be empty\n")
            return

        criteria: Dict[str, Any] = {"query": query}

        content_type = self._get_input("  Content type [all]: ").strip() or "all"
        criteria["content_type"] = content_type

        model = self._get_input("  Device model (optional): ").strip()
        if model:
            criteria["device_model"] = model

        region = self._get_input("  Region (optional): ").strip()
        if region:
            criteria["region"] = region

        include_beta = self._get_input("  Include beta? [n]: ").strip().lower()
        criteria["include_beta"] = include_beta in ("y", "yes", "true")

        try:
            results = self._search_engine.advanced_search(criteria)
            self._last_results = results
            self._display_results(results)
        except SearchError as error:
            print(f"  ✗ Search error: {error}\n")

    def _display_results(self, results: List[SearchResult]) -> None:
        """Display search results in a formatted table.

        Args:
            results: List of search results to display.
        """
        if not results:
            print("\n  No results found.\n")
            return

        print(f"\n  Found {len(results)} results:")
        print("  ─────────────────────────────────────────────────────")
        for idx, result in enumerate(results, 1):
            size_str = format_file_size(result.size_bytes)
            beta_tag = " [BETA]" if result.is_beta else ""
            print(f"  {idx:3d}. {result.name}")
            print(f"       Model: {result.device_model}  Version: {result.version}")
            print(f"       Type: {result.content_type}  Size: {size_str}  "
                  f"Region: {result.region}{beta_tag}")
        print()

    def _download_menu(self) -> None:
        """Download submenu."""
        if not self._session_manager or not self._session_manager.is_active():
            print("\n  ⚠ Please authenticate first\n")
            return

        print("\n  ── Download ──")
        print("  1. Download from search results")
        print("  2. Download by URL")
        print("  3. Set concurrent downloads")
        print("  0. Back\n")

        choice = self._get_input("  Select: ").strip()

        if choice == "1":
            self._download_from_results()
        elif choice == "2":
            self._download_by_url()
        elif choice == "3":
            self._set_concurrency()

    def _download_from_results(self) -> None:
        """Download selected items from last search results."""
        if not self._last_results:
            print("  ⚠ No search results. Run a search first.\n")
            return

        self._display_results(self._last_results)
        selection = self._get_input(
            "  Enter numbers to download (comma-separated, or 'all'): "
        ).strip()

        if selection.lower() == "all":
            selected = self._last_results
        else:
            try:
                indices = [int(s.strip()) - 1 for s in selection.split(",")]
                selected = [self._last_results[i] for i in indices
                            if 0 <= i < len(self._last_results)]
            except (ValueError, IndexError):
                print("  ⚠ Invalid selection\n")
                return

        if not selected:
            print("  ⚠ No items selected\n")
            return

        output_dir = self._settings.get("download", "output_directory", "downloads")
        confirm = self._get_input(
            f"  Download {len(selected)} files to '{output_dir}'? [y/N]: "
        ).strip().lower()

        if confirm not in ("y", "yes"):
            print("  Cancelled.\n")
            return

        items = [
            {"url": r.download_url, "filename": r.name}
            for r in selected if r.download_url
        ]

        try:
            results = self._download_manager.download_multiple(items, output_dir)
            ok = sum(1 for v in results.values() if v)
            fail = sum(1 for v in results.values() if not v)
            print(f"\n  Download complete: {ok} succeeded, {fail} failed\n")
        except DownloadError as error:
            print(f"  ✗ Download error: {error}\n")

    def _download_by_url(self) -> None:
        """Download a file by direct URL."""
        url = self._get_input("  Download URL: ").strip()
        if not url:
            print("  ⚠ URL cannot be empty\n")
            return

        filename = self._get_input("  Filename: ").strip()
        if not filename:
            filename = url.rsplit("/", 1)[-1] or "download"

        output_dir = self._settings.get("download", "output_directory", "downloads")
        filepath = os.path.join(output_dir, filename)
        os.makedirs(output_dir, exist_ok=True)

        try:
            success = self._download_manager.download_single(url, filepath)
            if success:
                print(f"  ✓ Downloaded to {filepath}\n")
            else:
                print("  ✗ Download failed\n")
        except DownloadError as error:
            print(f"  ✗ Error: {error}\n")

    def _set_concurrency(self) -> None:
        """Set the number of concurrent downloads."""
        current = self._download_manager._max_workers if self._download_manager else 3
        value = self._get_input(
            f"  Concurrent downloads (1-5, current: {current}): "
        ).strip()
        try:
            workers = int(value)
            if self._download_manager:
                self._download_manager.set_max_concurrent(workers)
                print(f"  ✓ Set to {workers} concurrent downloads\n")
        except ValueError:
            print("  ⚠ Invalid number\n")

    def _config_menu(self) -> None:
        """Configuration submenu."""
        print("\n  ── Configuration ──")
        print("  1. Show current config")
        print("  2. Set output directory")
        print("  3. Set default region")
        print("  4. Set log level")
        print("  0. Back\n")

        choice = self._get_input("  Select: ").strip()

        if choice == "1":
            self._show_config()
        elif choice == "2":
            new_dir = self._get_input("  New output directory: ").strip()
            if new_dir:
                self._settings.update("download", "output_directory", new_dir)
                print(f"  ✓ Output directory set to '{new_dir}'\n")
        elif choice == "3":
            print(f"  Available regions: {', '.join(FIRMWARE_REGIONS)}")
            region = self._get_input("  Region: ").strip()
            if region:
                self._settings.update("search", "default_region", region)
                print(f"  ✓ Default region set to '{region}'\n")
        elif choice == "4":
            level = self._get_input("  Log level (DEBUG/INFO/WARNING/ERROR): ").strip()
            if level.upper() in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
                self._settings.update("logging", "level", level.upper())
                print(f"  ✓ Log level set to {level.upper()}\n")

    def _show_config(self) -> None:
        """Display current configuration (masking sensitive values)."""
        if not self._settings:
            return
        all_config = self._settings.get_all()
        print("\n  Current Configuration:")
        print("  ─────────────────────────────────")
        sensitive_keys = {"jwt_token", "refresh_token", "password"}
        for section, values in all_config.items():
            print(f"  [{section}]")
            for key, value in values.items():
                if key in sensitive_keys and value:
                    display_value = value[:8] + "…" if len(value) > 8 else "***"
                else:
                    display_value = value
                print(f"    {key} = {display_value}")
        print()

    def _session_info(self) -> None:
        """Display current session information."""
        if not self._session_manager:
            print("\n  No session manager available\n")
            return
        info = self._session_manager.get_session_info()
        print("\n  Session Information:")
        print("  ─────────────────────────────────")
        print(f"  Active:        {info['active']}")
        print(f"  Token valid:   {info['token_valid']}")
        print(f"  Duration:      {info['duration_seconds']:.0f} seconds")
        print()

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _get_input(prompt: str) -> str:
        """Get user input with graceful Ctrl+C handling.

        Args:
            prompt: The input prompt to display.

        Returns:
            User input string, or empty string on EOF/interrupt.
        """
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            return ""


# ── Module-level entry point ───────────────────────────────────────

def main() -> None:
    """Application entry point — create CLI instance and run.

    Mirrors ``web_crawler.cli.main()`` — single function that
    bootstraps everything and starts the interactive loop.
    """
    try:
        cli = CLI()
        cli.run()
    except MotorolaFirmwareError as error:
        log.error("[ERR] Fatal error: %s", error)
        print(f"\n  Fatal error: {error}\n")
        sys.exit(1)
    except Exception as error:
        log.error("[ERR] Unexpected error: %s", error)
        print(f"\n  Unexpected error: {error}\n")
        sys.exit(1)
