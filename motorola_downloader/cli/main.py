"""Interactive CLI interface for Motorola Firmware Downloader.

Provides menu-driven interface for searching, downloading, and managing firmware.
"""

import sys
from typing import List, Optional

from motorola_downloader.core.authenticator import Authenticator, AuthenticationError
from motorola_downloader.core.download_manager import DownloadManager
from motorola_downloader.core.http_client import HTTPClient
from motorola_downloader.core.search_engine import SearchEngine, SearchResult
from motorola_downloader.core.session_manager import SessionManager
from motorola_downloader.core.settings import Settings, ConfigurationError
from motorola_downloader.utils.logger import get_logger
from motorola_downloader.utils.validators import validate_integer_range


class CLI:
    """Interactive command-line interface.

    Provides menu-driven interface for firmware search and download operations.
    """

    def __init__(self) -> None:
        """Initialize CLI."""
        self.logger = get_logger(__name__)
        self.settings: Optional[Settings] = None
        self.http_client: Optional[HTTPClient] = None
        self.authenticator: Optional[Authenticator] = None
        self.session_manager: Optional[SessionManager] = None
        self.search_engine: Optional[SearchEngine] = None
        self.download_manager: Optional[DownloadManager] = None

        self._current_search_results: List[SearchResult] = []

    def run(self) -> None:
        """Main CLI loop."""
        print("=" * 60)
        print("  Motorola Firmware Downloader")
        print("=" * 60)
        print()

        try:
            # Initialize components
            self._initialize()

            # Start session
            if not self._start_session():
                print("\nFailed to start session. Exiting.")
                return

            # Main menu loop
            while True:
                try:
                    choice = self._show_main_menu()

                    if choice == "1":
                        self._search_menu()
                    elif choice == "2":
                        self._download_menu()
                    elif choice == "3":
                        self._config_menu()
                    elif choice == "4":
                        self._show_session_info()
                    elif choice == "5":
                        print("\nExiting...")
                        break
                    else:
                        print("Invalid choice. Please try again.")

                except KeyboardInterrupt:
                    print("\n\nOperation cancelled by user.")
                    if self._confirm_action("Exit application?"):
                        break

        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            print(f"\nFatal error: {e}")

        finally:
            # Cleanup
            self._cleanup()

    def _initialize(self) -> None:
        """Initialize CLI components."""
        try:
            print("Loading configuration...")
            self.settings = Settings("config.ini")

            # Initialize HTTP client
            timeout = self.settings.get_int("download", "timeout", 30)
            verify_ssl = self.settings.get_bool("download", "verify_ssl", True)
            self.http_client = HTTPClient(timeout=timeout, verify_ssl=verify_ssl)

            # Initialize authenticator
            base_url = self.settings.get("motorola_server", "base_url")
            guid = self.settings.get("motorola_server", "guid")
            auto_refresh = self.settings.get_bool("authentication", "auto_refresh", True)
            refresh_threshold = self.settings.get_int("authentication", "refresh_threshold", 3600)

            self.authenticator = Authenticator(
                base_url=base_url,
                guid=guid,
                http_client=self.http_client,
                auto_refresh=auto_refresh,
                refresh_threshold=refresh_threshold,
            )

            # Initialize session manager
            self.session_manager = SessionManager(
                settings=self.settings,
                authenticator=self.authenticator,
                http_client=self.http_client,
            )

            # Initialize search engine
            self.search_engine = SearchEngine(
                base_url=base_url,
                authenticator=self.authenticator,
                http_client=self.http_client,
            )

            # Initialize download manager
            max_concurrent = self.settings.get_int("download", "max_concurrent_downloads", 3)
            output_dir = self.settings.get("download", "output_directory", "downloads")

            self.download_manager = DownloadManager(
                http_client=self.http_client,
                max_concurrent=max_concurrent,
                output_directory=output_dir,
            )

            print("Configuration loaded successfully.\n")

        except ConfigurationError as e:
            print(f"\nConfiguration error: {e}")
            print("Please ensure config.ini is properly configured.")
            sys.exit(1)

    def _start_session(self) -> bool:
        """Start authenticated session."""
        print("Starting session...")

        # Try to start session with existing token
        if self.session_manager.start_session():
            print("Session started with existing token.\n")
            return True

        # Need password for authentication
        print("\nAuthentication required.")
        password = input("Enter password (or press Enter to exit): ").strip()

        if not password:
            return False

        try:
            if self.session_manager.start_session(password=password):
                print("Authentication successful.\n")
                return True
            else:
                print("Authentication failed.")
                return False

        except AuthenticationError as e:
            print(f"Authentication error: {e}")
            return False

    def _show_main_menu(self) -> str:
        """Display main menu and get user choice."""
        print("\n" + "=" * 60)
        print("Main Menu")
        print("=" * 60)
        print("1. Search for firmware")
        print("2. Download firmware")
        print("3. Configuration")
        print("4. Session information")
        print("5. Exit")
        print()

        return input("Enter choice: ").strip()

    def _search_menu(self) -> None:
        """Display search menu."""
        print("\n" + "-" * 60)
        print("Search Menu")
        print("-" * 60)

        # Get search query
        query = input("Enter search query (model, version): ").strip()
        if not query:
            print("Search cancelled.")
            return

        # Get content type
        print("\nContent type:")
        print("1. All")
        print("2. Firmware")
        print("3. ROM")
        print("4. Tools")
        type_choice = input("Enter choice (default: 1): ").strip() or "1"

        content_type_map = {
            "1": "all",
            "2": "firmware",
            "3": "rom",
            "4": "tools",
        }
        content_type = content_type_map.get(type_choice, "all")

        # Perform search
        print(f"\nSearching for '{query}' (type: {content_type})...")

        try:
            results = self.search_engine.search(query, content_type)
            self._current_search_results = results

            if not results:
                print("No results found.")
                return

            # Display results
            print(f"\nFound {len(results)} results:")
            print()

            for i, result in enumerate(results, 1):
                print(f"{i}. {result.model} - {result.version} ({result.region})")
                if result.file_size:
                    size_mb = result.file_size / (1024 * 1024)
                    print(f"   Size: {size_mb:.2f} MB")
                if result.description:
                    print(f"   {result.description}")
                print()

        except Exception as e:
            print(f"Search error: {e}")
            self.logger.error(f"Search error: {e}")

    def _download_menu(self) -> None:
        """Display download menu."""
        print("\n" + "-" * 60)
        print("Download Menu")
        print("-" * 60)

        if not self._current_search_results:
            print("No search results available. Please search first.")
            return

        # Show available results
        print(f"\n{len(self._current_search_results)} results available:")
        for i, result in enumerate(self._current_search_results, 1):
            print(f"{i}. {result.model} - {result.version}")

        print()
        selection = input("Enter result numbers to download (comma-separated, or 'all'): ").strip()

        if not selection:
            print("Download cancelled.")
            return

        # Parse selection
        to_download = []

        if selection.lower() == "all":
            to_download = self._current_search_results
        else:
            try:
                indices = [int(x.strip()) for x in selection.split(",")]
                for idx in indices:
                    if 1 <= idx <= len(self._current_search_results):
                        to_download.append(self._current_search_results[idx - 1])
                    else:
                        print(f"Warning: Index {idx} out of range, skipping.")
            except ValueError:
                print("Invalid selection format.")
                return

        if not to_download:
            print("No valid selections.")
            return

        # Confirm download
        print(f"\nPreparing to download {len(to_download)} file(s).")
        if not self._confirm_action("Continue with download?"):
            print("Download cancelled.")
            return

        # Prepare download items
        items = [(result.download_url, None) for result in to_download]

        # Start downloads
        print("\nStarting downloads...")

        def progress_callback(completed: int, total: int) -> None:
            """Display download progress."""
            print(f"Progress: {completed}/{total} files completed")

        try:
            results = self.download_manager.download_multiple(
                items=items,
                progress_callback=progress_callback,
            )

            # Display summary
            successful = sum(1 for r in results if r.success)
            failed = len(results) - successful

            print(f"\nDownload complete:")
            print(f"  Successful: {successful}")
            print(f"  Failed: {failed}")

        except Exception as e:
            print(f"Download error: {e}")
            self.logger.error(f"Download error: {e}")

    def _config_menu(self) -> None:
        """Display configuration menu."""
        print("\n" + "-" * 60)
        print("Configuration Menu")
        print("-" * 60)
        print("1. View configuration")
        print("2. Update max concurrent downloads")
        print("3. Back to main menu")
        print()

        choice = input("Enter choice: ").strip()

        if choice == "1":
            self._view_config()
        elif choice == "2":
            self._update_max_concurrent()

    def _view_config(self) -> None:
        """Display current configuration."""
        print("\nCurrent Configuration:")
        print("-" * 40)

        sections = self.settings.get_all_sections()
        for section in sections:
            print(f"\n[{section}]")
            keys = self.settings.get_section_keys(section)
            for key in keys:
                # Don't display sensitive values
                if any(x in key.lower() for x in ["password", "token", "key"]):
                    value = "***HIDDEN***"
                else:
                    value = self.settings.get(section, key)
                print(f"  {key} = {value}")

    def _update_max_concurrent(self) -> None:
        """Update max concurrent downloads setting."""
        current = self.settings.get_int("download", "max_concurrent_downloads")
        print(f"\nCurrent max concurrent downloads: {current}")

        new_value = input("Enter new value (1-5): ").strip()
        validated = validate_integer_range(new_value, 1, 5)

        if validated is not None:
            self.settings.update("download", "max_concurrent_downloads", validated)
            self.download_manager.set_max_concurrent(validated)
            print(f"Updated to {validated}")
        else:
            print("Invalid value. Must be between 1 and 5.")

    def _show_session_info(self) -> None:
        """Display session information."""
        print("\n" + "-" * 60)
        print("Session Information")
        print("-" * 60)

        info = self.session_manager.get_session_info()

        for key, value in info.items():
            print(f"{key}: {value}")

    def _confirm_action(self, message: str) -> bool:
        """Ask user for confirmation.

        Args:
            message: Confirmation message

        Returns:
            True if user confirms, False otherwise
        """
        response = input(f"{message} (y/n): ").strip().lower()
        return response in ("y", "yes")

    def _cleanup(self) -> None:
        """Cleanup resources."""
        print("\nCleaning up...")

        if self.session_manager:
            self.session_manager.end_session()

        if self.http_client:
            self.http_client.close()

        print("Goodbye!")


def main() -> None:
    """CLI entry point."""
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
