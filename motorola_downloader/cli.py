"""Interactive CLI interface for Motorola Firmware Downloader.

Provides a menu-driven command-line interface for searching, downloading,
and configuring the firmware downloader. Uses colorama for colored output,
rich for formatted tables and panels, and tqdm for download progress bars.
Handles user input validation, progress display, and graceful shutdown.
"""

import os
import signal
import sys
from typing import Any, Dict, List, Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORAMA = True
except ImportError:
    _COLORAMA = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    _RICH = True
except ImportError:
    _RICH = False

from motorola_downloader.auth.session_manager import SessionManager
from motorola_downloader.download.download_manager import DownloadItem, DownloadManager
from motorola_downloader.exceptions import (
    AuthenticationError,
    DownloadError,
    MotorolaDownloaderError,
    SearchError,
    SessionError,
)
from motorola_downloader.search.search_engine import SearchEngine, SearchResult
from motorola_downloader.settings import Settings
from motorola_downloader.utils.logger import get_logger, mask_sensitive
from motorola_downloader.utils.validators import (
    validate_guid,
    validate_positive_int,
    validate_search_query,
)

_logger = get_logger(__name__)

# Rich console instance (used when rich is available)
_console = Console() if _RICH else None

# ---------------------------------------------------------------------------
# Color helper functions
# ---------------------------------------------------------------------------


def _c(text: str, color: str = "") -> str:
    """Apply colorama color to text if available.

    Args:
        text: The text to colorize.
        color: Colorama color constant (e.g., Fore.GREEN).

    Returns:
        Colorized text string, or plain text if colorama unavailable.
    """
    if _COLORAMA and color:
        return f"{color}{text}{Style.RESET_ALL}"
    return text

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

APP_NAME = "Motorola Firmware Downloader"
APP_VERSION = "1.0.0"

MAIN_MENU_OPTIONS = {
    "1": "Search Firmware",
    "2": "Download Manager",
    "3": "Configuration",
    "4": "Session Info",
    "5": "Exit",
}

SEARCH_MENU_OPTIONS = {
    "1": "Search by Model",
    "2": "Search by Version",
    "3": "Advanced Search",
    "4": "View Recent Results",
    "5": "Back to Main Menu",
}

DOWNLOAD_MENU_OPTIONS = {
    "1": "Download Selected Items",
    "2": "View Download Progress",
    "3": "Pause Downloads",
    "4": "Resume Downloads",
    "5": "Set Output Directory",
    "6": "Back to Main Menu",
}

CONFIG_MENU_OPTIONS = {
    "1": "View Configuration",
    "2": "Set GUID",
    "3": "Set JWT Token",
    "4": "Set Output Directory",
    "5": "Set Max Concurrent Downloads",
    "6": "Set Search Region",
    "7": "Back to Main Menu",
}


class CLI:
    """Interactive command-line interface for the firmware downloader.

    Provides menu-driven navigation for all application features including
    searching, downloading, and configuration management.

    Args:
        settings: Application settings instance.
        session: Authenticated session manager.
        search_engine: Search engine instance.
        download_manager: Download manager instance.
    """

    def __init__(
        self,
        settings: Settings,
        session: SessionManager,
        search_engine: SearchEngine,
        download_manager: DownloadManager,
    ) -> None:
        """Initialize the CLI.

        Args:
            settings: Application settings.
            session: Session manager for authentication.
            search_engine: Search engine for firmware queries.
            download_manager: Download manager for file transfers.
        """
        self._settings = settings
        self._session = session
        self._search_engine = search_engine
        self._download_manager = download_manager
        self.logger = get_logger(__name__)
        self._last_results: List[SearchResult] = []
        self._running = True

        signal.signal(signal.SIGINT, self._handle_interrupt)

    def run(self) -> None:
        """Start the main CLI loop.

        Displays the main menu and processes user selections until
        the user chooses to exit or sends Ctrl+C.
        """
        self._print_banner()
        self.logger.info("CLI started")

        while self._running:
            try:
                self.show_main_menu()
            except KeyboardInterrupt:
                self._handle_exit()
                break
            except MotorolaDownloaderError as exc:
                self._print_error(str(exc))
            except Exception as exc:
                self._print_error(f"Unexpected error: {exc}")
                self.logger.error("Unexpected CLI error: %s", exc)

    def show_main_menu(self) -> None:
        """Display the main menu and process the user's selection."""
        self._print_menu("Main Menu", MAIN_MENU_OPTIONS)
        choice = self._get_input("Select option: ")

        if choice == "1":
            self.search_menu()
        elif choice == "2":
            self.download_menu()
        elif choice == "3":
            self.config_menu()
        elif choice == "4":
            self._show_session_info()
        elif choice == "5":
            self._handle_exit()
        else:
            self._print_error("Invalid option. Please try again.")

    def search_menu(self) -> None:
        """Display the search submenu and process selections."""
        while self._running:
            self._print_menu("Search Menu", SEARCH_MENU_OPTIONS)
            choice = self._get_input("Select option: ")

            if choice == "1":
                self._search_by_model()
            elif choice == "2":
                self._search_by_version()
            elif choice == "3":
                self._advanced_search()
            elif choice == "4":
                self._view_results()
            elif choice == "5":
                return
            else:
                self._print_error("Invalid option. Please try again.")

    def download_menu(self) -> None:
        """Display the download submenu and process selections."""
        while self._running:
            self._print_menu("Download Menu", DOWNLOAD_MENU_OPTIONS)
            choice = self._get_input("Select option: ")

            if choice == "1":
                self._download_selected()
            elif choice == "2":
                self._view_download_progress()
            elif choice == "3":
                self._download_manager.pause_downloads()
                self._print_info("Downloads paused")
            elif choice == "4":
                self._download_manager.resume_downloads()
                self._print_info("Downloads resumed")
            elif choice == "5":
                self._set_output_directory()
            elif choice == "6":
                return
            else:
                self._print_error("Invalid option. Please try again.")

    def config_menu(self) -> None:
        """Display the configuration submenu and process selections."""
        while self._running:
            self._print_menu("Configuration Menu", CONFIG_MENU_OPTIONS)
            choice = self._get_input("Select option: ")

            if choice == "1":
                self._view_configuration()
            elif choice == "2":
                self._set_guid()
            elif choice == "3":
                self._set_jwt_token()
            elif choice == "4":
                self._set_output_directory()
            elif choice == "5":
                self._set_max_concurrent()
            elif choice == "6":
                self._set_search_region()
            elif choice == "7":
                return
            else:
                self._print_error("Invalid option. Please try again.")

    # -----------------------------------------------------------------------
    # Search operations
    # -----------------------------------------------------------------------

    def _search_by_model(self) -> None:
        """Perform a search by device model name."""
        query = self._get_input("Enter model name (e.g., moto g84): ")
        if not validate_search_query(query):
            self._print_error("Invalid search query. Minimum 2 characters required.")
            return

        content_type = self._select_content_type()
        self._print_info(f"Searching for '{query}' ({content_type})...")

        try:
            results = self._search_engine.search(query, content_type)
            self._last_results = results
            self._display_results(results)
        except SearchError as exc:
            self._print_error(f"Search failed: {exc}")

    def _search_by_version(self) -> None:
        """Perform a search by firmware version."""
        query = self._get_input("Enter firmware version: ")
        if not validate_search_query(query):
            self._print_error("Invalid search query. Minimum 2 characters required.")
            return

        self._print_info(f"Searching for version '{query}'...")

        try:
            results = self._search_engine.search(
                query, "firmware", {"version": query}
            )
            self._last_results = results
            self._display_results(results)
        except SearchError as exc:
            self._print_error(f"Search failed: {exc}")

    def _advanced_search(self) -> None:
        """Perform an advanced search with multiple criteria."""
        print("\n--- Advanced Search ---")
        model = self._get_input("Model name (or press Enter to skip): ")
        region = self._get_input("Region (or press Enter for default): ")
        content_type = self._select_content_type()
        max_size = self._get_input("Max file size in MB (or press Enter to skip): ")

        criteria: Dict[str, Any] = {}
        if model:
            criteria["query"] = model
        else:
            criteria["query"] = self._get_input("Search keyword: ")

        criteria["content_type"] = content_type
        if region:
            criteria["region"] = region
        if max_size:
            try:
                criteria["max_size"] = int(max_size) * 1024 * 1024
            except ValueError:
                self._print_error("Invalid size value, ignoring filter")

        self._print_info("Performing advanced search...")

        try:
            results = self._search_engine.advanced_search(criteria)
            self._last_results = results
            self._display_results(results)
        except SearchError as exc:
            self._print_error(f"Advanced search failed: {exc}")

    def _view_results(self) -> None:
        """Display the most recent search results."""
        if not self._last_results:
            self._print_info("No recent search results. Perform a search first.")
            return
        self._display_results(self._last_results)

    def _display_results(self, results: List[SearchResult]) -> None:
        """Display search results in a formatted table.

        Uses rich.Table when available for beautiful formatting,
        falls back to plain text with colorama colors otherwise.

        Args:
            results: List of SearchResult objects to display.
        """
        if not results:
            self._print_info("No results found.")
            return

        if _RICH and _console:
            table = Table(
                title=f"Found {len(results)} results",
                title_style="bold green",
                show_lines=False,
            )
            table.add_column("#", style="dim", width=4, justify="right")
            table.add_column("Type", style="cyan", width=10)
            table.add_column("Name", style="white", max_width=30)
            table.add_column("Model", style="yellow", width=15)
            table.add_column("Size", justify="right", style="magenta", width=10)

            for idx, result in enumerate(results, 1):
                size_str = self._format_size(result.file_size) if result.file_size else "N/A"
                table.add_row(
                    str(idx),
                    result.content_type,
                    result.name[:30],
                    result.model[:15],
                    size_str,
                )

            _console.print()
            _console.print(table)
            _console.print()
        else:
            header = _c(f"{'=' * 80}", Fore.CYAN if _COLORAMA else "")
            print(f"\n{header}")
            print(_c(f" Found {len(results)} results", Fore.GREEN if _COLORAMA else ""))
            print(header)
            print(f" {'#':>3} | {'Type':<10} | {'Name':<25} | {'Model':<15} | {'Size':>10}")
            print(f"{'-' * 80}")

            for idx, result in enumerate(results, 1):
                size_str = self._format_size(result.file_size) if result.file_size else "N/A"
                name_display = result.name[:25] if len(result.name) > 25 else result.name
                model_display = result.model[:15] if len(result.model) > 15 else result.model
                idx_str = _c(f"{idx:>3}", Fore.YELLOW if _COLORAMA else "")
                type_str = _c(f"{result.content_type:<10}", Fore.CYAN if _COLORAMA else "")
                print(
                    f" {idx_str} | {type_str} | {name_display:<25} | "
                    f"{model_display:<15} | {size_str:>10}"
                )

            print(f"{header}\n")

    # -----------------------------------------------------------------------
    # Download operations
    # -----------------------------------------------------------------------

    def _download_selected(self) -> None:
        """Download items selected from the most recent search results."""
        if not self._last_results:
            self._print_info("No search results available. Perform a search first.")
            return

        self._display_results(self._last_results)
        selection = self._get_input(
            "Enter item numbers to download (comma-separated, or 'all'): "
        )

        items_to_download: List[SearchResult] = []

        if selection.strip().lower() == "all":
            items_to_download = [r for r in self._last_results if r.download_url]
        else:
            try:
                indices = [int(s.strip()) - 1 for s in selection.split(",")]
                for idx in indices:
                    if 0 <= idx < len(self._last_results):
                        if self._last_results[idx].download_url:
                            items_to_download.append(self._last_results[idx])
                        else:
                            self._print_error(
                                f"Item {idx + 1} has no download URL"
                            )
                    else:
                        self._print_error(f"Invalid item number: {idx + 1}")
            except ValueError:
                self._print_error("Invalid selection format")
                return

        if not items_to_download:
            self._print_info("No valid items selected for download.")
            return

        # Confirm download
        print(f"\nReady to download {len(items_to_download)} files:")
        for item in items_to_download:
            size_str = self._format_size(item.file_size) if item.file_size else "Unknown"
            print(f"  - {item.name} ({size_str})")

        confirm = self._get_input("\nProceed with download? (y/n): ")
        if confirm.lower() != "y":
            self._print_info("Download cancelled.")
            return

        # Convert to DownloadItems
        download_items = [
            DownloadItem(
                url=result.download_url,
                filepath=os.path.join(
                    self._download_manager.output_directory, result.name
                ),
                filename=result.name,
                file_size=result.file_size,
                checksum=result.checksum,
            )
            for result in items_to_download
        ]

        self._print_info(f"Starting download of {len(download_items)} files...")

        try:
            results = self._download_manager.download_multiple(download_items)
            self._print_download_summary(results)
        except DownloadError as exc:
            self._print_error(f"Download error: {exc}")

    def _view_download_progress(self) -> None:
        """Display progress for all active downloads with colors."""
        progress = self._download_manager.get_all_progress()
        if not progress:
            self._print_info("No active downloads.")
            return

        if _RICH and _console:
            table = Table(title="Download Progress", title_style="bold blue")
            table.add_column("File", style="white", max_width=30)
            table.add_column("Status", width=15)
            table.add_column("Progress", justify="right", width=8)
            table.add_column("Speed", justify="right", style="cyan", width=12)
            table.add_column("ETA", justify="right", style="yellow", width=10)

            for filename, prog in progress.items():
                if prog.completed:
                    status = "[bold green]✓ Complete[/bold green]"
                elif prog.failed:
                    status = "[bold red]✗ Failed[/bold red]"
                else:
                    status = "[bold yellow]↓ Downloading[/bold yellow]"

                table.add_row(
                    filename[:30],
                    status,
                    f"{prog.get_percent():.1f}%",
                    prog.get_speed_str(),
                    prog.get_eta_str(),
                )

            _console.print()
            _console.print(table)
            _console.print()
        else:
            header = _c(f"{'=' * 70}", Fore.CYAN if _COLORAMA else "")
            print(f"\n{header}")
            print(_c(" Download Progress", Fore.BLUE if _COLORAMA else ""))
            print(header)

            for filename, prog in progress.items():
                if prog.completed:
                    status = _c("✓ Complete", Fore.GREEN if _COLORAMA else "")
                elif prog.failed:
                    status = _c("✗ Failed", Fore.RED if _COLORAMA else "")
                else:
                    status = _c("↓ Downloading", Fore.YELLOW if _COLORAMA else "")
                percent = f"{prog.get_percent():.1f}%"
                speed = prog.get_speed_str()
                eta = prog.get_eta_str()
                print(
                    f" {filename:<30} | {status:<15} | {percent:>7} | "
                    f"{speed:>10} | ETA: {eta}"
                )

            print(f"{header}\n")

    def _print_download_summary(self, results: Dict[str, bool]) -> None:
        """Print a summary of download results with colors.

        Args:
            results: Dictionary mapping filenames to success status.
        """
        successful = [f for f, s in results.items() if s]
        failed = [f for f, s in results.items() if not s]

        if _RICH and _console:
            _console.print(Panel.fit(
                f"[bold green]Successful:[/bold green] {len(successful)}\n"
                f"[bold red]Failed:[/bold red]     {len(failed)}",
                title="[bold]Download Summary[/bold]",
                border_style="blue",
            ))
            if failed:
                _console.print("\n [bold red]Failed downloads:[/bold red]")
                for filename in failed:
                    _console.print(f"   [red]✗[/red] {filename}")
            _console.print()
        else:
            header = _c(f"{'=' * 50}", Fore.CYAN if _COLORAMA else "")
            print(f"\n{header}")
            print(_c(" Download Summary", Fore.BLUE if _COLORAMA else ""))
            print(header)
            print(f" {_c('Successful:', Fore.GREEN if _COLORAMA else '')} {len(successful)}")
            print(f" {_c('Failed:', Fore.RED if _COLORAMA else '')}     {len(failed)}")

            if failed:
                print(f"\n {_c('Failed downloads:', Fore.RED if _COLORAMA else '')}")
                for filename in failed:
                    print(f"   {_c('✗', Fore.RED if _COLORAMA else '')} {filename}")

            print(f"{header}\n")

    # -----------------------------------------------------------------------
    # Configuration operations
    # -----------------------------------------------------------------------

    def _view_configuration(self) -> None:
        """Display current configuration settings with colors."""
        if _RICH and _console:
            for section in self._settings.get_all_sections():
                table = Table(show_header=False, box=None, padding=(0, 1))
                table.add_column("Key", style="yellow", width=30)
                table.add_column("Value", style="white")

                items = self._settings.get_section_items(section)
                for key, value in items.items():
                    display_value = value
                    if key in ("jwt_token", "refresh_token") and value:
                        display_value = mask_sensitive(value)
                    elif key == "guid" and value:
                        display_value = mask_sensitive(value, visible_chars=8)
                    table.add_row(key, display_value)

                _console.print(Panel(table, title=f"[bold cyan][{section}][/bold cyan]", border_style="dim"))
            _console.print()
        else:
            header = _c(f"{'=' * 50}", Fore.CYAN if _COLORAMA else "")
            print(f"\n{header}")
            print(_c(" Current Configuration", Fore.BLUE if _COLORAMA else ""))
            print(header)

            for section in self._settings.get_all_sections():
                section_name = _c(f"\n [{section}]", Fore.CYAN if _COLORAMA else "")
                print(section_name)
                items = self._settings.get_section_items(section)
                for key, value in items.items():
                    display_value = value
                    if key in ("jwt_token", "refresh_token") and value:
                        display_value = mask_sensitive(value)
                    elif key == "guid" and value:
                        display_value = mask_sensitive(value, visible_chars=8)
                    key_str = _c(f"   {key}", Fore.YELLOW if _COLORAMA else "")
                    print(f"{key_str} = {display_value}")

            print(f"\n{header}\n")

    def _set_guid(self) -> None:
        """Set the device GUID in configuration."""
        guid = self._get_input("Enter GUID (UUID v4 format): ")
        if not validate_guid(guid):
            self._print_error("Invalid GUID format. Expected UUID v4 (e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
            return

        self._settings.update("motorola_server", "guid", guid)
        self._print_info("GUID updated successfully")

    def _set_jwt_token(self) -> None:
        """Set the JWT token in configuration."""
        token = self._get_input("Enter JWT token: ")
        if not token.strip():
            self._print_error("Token cannot be empty")
            return

        self._settings.update("motorola_server", "jwt_token", token.strip())
        self._print_info("JWT token updated successfully")

    def _set_output_directory(self) -> None:
        """Set the download output directory."""
        directory = self._get_input("Enter output directory path: ")
        if not directory.strip():
            self._print_error("Directory path cannot be empty")
            return

        self._settings.update("download", "output_directory", directory.strip())
        self._print_info(f"Output directory set to: {directory.strip()}")

    def _set_max_concurrent(self) -> None:
        """Set the maximum number of concurrent downloads."""
        value = self._get_input("Enter max concurrent downloads (1-5): ")
        if not validate_positive_int(value, min_val=1, max_val=5):
            self._print_error("Value must be between 1 and 5")
            return

        self._settings.update("download", "max_concurrent_downloads", value.strip())
        self._download_manager.set_max_concurrent(int(value.strip()))
        self._print_info(f"Max concurrent downloads set to {value.strip()}")

    def _set_search_region(self) -> None:
        """Set the default search region."""
        regions = self._search_engine.get_available_regions()
        print("\nAvailable regions:")
        for idx, region in enumerate(regions, 1):
            print(f"  {idx}. {region}")

        choice = self._get_input("Select region number: ")
        try:
            region_idx = int(choice.strip()) - 1
            if 0 <= region_idx < len(regions):
                self._settings.update("search", "default_region", regions[region_idx])
                self._print_info(f"Default region set to: {regions[region_idx]}")
            else:
                self._print_error("Invalid region selection")
        except ValueError:
            self._print_error("Invalid input")

    # -----------------------------------------------------------------------
    # Session info
    # -----------------------------------------------------------------------

    def _show_session_info(self) -> None:
        """Display current session information with colors."""
        info = self._session.get_session_info()

        if _RICH and _console:
            active_str = "[bold green]Yes[/bold green]" if info["active"] else "[bold red]No[/bold red]"
            guid_str = mask_sensitive(info["guid"], 8) if info["guid"] else "[dim]Not set[/dim]"
            token_str = "[green]Yes[/green]" if info["has_token"] else "[red]No[/red]"
            duration_str = ""
            if info["session_duration"] > 0:
                duration_str = f"{info['session_duration'] / 60:.1f} minutes"

            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Key", style="yellow", width=15)
            table.add_column("Value", style="white")
            table.add_row("Active", active_str)
            table.add_row("GUID", guid_str)
            table.add_row("Has Token", token_str)
            if duration_str:
                table.add_row("Duration", duration_str)

            _console.print(Panel(table, title="[bold]Session Information[/bold]", border_style="blue"))
        else:
            header = _c(f"{'=' * 50}", Fore.CYAN if _COLORAMA else "")
            print(f"\n{header}")
            print(_c(" Session Information", Fore.BLUE if _COLORAMA else ""))
            print(header)

            active_str = _c("Yes", Fore.GREEN if _COLORAMA else "") if info["active"] else _c("No", Fore.RED if _COLORAMA else "")
            print(f" Active:    {active_str}")
            print(f" GUID:      {mask_sensitive(info['guid'], 8) if info['guid'] else 'Not set'}")

            token_str = _c("Yes", Fore.GREEN if _COLORAMA else "") if info["has_token"] else _c("No", Fore.RED if _COLORAMA else "")
            print(f" Has Token: {token_str}")

            if info["session_duration"] > 0:
                duration_min = info["session_duration"] / 60
                print(f" Duration:  {duration_min:.1f} minutes")

            print(f"{header}\n")

    # -----------------------------------------------------------------------
    # Helper methods
    # -----------------------------------------------------------------------

    def _select_content_type(self) -> str:
        """Prompt user to select a content type.

        Returns:
            Selected content type string.
        """
        if _RICH and _console:
            _console.print("\n[bold]Content types:[/bold]")
            _console.print("  [yellow]1.[/yellow] Firmware")
            _console.print("  [yellow]2.[/yellow] ROM")
            _console.print("  [yellow]3.[/yellow] Tools")
            _console.print("  [yellow]4.[/yellow] All")
        else:
            print("\nContent types:")
            print(f"  {_c('1.', Fore.YELLOW if _COLORAMA else '')} Firmware")
            print(f"  {_c('2.', Fore.YELLOW if _COLORAMA else '')} ROM")
            print(f"  {_c('3.', Fore.YELLOW if _COLORAMA else '')} Tools")
            print(f"  {_c('4.', Fore.YELLOW if _COLORAMA else '')} All")
        choice = self._get_input("Select content type (1-4): ")

        type_map = {"1": "firmware", "2": "rom", "3": "tools", "4": "all"}
        return type_map.get(choice, "all")

    def _get_input(self, prompt: str) -> str:
        """Get validated user input.

        Args:
            prompt: Input prompt string to display.

        Returns:
            User input string (stripped).
        """
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return ""

    def _print_banner(self) -> None:
        """Print the application banner with colors."""
        if _RICH and _console:
            _console.print(Panel.fit(
                f"[bold cyan]{APP_NAME}[/bold cyan] [dim]v{APP_VERSION}[/dim]\n"
                "[green]Professional Motorola firmware download tool[/green]",
                border_style="bright_blue",
            ))
        else:
            header = _c(f"{'=' * 50}", Fore.CYAN if _COLORAMA else "")
            print(f"\n{header}")
            print(_c(f" {APP_NAME} v{APP_VERSION}", Fore.CYAN if _COLORAMA else ""))
            print(header)
            print(_c(" Professional Motorola firmware download tool", Fore.GREEN if _COLORAMA else ""))
            print(f"{header}\n")

    def _print_menu(self, title: str, options: Dict[str, str]) -> None:
        """Print a formatted menu with colored options.

        Args:
            title: Menu title.
            options: Dictionary of option numbers to descriptions.
        """
        if _RICH and _console:
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("Key", style="bold yellow", width=4)
            table.add_column("Option", style="white")
            for key, description in options.items():
                table.add_row(f"[{key}]", description)
            _console.print(f"\n[bold bright_blue]--- {title} ---[/bold bright_blue]")
            _console.print(table)
        else:
            title_colored = _c(f"\n--- {title} ---", Fore.CYAN if _COLORAMA else "")
            print(title_colored)
            for key, description in options.items():
                key_str = _c(f"  {key}.", Fore.YELLOW if _COLORAMA else "")
                print(f"{key_str} {description}")
            print()

    def _print_info(self, message: str) -> None:
        """Print an info message with color.

        Args:
            message: Message string to display.
        """
        if _RICH and _console:
            _console.print(f"\n [bold green]ℹ[/bold green] {message}")
        else:
            symbol = _c("ℹ", Fore.GREEN if _COLORAMA else "")
            print(f"\n {symbol} {message}")

    def _print_error(self, message: str) -> None:
        """Print an error message with color.

        Args:
            message: Error message string to display.
        """
        if _RICH and _console:
            _console.print(f"\n [bold red]✗ Error:[/bold red] {message}")
        else:
            symbol = _c("✗ Error:", Fore.RED if _COLORAMA else "")
            print(f"\n {symbol} {message}")

    _MSG_INTERRUPT = "Caught interrupt signal. Exiting gracefully..."

    def _handle_interrupt(self, signum: int, frame: Any) -> None:
        """Handle Ctrl+C interrupt gracefully.

        Args:
            signum: Signal number.
            frame: Current stack frame.
        """
        if _RICH and _console:
            _console.print(f"\n\n [bold yellow]⚠ {self._MSG_INTERRUPT}[/bold yellow]")
        else:
            print(_c(f"\n\n {self._MSG_INTERRUPT}", Fore.YELLOW if _COLORAMA else ""))
        self._running = False

    def _handle_exit(self) -> None:
        """Handle application exit with cleanup."""
        self._running = False
        if _RICH and _console:
            _console.print("\n [dim]Shutting down...[/dim]")
        else:
            print(_c("\n Shutting down...", Fore.YELLOW if _COLORAMA else ""))
        self._session.end_session()
        if _RICH and _console:
            _console.print(" [bold green]Goodbye![/bold green]\n")
        else:
            print(_c(" Goodbye!\n", Fore.GREEN if _COLORAMA else ""))

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format a byte count as a human-readable size string.

        Args:
            size_bytes: Size in bytes.

        Returns:
            Formatted size string (e.g., '1.5 GB').
        """
        if size_bytes <= 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        unit_index = 0
        size = float(size_bytes)
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        return f"{size:.1f} {units[unit_index]}"
