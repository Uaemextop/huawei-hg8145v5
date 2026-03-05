"""
Interactive CLI for the Motorola Firmware Downloader.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List

import click

from motorola_firmware.authenticator import Authenticator
from motorola_firmware.download_manager import DownloadManager
from motorola_firmware.http_client import HttpClient
from motorola_firmware.logger import get_logger
from motorola_firmware.search_engine import SearchEngine
from motorola_firmware.session_manager import SessionManager
from motorola_firmware.settings import InvalidConfigurationError, Settings
from motorola_firmware.validators import validate_url


class CliApplication:
    """Interactive menu-driven CLI."""

    def __init__(
        self,
        settings: Settings,
        http_client: HttpClient,
        authenticator: Authenticator,
        session_manager: SessionManager,
        search_engine: SearchEngine,
        download_manager: DownloadManager,
    ) -> None:
        self.settings = settings
        self.http_client = http_client
        self.authenticator = authenticator
        self.session_manager = session_manager
        self.search_engine = search_engine
        self.download_manager = download_manager
        self.logger = get_logger(__name__)
        self._last_results: List[dict] = []

    def run(self) -> None:
        """Run the main menu loop."""
        try:
            self.session_manager.start_session()
        except Exception:
            click.echo("Unable to start session. Check credentials.")
            return

        while True:
            click.echo("\nMotorola Firmware Downloader")
            click.echo("1) Buscar firmware/ROM/tools")
            click.echo("2) Descargas pendientes")
            click.echo("3) Configuración")
            click.echo("4) Salir")
            choice = click.prompt("Selecciona una opción", default="1")
            if choice == "1":
                self.search_menu()
            elif choice == "2":
                self.download_menu()
            elif choice == "3":
                self.config_menu()
            elif choice == "4":
                click.echo("Cerrando sesión...")
                self.session_manager.end_session()
                break
            else:
                click.echo("Opción inválida")

    def search_menu(self) -> None:
        """Handle search interactions."""
        query = click.prompt("Ingresa tu búsqueda")
        content_type = click.prompt(
            "Tipo (firmware|rom|tools|all)",
            default="all",
        )
        filters = {}
        region = click.prompt(
            "Región (enter para usar config)",
            default="",
            show_default=False,
        )
        if region:
            filters["region"] = region
        self.session_manager.refresh_if_needed()
        headers = self.authenticator.get_headers()
        self.http_client.set_headers(headers)
        results = self.search_engine.search(query, content_type, filters)
        self._last_results = results
        if not results:
            click.echo("No se encontraron resultados.")
            return
        click.echo("\nResultados:")
        for idx, item in enumerate(results, start=1):
            name = item.get("name") or item.get("id") or "Desconocido"
            ctype = item.get("type", content_type)
            click.echo(f"{idx}) {name} [{ctype}]")

    def download_menu(self) -> None:
        """Allow the user to select downloads from previous results."""
        if not self._last_results:
            click.echo("No hay resultados disponibles. Realiza una búsqueda primero.")
            return
        selection = click.prompt(
            "Selecciona índices separados por coma (ej. 1,2) o 'a' para todos",
            default="a",
        )
        chosen: List[dict] = []
        if selection.lower() == "a":
            chosen = self._last_results
        else:
            indices = {int(i.strip()) for i in selection.split(",") if i.strip().isdigit()}
            for idx in indices:
                if 1 <= idx <= len(self._last_results):
                    chosen.append(self._last_results[idx - 1])
        if not chosen:
            click.echo("No hay elementos seleccionados.")
            return

        items = []
        for item in chosen:
            url = str(item.get("download_url") or item.get("url") or "")
            if not validate_url(url, allow_http=False):
                self.logger.warning("Resultado ignorado por URL inválida")
                continue
            filename = item.get("filename") or item.get("name") or Path(url).name
            items.append({"url": url, "filename": filename})
        if not items:
            click.echo("No hay URLs válidas para descargar.")
            return
        self.session_manager.refresh_if_needed()
        self.http_client.set_headers(self.authenticator.get_headers())
        results = self.download_manager.download_multiple(items)
        success = sum(1 for _, ok in results if ok)
        click.echo(f"Descargas completadas: {success}/{len(results)}")

    def config_menu(self) -> None:
        """Display key configuration values."""
        click.echo("\nConfiguración actual:")
        click.echo(f"Servidor: {self.settings.get('motorola_server', 'base_url')}")
        click.echo(f"GUID configurado: {bool(self.settings.get('motorola_server', 'guid'))}")
        click.echo(
            f"Descargas concurrentes: {self.settings.get_int('download', 'max_concurrent_downloads', 3)}",
        )
        click.echo(f"Directorio de salida: {self.settings.get('download', 'output_directory')}")
        click.echo(f"Región de búsqueda: {self.settings.get('search', 'region', 'us')}")


@click.command()
@click.option(
    "--config",
    "config_path",
    default="config.ini",
    help="Ruta al archivo config.ini",
    show_default=True,
)
def main(config_path: str) -> None:
    """Entry point for CLI."""
    settings = Settings(config_path)
    try:
        settings.load_from_file()
    except (FileNotFoundError, InvalidConfigurationError) as exc:
        click.echo(f"Error cargando configuración: {exc}")
        sys.exit(1)

    log_level = settings.get("logging", "level", "INFO")
    log_file = settings.get("logging", "log_file", "logs/motorola_downloader.log")
    get_logger(__name__, level=log_level, log_file=log_file)

    timeout = settings.get_int("download", "timeout_seconds", 30)
    http_client = HttpClient(timeout=timeout)
    authenticator = Authenticator(settings, http_client)
    session_manager = SessionManager(authenticator)
    search_engine = SearchEngine(settings, http_client)
    download_manager = DownloadManager(settings, http_client)

    app = CliApplication(
        settings=settings,
        http_client=http_client,
        authenticator=authenticator,
        session_manager=session_manager,
        search_engine=search_engine,
        download_manager=download_manager,
    )
    try:
        app.run()
    except KeyboardInterrupt:
        click.echo("\nInterrupción recibida, cerrando sesión.")
        session_manager.end_session()
    finally:
        http_client.close()


if __name__ == "__main__":
    main()
