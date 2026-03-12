"""
Dynamic plugin system for the web intelligence framework.

Plugins are loaded automatically from this package.  Each plugin must
subclass :class:`BasePlugin` and will be registered on import via the
metaclass.  The :func:`load_plugins` helper discovers and imports every
module inside this package so that all bundled plugins are available
without manual registration.
"""

from web_crawler.plugins.base import BasePlugin, PluginRegistry, load_plugins

__all__ = ["BasePlugin", "PluginRegistry", "load_plugins"]
