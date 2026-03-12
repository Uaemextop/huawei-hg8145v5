"""
Plugin system for the web crawler framework.

Plugins are automatically discovered and registered when placed in the
``plugins`` package.  Each plugin module must define a ``register``
function that receives the :class:`PluginRegistry` and calls the
appropriate ``register_*`` method.
"""

from web_crawler.plugins.registry import PluginRegistry

__all__ = ["PluginRegistry"]
