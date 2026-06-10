"""
PluginLoader — discovers and loads BasePlugin subclasses from the plugins volume.

The loader scans the plugins directory for Python modules, imports them, and
collects all classes that inherit from BasePlugin. No manifest file needed.

Usage:
    loader = PluginLoader("/app/babel")
    plugin_class = loader.get_plugin(Path("Security.evtx"), "application/x-winevt")
    plugin = plugin_class(context)
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# Built-in plugins (read-only volume)
PLUGINS_DIR = Path("/app/babel")
# Custom ingesters created via the Studio UI (read-write shared volume)
INGESTER_DIR = Path(os.getenv("INGESTER_DIR", "/app/sluice"))


class PluginLoader:
    def __init__(self, plugins_dir: Path = PLUGINS_DIR, ingester_dir: Path = INGESTER_DIR) -> None:
        self.plugins_dir = plugins_dir
        self.ingester_dir = ingester_dir
        self._plugin_classes: list[type] = []
        self._loaded = False

    def load(self) -> None:
        """Scan built-in plugins/ and custom ingester/ directories."""
        self._plugin_classes = []

        if not self.plugins_dir.exists():
            logger.warning("Plugins directory %s does not exist", self.plugins_dir)
            return

        plugins_str = str(self.plugins_dir)
        if plugins_str not in sys.path:
            sys.path.insert(0, plugins_str)

        parent_str = str(self.plugins_dir.parent)
        if parent_str not in sys.path:
            sys.path.insert(0, parent_str)

        from citadel_contracts import BasePlugin  # noqa: F401

        # Built-in plugins (*_plugin.py)
        for plugin_file in sorted(self.plugins_dir.rglob("*_plugin.py")):
            if plugin_file.name.startswith("_"):
                continue
            self._load_module(plugin_file)

        # Custom ingesters (*_ingester.py) — created via Studio
        if self.ingester_dir.exists():
            for plugin_file in sorted(self.ingester_dir.glob("*_ingester.py")):
                if plugin_file.name.startswith("_"):
                    continue
                self._load_module(plugin_file)
            if list(self.ingester_dir.glob("*_ingester.py")):
                logger.info("Loaded custom ingesters from %s", self.ingester_dir)
        else:
            logger.debug("Custom ingester dir %s not found — skipping", self.ingester_dir)

        # Sort descending by PLUGIN_PRIORITY so high-priority specific parsers
        # are always tried before generic fallbacks (log2timeline, plaso).
        # getattr default=50 keeps old plugins (pre-PLUGIN_PRIORITY) working
        # without a full container rebuild.
        self._plugin_classes.sort(key=lambda c: getattr(c, "PLUGIN_PRIORITY", 50), reverse=True)

        self._loaded = True
        logger.info(
            "Loaded %d plugin class(es): %s",
            len(self._plugin_classes),
            [p.PLUGIN_NAME for p in self._plugin_classes],
        )

    def reload(self) -> None:
        """Force a fresh scan of the plugins directory."""
        self._loaded = False
        self._plugin_classes = []
        self.load()

    def _load_module(self, path: Path) -> None:
        module_name = f"_fo_plugin_{path.stem}_{abs(hash(str(path)))}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                logger.warning("Cannot create spec for %s", path)
                return
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Collect BasePlugin subclasses
            from citadel_contracts import BasePlugin

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj.PLUGIN_NAME != "base"
                    and obj not in self._plugin_classes
                ):
                    self._plugin_classes.append(obj)
                    logger.debug("Registered plugin: %s (from %s)", obj.PLUGIN_NAME, path)

        except Exception as exc:
            logger.error("Failed to load plugin from %s: %s", path, exc, exc_info=True)

    def get_plugin(self, file_path: Path, mime_type: str) -> type | None:
        """
        Return the first plugin class that claims the file, or None if none match.
        """
        if not self._loaded:
            self.load()

        for plugin_class in self._plugin_classes:
            try:
                if plugin_class.can_handle(file_path, mime_type):
                    logger.info(
                        "Plugin %s will handle %s", plugin_class.PLUGIN_NAME, file_path.name
                    )
                    return plugin_class
            except Exception as exc:
                logger.warning("Plugin %s raised in can_handle: %s", plugin_class.PLUGIN_NAME, exc)

        logger.warning("No plugin found for %s (mime: %s)", file_path.name, mime_type)
        return None

    def get_plugin_by_name(self, name: str) -> type | None:
        """Return a plugin class by exact PLUGIN_NAME, ignoring can_handle."""
        if not self._loaded:
            self.load()
        name_lower = name.lower()
        for plugin_class in self._plugin_classes:
            if plugin_class.PLUGIN_NAME.lower() == name_lower:
                return plugin_class
        logger.warning("No plugin named %r found", name)
        return None

    def list_plugins(self) -> list[dict]:
        """Return metadata for all loaded plugins."""
        if not self._loaded:
            self.load()
        return [cls.get_info() for cls in self._plugin_classes]
