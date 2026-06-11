"""
PluginLoader — discovers and loads BasePlugin subclasses from the plugins volume.

Standalone copy for use in the API container (which does not include the
processor package).  Identical logic to processor/plugin_loader.py.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

PLUGINS_DIR = Path("/app/babel")
INGESTER_DIR = Path(os.getenv("INGESTER_DIR", "/app/sluice"))


def _is_template_path(path: Path) -> bool:
    """True for cookiecutter / scaffolding paths that hold un-rendered source."""
    s = str(path)
    return "{{" in s or "cookiecutter" in s or f"{os.sep}template{os.sep}" in s


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

        # Built-in plugins (*_plugin.py under plugins/). Skip scaffolding
        # templates — cookiecutter dirs hold un-rendered `{{ }}` source that is
        # not valid Python and must never be imported as a real plugin.
        for plugin_file in sorted(self.plugins_dir.rglob("*_plugin.py")):
            if plugin_file.name.startswith("_"):
                continue
            if _is_template_path(plugin_file):
                continue
            self._load_module(plugin_file)

        # Custom ingesters (*_ingester.py under ingester/)
        if self.ingester_dir.exists():
            for plugin_file in sorted(self.ingester_dir.glob("*_ingester.py")):
                if plugin_file.name.startswith("_"):
                    continue
                self._load_module(plugin_file)
        else:
            logger.debug("Custom ingester directory %s not found — skipping", self.ingester_dir)

        self._loaded = True
        logger.info(
            "Loaded %d plugin class(es): %s",
            len(self._plugin_classes),
            [p.PLUGIN_NAME for p in self._plugin_classes],
        )

    def reload(self) -> None:
        self._loaded = False
        self._plugin_classes = []
        self.load()

    def _load_module(self, path: Path) -> None:
        module_name = f"_fo_plugin_{path.stem}_{abs(hash(str(path)))}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                return
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            from citadel_contracts import BasePlugin

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj.PLUGIN_NAME != "base"
                    and obj not in self._plugin_classes
                ):
                    # Record the file each class came from so the UI can open
                    # the exact source in Studio (PLUGIN_NAME != filename stem).
                    obj.__source_file__ = path.name
                    self._plugin_classes.append(obj)
        except Exception as exc:
            logger.error("Failed to load plugin from %s: %s", path, exc, exc_info=True)

    def get_plugin(self, file_path: Path, mime_type: str) -> type | None:
        if not self._loaded:
            self.load()
        for plugin_class in self._plugin_classes:
            try:
                if plugin_class.can_handle(file_path, mime_type):
                    return plugin_class
            except Exception as exc:
                logger.warning("Plugin %s.can_handle() raised: %s", plugin_class.__name__, exc)
        return None

    def list_plugins(self) -> list[dict]:
        if not self._loaded:
            self.load()
        out = []
        for cls in self._plugin_classes:
            info = cls.get_info()
            # Source filename (set in _load_module) lets the UI open the exact
            # file in Studio — PLUGIN_NAME is a display name, not the filename.
            info["source_file"] = getattr(cls, "__source_file__", None)
            out.append(info)
        return out
