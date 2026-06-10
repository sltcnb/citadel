"""Plugin management endpoints."""

import sys
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from config import settings

router = APIRouter(tags=["plugins"])

# Lazy-load the plugin loader to avoid import issues at startup
_loader = None


def get_loader():
    global _loader
    if _loader is None:
        # Add plugins volume to sys.path
        plugins_path = Path(settings.PLUGINS_DIR)
        parent = str(plugins_path.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)

        from plugin_loader import PluginLoader

        _loader = PluginLoader(plugins_path)
        _loader.load()
    return _loader


@router.get("/plugins")
def list_plugins():
    """List all loaded plugins from the plugins volume."""
    try:
        loader = get_loader()
        plugins = loader.list_plugins()
        return {"plugins": plugins, "total": len(plugins)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Plugin discovery failed: {exc}")


@router.post("/plugins/upload")
async def upload_plugin(file: UploadFile = File(...)):
    """
    Upload a Python plugin file (.py) to the plugins directory and reload.
    The filename must follow the convention *_plugin.py so the loader picks it up.
    """
    safe_name = Path(file.filename).name  # strip any path components
    if not safe_name.endswith("_plugin.py"):
        raise HTTPException(
            status_code=400,
            detail="Plugin files must be named *_plugin.py (e.g. my_parser_plugin.py)",
        )

    plugins_path = Path(settings.PLUGINS_DIR)
    plugins_path.mkdir(parents=True, exist_ok=True)
    dest = plugins_path / safe_name
    dest.write_bytes(await file.read())

    # Auto-reload so the new plugin is immediately active
    global _loader
    _loader = None
    loader = get_loader()
    plugins = loader.list_plugins()

    return {
        "message": f"Plugin '{safe_name}' uploaded and loaded",
        "plugins": plugins,
        "total": len(plugins),
    }


@router.post("/plugins/reload")
def reload_plugins():
    """Force a hot-reload of all plugins from the volume."""
    global _loader
    _loader = None
    try:
        loader = get_loader()
        plugins = loader.list_plugins()
        return {
            "message": "Plugins reloaded",
            "plugins": plugins,
            "total": len(plugins),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reload failed: {exc}")
