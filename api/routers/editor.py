"""
Custom Code Editor API.

Manages custom ingester files (ingester/*_ingester.py) and module files
(modules/*_module.py) that extend the platform without touching the
built-in plugin/module directories.

Directory layout (both mounted as Docker volumes):
  /app/sluice/   — custom ingesters; auto-loaded by PluginLoader alongside built-ins
  /app/anvil/    — custom modules;   auto-loaded by module_task at run time
"""

from __future__ import annotations

import os
import py_compile
import re
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["editor"])

INGESTER_DIR = Path(os.getenv("INGESTER_DIR", "/app/sluice"))
MODULES_DIR = Path(os.getenv("MODULES_DIR", "/app/anvil"))
PLUGINS_DIR = Path(os.getenv("PLUGINS_DIR", "/app/babel"))
MODULES_REG_DIR = Path(__file__).parent.parent / "modules_registry"
# Processor Python files: tasks + utils (the execution engine behind modules/ingestion)
PROCESSOR_DIR = Path(os.getenv("PROCESSOR_DIR", "/app/processor"))

INGESTER_SUFFIX = "_ingester.py"
MODULE_SUFFIX = "_module.py"
PLUGIN_SUFFIX = "_plugin.py"


# ── Helpers ────────────────────────────────────────────────────────────────────


def _ensure(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)


def _safe(base: Path, name: str, suffix: str) -> Path:
    if not name.endswith(suffix):
        raise HTTPException(400, f"File name must end with '{suffix}'")
    if any(c in name for c in ("/", "\\", "..")):
        raise HTTPException(400, "Invalid file name")
    return base / name


def _read_priority(path: Path):
    """Read PLUGIN_PRIORITY integer from first 2 KB of a Python file."""
    try:
        snippet = path.read_bytes()[:2048].decode("utf-8", errors="ignore")
        m = re.search(r"^PLUGIN_PRIORITY\s*=\s*(\d+)", snippet, re.MULTILINE)
        return int(m.group(1)) if m else None
    except OSError:
        return None


def _list(directory: Path, suffix: str, read_priority: bool = False) -> list[dict]:
    _ensure(directory)
    out = []
    for f in sorted(directory.glob(f"*{suffix}")):
        entry: dict = {
            "name": f.name,
            "size": f.stat().st_size,
            "modified": f.stat().st_mtime,
        }
        if read_priority:
            p = _read_priority(f)
            if p is not None:
                entry["priority"] = p
        out.append(entry)
    return out


def _list_recursive(directory: Path, suffix: str) -> list[dict]:
    """Recursive version — returns relative paths for files in subdirectories."""
    if not directory.exists():
        return []
    out = []
    for f in sorted(directory.rglob(f"*{suffix}")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(directory).as_posix()
        out.append(
            {
                "name": rel,
                "size": f.stat().st_size,
                "modified": f.stat().st_mtime,
            }
        )
    return out


def _safe_plugin(base: Path, name: str, suffix: str) -> Path:
    """Resolve a relative plugin path safely (allows subdirs, blocks traversal)."""
    if ".." in name or name.startswith("/"):
        raise HTTPException(400, "Invalid file path")
    if not name.endswith(suffix):
        raise HTTPException(400, f"File name must end with '{suffix}'")
    return base / name


def _read(path: Path) -> str:
    if not path.exists():
        raise HTTPException(404, "File not found")
    return path.read_text(encoding="utf-8")


def _write(path: Path, content: str) -> None:
    _ensure(path.parent)
    path.write_text(content, encoding="utf-8")


def _validate(content: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8") as tf:
        tf.write(content)
        tmp = tf.name
    try:
        py_compile.compile(tmp, doraise=True)
        return {"valid": True}
    except py_compile.PyCompileError as exc:
        # Make the error message relative to the actual file (not tmp path)
        msg = str(exc).replace(tmp, "<editor>")
        return {"valid": False, "error": msg}
    finally:
        os.unlink(tmp)


# ── DTOs ───────────────────────────────────────────────────────────────────────


class FileWrite(BaseModel):
    content: str


class ValidateBody(BaseModel):
    content: str


# ── Ingester CRUD ──────────────────────────────────────────────────────────────


@router.get("/editor/ingesters")
def list_ingesters():
    return {"files": _list(INGESTER_DIR, INGESTER_SUFFIX, read_priority=True)}


@router.get("/editor/ingesters/{name}")
def get_ingester(name: str):
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    return {"name": name, "content": _read(path)}


@router.put("/editor/ingesters/{name}")
def save_ingester(name: str, body: FileWrite):
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    _write(path, body.content)
    return {"saved": True, "name": name}


@router.delete("/editor/ingesters/{name}", status_code=204)
def delete_ingester(name: str):
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()


@router.patch("/editor/ingesters/{name}/priority")
def patch_ingester_priority(name: str, body: dict):
    """Update PLUGIN_PRIORITY value in a custom ingester file."""
    priority = body.get("priority")
    if not isinstance(priority, int) or priority < 0:
        raise HTTPException(400, "priority must be a non-negative integer")
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    content = path.read_text(encoding="utf-8")
    if re.search(r"^PLUGIN_PRIORITY\s*=\s*\d+", content, re.MULTILINE):
        new_content = re.sub(
            r"^(PLUGIN_PRIORITY\s*=\s*)\d+", rf"\g<1>{priority}", content, flags=re.MULTILINE
        )
    else:
        new_content = f"PLUGIN_PRIORITY = {priority}\n" + content
    path.write_text(new_content, encoding="utf-8")
    return {"name": name, "priority": priority}


# ── Module CRUD ────────────────────────────────────────────────────────────────


@router.get("/editor/modules")
def list_modules_editor():
    from routers.modules import _BUILTIN_MODULE_CATEGORIES

    files = _list(MODULES_DIR, MODULE_SUFFIX)
    for f in files:
        module_id = f["name"][: -len(MODULE_SUFFIX)]
        if module_id in _BUILTIN_MODULE_CATEGORIES:
            f["builtin"] = True
    return {"files": files}


@router.get("/editor/modules/{name}")
def get_module_editor(name: str):
    path = _safe(MODULES_DIR, name, MODULE_SUFFIX)
    return {"name": name, "content": _read(path)}


@router.put("/editor/modules/{name}")
def save_module_editor(name: str, body: FileWrite):
    path = _safe(MODULES_DIR, name, MODULE_SUFFIX)
    _write(path, body.content)
    # Invalidate the modules list cache so new/updated modules appear immediately
    try:
        from routers.modules import invalidate_modules_cache

        invalidate_modules_cache()
    except Exception:
        pass
    return {"saved": True, "name": name}


@router.delete("/editor/modules/{name}", status_code=204)
def delete_module_editor(name: str):
    path = _safe(MODULES_DIR, name, MODULE_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()
    try:
        from routers.modules import invalidate_modules_cache

        invalidate_modules_cache()
    except Exception:
        pass


# ── Built-in ingester plugin files (editable) ─────────────────────────────────


@router.get("/editor/builtin-ingesters")
def list_builtin_ingesters():
    """List built-in plugin Python files (recursive — plugins live in subdirs)."""
    return {"files": [dict(f, builtin=True) for f in _list_recursive(PLUGINS_DIR, PLUGIN_SUFFIX)]}


@router.get("/editor/builtin-ingesters/{name:path}")
def get_builtin_ingester(name: str):
    path = _safe_plugin(PLUGINS_DIR, name, PLUGIN_SUFFIX)
    return {"name": name, "content": _read(path), "builtin": True}


@router.put("/editor/builtin-ingesters/{name:path}")
def save_builtin_ingester(name: str, body: FileWrite):
    """Overwrite a built-in plugin file on the plugins PVC."""
    path = _safe_plugin(PLUGINS_DIR, name, PLUGIN_SUFFIX)
    _write(path, body.content)
    return {"saved": True, "name": name, "builtin": True}


@router.delete("/editor/builtin-ingesters/{name:path}", status_code=204)
def delete_builtin_ingester(name: str):
    """Delete a built-in plugin file from the plugins PVC."""
    path = _safe_plugin(PLUGINS_DIR, name, PLUGIN_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()


# ── Built-in module YAML registry files (editable) ────────────────────────────


def _safe_yaml(name: str) -> Path:
    if not name.endswith(".yaml") or any(c in name for c in ("/", "\\", "..")):
        raise HTTPException(400, "Invalid file name — must end with .yaml")
    return MODULES_REG_DIR / name


@router.get("/editor/builtin-modules")
def list_builtin_modules():
    """List module YAML registry files."""
    if not MODULES_REG_DIR.exists():
        return {"files": []}
    files = []
    for f in sorted(MODULES_REG_DIR.glob("*.yaml")):
        files.append(
            {
                "name": f.name,
                "size": f.stat().st_size,
                "modified": f.stat().st_mtime,
                "builtin": True,
            }
        )
    return {"files": files}


@router.get("/editor/builtin-modules/{name}")
def get_builtin_module_file(name: str):
    path = _safe_yaml(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    return {"name": name, "content": path.read_text(encoding="utf-8"), "builtin": True}


@router.put("/editor/builtin-modules/{name}")
def save_builtin_module_file(name: str, body: FileWrite):
    """Overwrite a module YAML registry file."""
    _ensure(MODULES_REG_DIR)
    path = _safe_yaml(name)
    path.write_text(body.content, encoding="utf-8")
    return {"saved": True, "name": name, "builtin": True}


@router.delete("/editor/builtin-modules/{name}", status_code=204)
def delete_builtin_module_file(name: str):
    """Delete a module YAML registry file."""
    path = _safe_yaml(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()


# ── Processor Python files (tasks/ + utils/) ──────────────────────────────────


def _safe_processor(name: str) -> Path:
    if ".." in name or name.startswith("/"):
        raise HTTPException(400, "Invalid file path")
    if not name.endswith(".py"):
        raise HTTPException(400, "File must be a .py file")
    return PROCESSOR_DIR / name


@router.get("/editor/processor-files")
def list_processor_files():
    """List editable processor Python files (tasks/ and utils/)."""
    if not PROCESSOR_DIR.exists():
        return {"files": []}
    files = []
    for subdir in ("tasks", "utils"):
        d = PROCESSOR_DIR / subdir
        if not d.exists():
            continue
        for f in sorted(d.glob("*.py")):
            if f.name.startswith("__"):
                continue
            files.append(
                {
                    "name": f"{subdir}/{f.name}",
                    "size": f.stat().st_size,
                    "modified": f.stat().st_mtime,
                    "builtin": True,
                }
            )
    return {"files": files}


@router.get("/editor/processor-files/{name:path}")
def get_processor_file(name: str):
    path = _safe_processor(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    return {"name": name, "content": path.read_text(encoding="utf-8"), "builtin": True}


@router.put("/editor/processor-files/{name:path}")
def save_processor_file(name: str, body: FileWrite):
    """Overwrite a processor Python file."""
    path = _safe_processor(name)
    _write(path, body.content)
    return {"saved": True, "name": name, "builtin": True}


# ── Shared: syntax validation ──────────────────────────────────────────────────


@router.post("/editor/validate")
def validate_syntax(body: ValidateBody):
    """Check Python syntax without executing. Returns {valid, error?}."""
    return _validate(body.content)
