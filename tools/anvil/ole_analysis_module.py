"""Alias for oletools_module — same analysis, separate module entry for backward compatibility."""

import sys
from pathlib import Path

# Re-export metadata
MODULE_NAME = "OLE Analysis"
MODULE_DESCRIPTION = (
    "VBA macro and OLE structure analysis via oletools. Alias for the Oletools module."
)
INPUT_EXTENSIONS = [
    ".doc",
    ".docx",
    ".docm",
    ".dot",
    ".dotm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xla",
    ".xlam",
    ".ppt",
    ".pptx",
    ".pptm",
    ".rtf",
    ".mht",
]
INPUT_FILENAMES = []
ARTIFACT_TYPE = "oletools"

# Add modules dir to path so we can import oletools_module
sys.path.insert(0, str(Path(__file__).parent))
from oletools_module import run  # noqa: E402, F401
