"""Shared constants for Hermes Agent.

Import-safe module with no dependencies — can be imported from anywhere
without risk of circular imports.
"""
import os
from pathlib import Path

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_MODELS_URL = f"{OPENROUTER_BASE_URL}/models"
OPENROUTER_CHAT_URL = f"{OPENROUTER_BASE_URL}/chat/completions"


def get_hermes_dir(*subpaths: str, fallback: str = ".hermes") -> Path:
    """Get the Hermes directory path with optional subpaths.

    Args:
        *subpaths: Optional subdirectories to append
        fallback: Fallback directory name if HERMES_HOME is not set

    Returns:
        Path to the Hermes directory (with subpaths if provided)
    """
    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home:
        base_path = Path(hermes_home)
    else:
        base_path = Path.home() / fallback

    result = base_path
    for subpath in subpaths:
        result = result / subpath

    return result
