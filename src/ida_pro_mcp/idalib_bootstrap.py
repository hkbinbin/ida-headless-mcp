"""Helpers for locating IDA before importing the idapro package."""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path


def _idalib_name() -> str:
    system = platform.system()
    if system == "Windows":
        return "idalib.dll"
    if system == "Darwin":
        return "libidalib.dylib"
    return "libidalib.so"


def is_valid_ida_dir(path: str | os.PathLike[str] | None) -> bool:
    if not path:
        return False
    ida_dir = Path(path)
    return ida_dir.is_dir() and (ida_dir / _idalib_name()).is_file()


def _ida_config_path() -> Path:
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Hex-Rays" / "IDA Pro" / "ida-config.json"
    return Path.home() / ".idapro" / "ida-config.json"


def find_configured_ida_dir() -> str | None:
    """Return the IDA directory from Hex-Rays' idalib activation config."""
    config_path = _ida_config_path()
    if not config_path.is_file():
        return None

    try:
        with config_path.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    ida_dir = config.get("Paths", {}).get("ida-install-dir")
    if is_valid_ida_dir(ida_dir):
        return str(Path(ida_dir).resolve())
    return None


def ensure_idadir(ida_dir: str | os.PathLike[str] | None = None) -> str | None:
    """Ensure IDADIR is set when it can be discovered safely."""
    if ida_dir is not None:
        resolved = str(Path(ida_dir).resolve())
        if is_valid_ida_dir(resolved):
            os.environ["IDADIR"] = resolved
            return resolved
        return None

    current = os.environ.get("IDADIR")
    if is_valid_ida_dir(current):
        return str(Path(current).resolve())

    configured = find_configured_ida_dir()
    if configured:
        os.environ["IDADIR"] = configured
        return configured

    return None
