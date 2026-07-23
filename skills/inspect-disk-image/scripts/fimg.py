#!/usr/bin/env python3
"""Install or invoke the native fimg binary."""

from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path


REPOSITORY = "gkdms04/forensic-image-cli"


def install_dir() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return root / "fimg" / "bin"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "fimg" / "bin"


def binary_name() -> str:
    return "fimg.exe" if os.name == "nt" else "fimg"


def find_binary() -> Path | None:
    configured = os.environ.get("FIMG_BIN")
    candidates = [
        Path(configured).expanduser() if configured else None,
        Path(shutil.which("fimg") or "") if shutil.which("fimg") else None,
        install_dir() / binary_name(),
    ]
    return next((path for path in candidates if path and path.is_file()), None)


def install() -> Path:
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"}:
        raise RuntimeError(f"No prebuilt release for architecture: {machine}")
    asset_name = "fimg-windows-x86_64.exe" if os.name == "nt" else "fimg-linux-x86_64"
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "fimg-skill"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    asset = next((item for item in release.get("assets", []) if item["name"] == asset_name), None)
    if not asset:
        raise RuntimeError(f"Release asset not found: {asset_name}")

    destination = install_dir() / binary_name()
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    try:
        download = urllib.request.Request(
            asset["browser_download_url"], headers={"User-Agent": "fimg-skill"}
        )
        with urllib.request.urlopen(download, timeout=120) as response, partial.open("wb") as output:
            shutil.copyfileobj(response, output)
        partial.chmod(partial.stat().st_mode | stat.S_IXUSR)
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)
    print(f"Installed: {destination}")
    return destination


def main() -> int:
    if sys.argv[1:] == ["--install"]:
        install()
        return 0
    binary = find_binary()
    if binary is None:
        print(
            "fimg is not installed. Run: python scripts/fimg.py --install",
            file=sys.stderr,
        )
        return 2
    return subprocess.run([str(binary), *sys.argv[1:]], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())

