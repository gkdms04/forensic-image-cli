#!/usr/bin/env python3
"""Install or invoke the native fimg binary."""

from __future__ import annotations

import hashlib
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


def asset_name() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        arch = "x86_64"
    elif machine in {"arm64", "aarch64"}:
        arch = "aarch64"
    else:
        raise RuntimeError(f"No prebuilt release for architecture: {machine}")

    if system == "Windows":
        if arch != "x86_64":
            raise RuntimeError(f"No prebuilt Windows release for architecture: {machine}")
        return "fimg-windows-x86_64.exe"
    if system == "Linux":
        return f"fimg-linux-{arch}"
    if system == "Darwin":
        return f"fimg-macos-{arch}"
    raise RuntimeError(f"No prebuilt release for platform: {system}")


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


def download_bytes(url: str, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "fimg-skill"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def expected_digest(sums: str, name: str) -> str:
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == name:
            return parts[0].lower()
    raise RuntimeError(f"No checksum for {name} in SHA256SUMS")


def install() -> Path:
    wanted = asset_name()
    request = urllib.request.Request(
        f"https://api.github.com/repos/{REPOSITORY}/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "fimg-skill"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    assets = {item["name"]: item["browser_download_url"] for item in release.get("assets", [])}
    if wanted not in assets:
        raise RuntimeError(f"Release asset not found: {wanted}")
    if "SHA256SUMS" not in assets:
        raise RuntimeError("Release is missing SHA256SUMS; refusing to install unverified binary")

    sums = download_bytes(assets["SHA256SUMS"], timeout=30).decode("utf-8")
    expected = expected_digest(sums, wanted)
    payload = download_bytes(assets[wanted], timeout=120)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise RuntimeError(
            f"Checksum mismatch for {wanted}: expected {expected}, got {actual}"
        )

    destination = install_dir() / binary_name()
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    try:
        partial.write_bytes(payload)
        partial.chmod(partial.stat().st_mode | stat.S_IXUSR)
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)
    print(f"Installed: {destination} (sha256 {actual})")
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

