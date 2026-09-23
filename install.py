#!/usr/bin/env python3
"""pAIn installer — multi-platform."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

TOOL_NAME = "pAIn"
MIN_PYTHON = (3, 10)

INSTALL_DIR = Path("/opt/pr0t31n/pAIn")


def _run(cmd, check: bool = True, **kw):
    display = " ".join(cmd) if isinstance(cmd, list) else cmd
    print(f"  → {display}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check, **kw)


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


def _pip_installed(pkg_spec):
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "Pillow": "PIL", "pillow-heif": "pillow_heif",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


# ── Python version check ──────────────────────────────────────────────────────
if sys.version_info < MIN_PYTHON:
    print(f"ERROR: Python {'.'.join(map(str, MIN_PYTHON))}+ required "
          f"(found {sys.version_info.major}.{sys.version_info.minor})")
    sys.exit(1)


def install_system_deps():
    """Install system packages for ffmpeg and espeak."""
    print("\n[1] System dependencies")

    # ffmpeg — required for most audio format generation
    if _has("ffmpeg"):
        print("  ✓ ffmpeg already installed")
    else:
        print("  Installing ffmpeg ...")
        if sys.platform.startswith("linux") and _has("apt-get"):
            _run(["apt-get", "install", "-y", "ffmpeg"], check=False)
        elif sys.platform == "darwin" and _has("brew"):
            _run(["brew", "install", "ffmpeg"], check=False)
        else:
            print("  ! Could not auto-install ffmpeg — install manually")

    # espeak-ng — optional, for audio speech injection
    if _has("espeak-ng") or _has("espeak"):
        print("  ✓ espeak already installed")
    else:
        print("  Installing espeak-ng (optional — audio speech injection) ...")
        if sys.platform.startswith("linux") and _has("apt-get"):
            _run(["apt-get", "install", "-y", "espeak-ng"], check=False)
        elif sys.platform == "darwin" and _has("brew"):
            _run(["brew", "install", "espeak"], check=False)
        else:
            print("  ! espeak not auto-installed — audio spoken-payload tests will be skipped")


def install_pip_deps():
    """Install Python packages."""
    print("\n[2] Python packages")
    req = INSTALL_DIR / "requirements.txt"
    if req.exists():
        packages = [line.strip() for line in req.read_text().splitlines()
                    if line.strip() and not line.startswith("#")]
    else:
        packages = [
            "requests>=2.28.0",
            "Pillow>=10.0.0",
            "piexif>=1.1.3",
            "reportlab>=4.0.0",
            "mutagen>=1.47.0",
            "pillow-heif>=0.13.0",
            "colorama>=0.4.6",
        ]
    missing = []
    for pkg in packages:
        if _pip_installed(pkg):
            print(f"  ✓ {pkg} already installed")
        else:
            missing.append(pkg)
    if not missing:
        print("  All Python packages already installed")
        return
    _run([sys.executable, "-m", "pip", "install",
          "--break-system-packages"] + missing,
         check=False)


def create_dirs():
    """Create runtime directories."""
    print("\n[3] Directories")
    for d in [INSTALL_DIR / "pain_output"]:
        d.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {d}")


def main():
    print(f"\n{TOOL_NAME} — Installation")
    print("=" * 40)
    install_system_deps()
    install_pip_deps()
    create_dirs()
    print(f"\n{TOOL_NAME} installed.")
    print(f"  Run: python3 {INSTALL_DIR}/pain.py --help")
    print(f"  Example: python3 {INSTALL_DIR}/pain.py --target config.json")
    print(f"  Dry run: python3 {INSTALL_DIR}/pain.py --dry-run --formats pdf,png,mp3\n")


if __name__ == "__main__":
    main()
