#!/usr/bin/env python3
"""
generate_icons.py - Normalize a custom app icon and regenerate all icon PNGs.

Reads build-system/branding/logo.png (relative to the repo root). If it is
missing, the original icons are kept untouched. Otherwise the legacy icon PNGs
and every PNG inside DefaultAppIcon.xcassets are replaced with a normalized
1024x1024 rendering.
"""
import os
import sys
from PIL import Image

ICON_SPECS = {
    "IconDefault-60@2x.png": (120, 120),
    "IconDefault-60@3x.png": (180, 180),
    "IconDefault-76.png": (76, 76),
    "IconDefault-76@2x.png": (152, 152),
    "IconDefault-83.5@2x.png": (167, 167),
    "IconDefault-Small-40.png": (40, 40),
    "IconDefault-Small-40@2x.png": (80, 80),
    "IconDefault-Small-40@3x.png": (120, 120),
    "IconDefault-Small.png": (29, 29),
    "IconDefault-Small@2x.png": (58, 58),
    "IconDefault-Small@3x.png": (87, 87),
    "IconDefault-1024.png": (1024, 1024),
}

SOURCE_PATH = "build-system/branding/logo.png"
TARGET_DIR = "Telegram/Telegram-iOS"
XCASSETS_DIR = os.path.join(TARGET_DIR, "DefaultAppIcon.xcassets")


def main():
    if not os.path.isfile(SOURCE_PATH):
        print(f"[Icon Step] No custom file found at '{SOURCE_PATH}'. Skipping.")
        return 0

    print(f"[Icon Step] Processing '{SOURCE_PATH}'...")

    with Image.open(SOURCE_PATH) as raw_img:
        # Strip transparency/alpha to adhere to App Store requirements
        img = raw_img.convert("RGB")

        if img.size != (1024, 1024):
            print(f"[Icon Step] Resizing base from {img.size[0]}x{img.size[1]} to 1024x1024...")
            img = img.resize((1024, 1024), Image.Resampling.LANCZOS)

        # 1. Overwrite legacy PNG icons
        for filename, size in ICON_SPECS.items():
            dest = os.path.join(TARGET_DIR, filename)
            resized = img.resize(size, Image.Resampling.LANCZOS)
            resized.save(dest, "PNG")
            print(f" -> Replaced {filename} ({size[0]}x{size[1]})")

        # 2. Overwrite all PNGs inside DefaultAppIcon.xcassets
        if os.path.isdir(XCASSETS_DIR):
            for root, _, files in os.walk(XCASSETS_DIR):
                for file in files:
                    if file.lower().endswith(".png"):
                        target_file = os.path.join(root, file)
                        with Image.open(target_file) as existing_icon:
                            target_size = existing_icon.size
                        resized = img.resize(target_size, Image.Resampling.LANCZOS)
                        resized.save(target_file, "PNG")
                        print(f" -> Replaced Asset Catalog {target_file} ({target_size[0]}x{target_size[1]})")
        else:
            print(f"[Icon Step] '{XCASSETS_DIR}' not found. Skipping asset catalog.")

    print("[Icon Step] All icons updated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())