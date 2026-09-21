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

def main():
    source_path = "build-system/branding/logo.png"
    target_dir = "Telegram/Telegram-iOS"

    if not os.path.isfile(source_path):
        print(f"[Icon Generator] '{source_path}' not found. Skipping icon generation.")
        return

    print(f"[Icon Generator] Found '{source_path}'. Normalizing and generating icons...")

    with Image.open(source_path) as raw_img:
        # Strip transparency/alpha to adhere to App Store requirements
        img = raw_img.convert("RGB")

        # Force normalize/rescale to 1024x1024 if the base input differs
        if img.size != (1024, 1024):
            print(f"[Icon Generator] Rescaling source from {img.size[0]}x{img.size[1]} to 1024x1024...")
            img = img.resize((1024, 1024), Image.Resampling.LANCZOS)

        # Export each dimension
        for filename, size in ICON_SPECS.items():
            out_path = os.path.join(target_dir, filename)
            resized = img.resize(size, Image.Resampling.LANCZOS)
            resized.save(out_path, "PNG")
            print(f" -> Generated {filename} ({size[0]}x{size[1]})")

    print("[Icon Generator] Successfully updated all application icons.")

if __name__ == "__main__":
    main()