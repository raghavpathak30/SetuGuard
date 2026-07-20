#!/usr/bin/env python3
"""
Parse F-Droid's index-v2.json and extract direct APK download URLs,
one per package (latest version only), for bulk download via aria2c.

Usage:
    python3 parse_fdroid_index.py index-v2.json fdroid_urls.txt [max_count]
"""
import json
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 parse_fdroid_index.py <index-v2.json> <output.txt> [max_count]")
        sys.exit(1)

    index_path = sys.argv[1]
    output_path = sys.argv[2]
    max_count = int(sys.argv[3]) if len(sys.argv) > 3 else None

    with open(index_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    packages = data.get("packages", {})
    base_url = "https://f-droid.org/repo"

    urls = []
    for app_id, pkg_data in packages.items():
        versions = pkg_data.get("versions", {})
        if not versions:
            continue

        # pick the version with the highest versionCode (latest release)
        best_version = None
        best_code = -1
        for version_hash, version_data in versions.items():
            manifest = version_data.get("manifest", {})
            version_code = manifest.get("versionCode", 0)
            if version_code > best_code:
                best_code = version_code
                best_version = version_data

        if best_version is None:
            continue

        file_info = best_version.get("file", {})
        file_name = file_info.get("name")
        if not file_name:
            continue

        urls.append(f"{base_url}{file_name}")

        if max_count and len(urls) >= max_count:
            break

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(urls) + "\n")

    print(f"Wrote {len(urls)} APK URLs to {output_path}")

if __name__ == "__main__":
    main()
