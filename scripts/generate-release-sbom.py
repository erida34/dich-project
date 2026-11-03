#!/usr/bin/env python3
"""Create an SPDX SBOM from the release package's locked normal/build graph."""

import json
import subprocess
import sys
from pathlib import Path


def run(*args: str, cwd: Path) -> str:
    result = subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True)
    return result.stdout


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} OUTPUT.spdx.json", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parent.parent
    output_path = Path(sys.argv[1]).resolve()
    tree = run(
        "cargo",
        "tree",
        "--locked",
        "-p",
        "dich-cli",
        "--edges",
        "normal,build",
        "--format",
        "{p}",
        "--prefix",
        "none",
        cwd=root,
    )
    included = set()
    for line in tree.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("v"):
            included.add((fields[0], fields[1][1:]))

    raw = run(
        "cargo",
        "sbom",
        "--cargo-package",
        "dich-cli",
        "--output-format",
        "spdx_json_2_3",
        cwd=root,
    )
    document = json.loads(raw)
    if document.get("spdxVersion") != "SPDX-2.3":
        raise SystemExit("cargo-sbom did not produce SPDX 2.3")

    packages = [
        package
        for package in document.get("packages", [])
        if (package.get("name"), package.get("versionInfo")) in included
    ]
    package_ids = {package["SPDXID"] for package in packages}
    main_package = next(
        (package for package in packages if package.get("name") == "dich-cli"),
        None,
    )
    if main_package is None:
        raise SystemExit("SBOM does not describe the dich-cli release package")

    document["packages"] = packages
    document["relationships"] = [
        relationship
        for relationship in document.get("relationships", [])
        if relationship.get("spdxElementId") in package_ids
        and relationship.get("relatedSpdxElement") in package_ids
    ]
    document["relationships"].append(
        {
            "spdxElementId": document["SPDXID"],
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": main_package["SPDXID"],
        }
    )
    document["files"] = []
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"Wrote SPDX 2.3 SBOM with {len(packages)} release dependency components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
