#!/usr/bin/env python3
"""Qualify and package the exact Linux/amd64 executable from a built image."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=True, text=True, **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sudo", action="store_true")
    args = parser.parse_args()
    if not args.image or args.image.startswith("-"):
        parser.error("provide an image name or immutable digest")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("qualification supports only Linux x86_64")
    docker = ["sudo", "docker"] if args.sudo else ["docker"]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    expected = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    for name in ("client-qualification.json", "mcp-infisical-rs-linux-x86_64.tar.gz", "compiler.txt"):
        (output / name).unlink(missing_ok=True)
    container = run([*docker, "create", args.image], capture_output=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise ValueError("Docker did not return a container identifier")
    with tempfile.TemporaryDirectory(prefix="infisical-qualification-") as directory:
        extracted = Path(directory)
        binary = extracted / "mcp-infisical-rs"
        compiler = extracted / "rustc.txt"
        try:
            image_id = run([*docker, "container", "inspect", "--format", "{{.Image}}", container],
                           capture_output=True).stdout.strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                raise ValueError("Docker did not return an immutable image ID")
            run([*docker, "cp", f"{container}:/mcp-infisical-rs", str(binary)])
            run([*docker, "cp", f"{container}:/usr/share/mcp-rustc.txt", str(compiler)])
        finally:
            run([*docker, "rm", "-v", container], capture_output=True)
        compiler_text = compiler.read_text()
        if compiler_text.splitlines()[0].split()[1] != expected:
            raise ValueError("image compiler differs from the repository toolchain")
        environment = dict(os.environ, INFISICAL_QUALIFICATION_BINARY=str(binary))
        with (output / "client-qualification.log").open("w") as log:
            run(["cargo", "test", "--locked", "-p", "infisical-server", "--test", "standalone"],
                cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
        archive = output / "mcp-infisical-rs-linux-x86_64.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(binary, arcname="mcp-infisical-rs")
            bundle.add(compiler, arcname="rustc.txt")
            for name in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                bundle.add(ROOT / name, arcname=name)
        (output / "compiler.txt").write_text(compiler_text)
        (output / "client-qualification.json").write_text(json.dumps({
            "image": args.image,
            "imageId": image_id,
            "platform": "linux/amd64",
            "kernel": platform.release(),
            "libc": platform.libc_ver(),
            "client": "repository JSON-RPC stdio and reqwest Streamable HTTP fixtures",
            "test": "infisical-server/standalone",
            "exit": 0,
            "nativeArchive": archive.name,
        }, indent=2) + "\n")
    print("image executable qualification: EXIT=0")


if __name__ == "__main__":
    main()
