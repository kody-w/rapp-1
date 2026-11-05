#!/usr/bin/env python3
"""Reproduce the pinned source seed, or verify its bytes without using the network."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent
SCHEMA = "rapp-seed/1"
MAX_BYTES = 5_000_000
ENGINE_SHA256 = "bd55a7f0bcf5efd3f7966ca39bb146da3c25fda9a0b1ce5ba587919d3c3775f4"
PINNED_INVENTORY_SHA256 = "c2c69ad14a98779cd2bfaddb351383b220cfad82c671fc0dbdaf0383b1b0c087"
SOURCES = {
    "brainstem": {
        "repo": "kody-w/rapp-installer",
        "ref": "brainstem-v0.6.16",
        "commit": "5fbde1776a72715935c3d597a9ddfce28a04032b",
    },
    "rar": {
        "repo": "kody-w/RAR",
        "ref": "4fa988a479828b177de3ef13838328d6190ff5d2",
        "commit": "4fa988a479828b177de3ef13838328d6190ff5d2",
    },
    "layers": {
        "repo": "kody-w/grail-layers",
        "ref": "db18afbd8b9dcbb620a98ffb311fa1823ddc9e18",
        "commit": "db18afbd8b9dcbb620a98ffb311fa1823ddc9e18",
    },
}
ROOTS = ("brainstem", "rar-builder", "layers")
RAR_ENTRYPOINTS = (
    "build_registry.py",
    "scripts/build_static_api.py",
    "tools/build_agent_pages.py",
    "tools/sync_layers.py",
    "template_agent.py",
)
RAR_INPUTS = ("marketplaces.json", "LAYERS.md")
LAYER_ENTRYPOINTS = (
    "install.sh",
    "grail_layers.py",
    "packs.py",
    "hologram.py",
    "shape_lens.py",
    "rapp.py",
    "brainstem_shape_agent.py",
    "chaos.py",
    "succession.py",
    "succession_drill.py",
    "skills/rar-easy-mode/SKILL.md",
)
SECRET_PATTERNS = {
    "private key": rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "GitHub token": rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b",
    "AWS access key": rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "service API key": rb"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{32,}|AIza[A-Za-z0-9_-]{35})\b",
    "storage account key": rb"\bAccountKey=[A-Za-z0-9+/]{40,}={0,2}",
    "literal credential assignment": (
        rb"""(?im)\b[A-Za-z_]*(?:api_key|access_token|refresh_token|password|secret|account_key)"""
        rb"""[A-Za-z_]*["']?\s*[:=]\s*["']([A-Za-z0-9_+/=.-]{24,})["']"""
    ),
}


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def inventory_fingerprint(manifest: dict) -> str:
    inventory = {key: manifest[key] for key in ("files", "exclusions", "executables")}
    return digest(json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())


def secret_findings(path: str, body: bytes, reviewed: list[str] | None = None) -> list[str]:
    findings = []
    for label, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, body):
            line = body.count(b"\n", 0, match.start()) + 1
            if (
                label == "literal credential assignment"
                and path.endswith("/tests/test_no_copilot_onboarding.py")
                and match.group(1) == b"raw-403-internal-detail-should-never-leak"
            ):
                if reviewed is not None:
                    reviewed.append(f"{path}:{line}: non-secret upstream response-redaction test marker")
                continue
            findings.append(f"{path}:{line}: {label} (value withheld)")
    return findings


def exclusion(path: str, body: bytes) -> str | None:
    parts = PurePosixPath(path).parts
    if any(p in {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "node_modules"}
           for p in parts) or path.endswith((".pyc", ".pyo")):
        return "cache or dependency environment"
    if any(p == ".env" or p.startswith(".env.") for p in parts):
        return "environment file (including examples)"
    if any(p in {".copilot_token", ".copilot_session", ".brainstem_secret", "credentials.json"}
           or p.endswith((".pem", ".key", ".p8", ".p12", ".pfx")) for p in parts):
        return "credential file"
    if len(body) > MAX_BYTES:
        return "larger than 5 MB"
    if secret_findings(path, body):
        return "credential pattern detected"
    return None


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], text=True, stderr=subprocess.PIPE
    ).strip()


def tracked(root: Path, prefix: str) -> list[str]:
    return sorted(p for p in git(root, "ls-files", "--", prefix).splitlines() if p)


def import_closure(root: Path, entrypoints: tuple[str, ...]) -> list[str]:
    """Include local Python imports recursively; never import the upstream code."""
    pending = list(entrypoints)
    found = set()
    while pending:
        name = pending.pop()
        if name in found:
            continue
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing or non-regular source: {name}")
        found.add(name)
        if path.suffix != ".py":
            continue
        for node in ast.walk(ast.parse(path.read_bytes(), filename=name)):
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    raise ValueError(f"{name}: relative import needs an explicit closure rule")
                if node.module:
                    modules = [node.module]
                    modules += [f"{node.module}.{alias.name}" for alias in node.names]
            for module in modules:
                relative = module.replace(".", "/")
                candidates = [relative + ".py", relative + "/__init__.py"]
                candidates += [
                    "/".join(relative.split("/")[:i]) + "/__init__.py"
                    for i in range(1, len(relative.split("/")))
                ]
                pending.extend(p for p in candidates if (root / p).is_file())
    return sorted(found)


def plan(repositories: dict[str, Path]) -> tuple[dict[str, bytes], dict]:
    files = {}
    entries = []
    excluded = []
    executables = []

    def add(source: str, source_path: str, target: str) -> None:
        path = repositories[source] / source_path
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"non-regular source file: {source_path}")
        body = path.read_bytes()
        reason = exclusion(source_path, body)
        provenance = {
            "source_repo": SOURCES[source]["repo"],
            "source_ref": SOURCES[source]["ref"],
            "source_path": source_path,
        }
        if reason:
            excluded.append({**provenance, "reason": reason})
            return
        if target in files:
            raise ValueError(f"duplicate target: {target}")
        files[target] = body
        if path.stat().st_mode & 0o111:
            executables.append(target)
        entries.append({
            "path": target,
            **provenance,
            "sha256": digest(body),
            "bytes": len(body),
        })

    engine = repositories["brainstem"] / "rapp_brainstem/brainstem.py"
    if digest(engine.read_bytes()) != ENGINE_SHA256:
        raise ValueError("Brainstem hash differs from the required v0.6.16 pin; stopped")
    for name in tracked(repositories["brainstem"], "rapp_brainstem/"):
        add("brainstem", name, "brainstem/" + name.removeprefix("rapp_brainstem/"))
    for name in ("install.sh", "install.ps1", "install.cmd"):
        add("brainstem", name, "brainstem/" + name)
    rar_files = sorted(set(import_closure(repositories["rar"], RAR_ENTRYPOINTS)) | set(RAR_INPUTS))
    for name in rar_files:
        add("rar", name, "rar-builder/" + name)
    for name in import_closure(repositories["layers"], LAYER_ENTRYPOINTS):
        add("layers", name, "layers/" + name)
    for name in tracked(repositories["rar"], "stacks/grail-layers/"):
        add("rar", name, "layers/" + name)
    if "brainstem/brainstem.py" not in files:
        raise ValueError("required Brainstem was excluded")
    required = {
        *("rar-builder/" + p for p in rar_files),
        *("layers/" + p for p in import_closure(repositories["layers"], LAYER_ENTRYPOINTS)),
        *("layers/" + p for p in tracked(repositories["rar"], "stacks/grail-layers/")),
        "brainstem/install.sh", "brainstem/install.ps1", "brainstem/install.cmd",
    }
    if required - files.keys():
        raise ValueError(f"required runtime/builder files excluded: {sorted(required - files.keys())}")
    manifest = {
        "schema": SCHEMA,
        "sources": SOURCES,
        "files": sorted(entries, key=lambda e: e["path"]),
        "exclusions": sorted(excluded, key=lambda e: (e["source_repo"], e["source_path"])),
        "executables": sorted(executables),
    }
    return files, manifest


def validate_manifest(manifest: dict) -> list[dict]:
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("invalid seed schema")
    if manifest.get("sources") != SOURCES:
        raise ValueError("manifest sources differ from the refresh script's pins")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("manifest must contain a nonempty file list")
    paths = set()
    refs = {(s["repo"], s["ref"]) for s in SOURCES.values()}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path", "source_repo", "source_ref", "source_path", "sha256", "bytes"
        }:
            raise ValueError("invalid file entry")
        for key in ("path", "source_path"):
            value = entry[key]
            if not isinstance(value, str) or "\\" in value:
                raise ValueError(f"invalid {key}")
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
                raise ValueError(f"unsafe {key}: {value}")
        if PurePosixPath(entry["path"]).parts[0] not in ROOTS:
            raise ValueError(f"file outside generated trees: {entry['path']}")
        if entry["path"] in paths:
            raise ValueError(f"duplicate file: {entry['path']}")
        paths.add(entry["path"])
        if not all(isinstance(entry[key], str) for key in ("source_repo", "source_ref")):
            raise ValueError(f"invalid source: {entry['path']}")
        if (entry["source_repo"], entry["source_ref"]) not in refs:
            raise ValueError(f"unknown source: {entry['path']}")
        if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise ValueError(f"invalid sha256: {entry['path']}")
        if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= MAX_BYTES:
            raise ValueError(f"invalid byte count: {entry['path']}")
    executables = manifest.get("executables")
    if (
        not isinstance(executables, list)
        or not all(isinstance(p, str) and p in paths for p in executables)
        or executables != sorted(set(executables))
    ):
        raise ValueError("invalid executable path list")
    if not isinstance(manifest.get("exclusions"), list):
        raise ValueError("invalid exclusions")
    return entries


def inventory(seed: Path) -> set[str]:
    paths = set()
    for name in ROOTS:
        root = seed / name
        if root.is_symlink() or not root.is_dir():
            raise ValueError(f"generated tree missing or symlinked: {name}")
        for path in root.rglob("*"):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError(f"non-regular generated path: {path.relative_to(seed)}")
            if path.is_file():
                paths.add(path.relative_to(seed).as_posix())
    return paths


def check(seed: Path = HERE, *, scan: bool = False) -> int:
    manifest_path = seed / "SEED.json"
    if manifest_path.is_symlink():
        raise ValueError("manifest must not be a symlink")
    manifest = json.loads(manifest_path.read_bytes())
    entries = validate_manifest(manifest)
    actual = inventory(seed)
    expected = {e["path"] for e in entries}
    errors = [f"unlisted file: {p}" for p in sorted(actual - expected)]
    if inventory_fingerprint(manifest) != PINNED_INVENTORY_SHA256:
        errors.append("manifest differs from the pinned complete source inventory")
    matched = 0
    findings = []
    reviewed = []
    for entry in entries:
        name = entry["path"]
        if name not in actual:
            errors.append(f"missing file: {name}")
            continue
        body = (seed / name).read_bytes()
        if len(body) != entry["bytes"] or digest(body) != entry["sha256"]:
            errors.append(f"fingerprint mismatch: {name}")
        else:
            matched += 1
        if os.name == "posix" and bool((seed / name).stat().st_mode & 0o111) != (name in manifest["executables"]):
            errors.append(f"executable mode mismatch: {name}")
        findings.extend(secret_findings(name, body, reviewed))
        reason = exclusion(name, body)
        if reason:
            errors.append(f"prohibited generated file: {name}: {reason}")
    engine = next((e for e in entries if e["path"] == "brainstem/brainstem.py"), None)
    if engine is None or engine["sha256"] != ENGINE_SHA256:
        errors.append("required Brainstem pin missing or changed")
    if scan:
        for finding in findings:
            print(finding)
        for note in reviewed:
            print(f"Reviewed fixture: {note}")
        print(f"Secret scan: {len(entries)} files scanned; {len(findings)} credential-pattern findings")
    for error in errors:
        print(error, file=sys.stderr)
    print(f"{matched} of {len(entries)} files match")
    return int(bool(errors or findings))


def fetch(destination: Path, source: dict) -> None:
    url = f"https://github.com/{source['repo']}.git"
    if source["ref"] == "brainstem-v0.6.16":
        subprocess.run(
            ["git", "-c", "advice.detachedHead=false", "clone", "--quiet", "--depth", "1",
             "--branch", source["ref"], url, str(destination)], check=True,
        )
    else:
        subprocess.run(["git", "init", "--quiet", str(destination)], check=True)
        subprocess.run(["git", "-C", str(destination), "remote", "add", "origin", url], check=True)
        subprocess.run(
            ["git", "-C", str(destination), "fetch", "--quiet", "--depth", "1", "origin", source["ref"]],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(destination), "checkout", "--quiet", "--detach", "FETCH_HEAD"], check=True,
        )
    if git(destination, "rev-parse", "HEAD") != source["commit"]:
        raise ValueError(f"{source['repo']}: fetched commit differs from the pin")


def refresh(seed: Path = HERE) -> None:
    with tempfile.TemporaryDirectory(prefix="rapp-seed-") as directory:
        repositories = {key: Path(directory) / key for key in SOURCES}
        for key, source in SOURCES.items():
            fetch(repositories[key], source)
        files, manifest = plan(repositories)
        validate_manifest(manifest)
        fingerprint = inventory_fingerprint(manifest)
        if fingerprint != PINNED_INVENTORY_SHA256:
            raise ValueError(
                f"fetched source inventory differs; stopped. Candidate fingerprint: {fingerprint}. "
                "Review the source selection before deliberately updating PINNED_INVENTORY_SHA256."
            )
        # Refuse symlinks before writing anything into an existing generated tree.
        for root in ROOTS:
            if (seed / root).exists() or (seed / root).is_symlink():
                if (seed / root).is_symlink() or not (seed / root).is_dir():
                    raise ValueError(f"unsafe generated tree: {root}")
                for path in (seed / root).rglob("*"):
                    if path.is_symlink() or not (path.is_file() or path.is_dir()):
                        raise ValueError(f"unsafe generated path: {path.relative_to(seed)}")
        if (seed / "SEED.json").is_symlink():
            raise ValueError("manifest must not be a symlink")
        for name, body in files.items():
            path = seed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists() or path.read_bytes() != body:
                path.write_bytes(body)
            path.chmod(0o755 if name in manifest["executables"] else 0o644)
        for root in ROOTS:
            for path in sorted((seed / root).rglob("*"), reverse=True):
                if path.is_file() and path.relative_to(seed).as_posix() not in files:
                    path.unlink()
                elif path.is_dir() and not any(path.iterdir()):
                    path.rmdir()
        rendered = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode()
        path = seed / "SEED.json"
        if not path.exists() or path.read_bytes() != rendered:
            path.write_bytes(rendered)
        print(f"Refreshed {len(files)} files at their pinned refs; {len(manifest['exclusions'])} exclusions")
        for entry in manifest["exclusions"]:
            print(f"Excluded {entry['source_repo']}:{entry['source_path']}: {entry['reason']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify locally; never fetch or write")
    parser.add_argument("--scan", action="store_true", help="also print the credential-pattern scan")
    args = parser.parse_args()
    try:
        if not args.check:
            refresh()
        return check(scan=args.scan)
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError) as error:
        print(f"Seed failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
