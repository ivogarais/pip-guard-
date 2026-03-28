#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

PINNED_SPEC_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)\s*$")


@dataclass(frozen=True)
class Artifact:
    filename: str
    url: str
    packagetype: str


@dataclass(frozen=True)
class ResolvedRequirement:
    requested_spec: str
    exact_requirement: str
    package_name: str
    version: str


def cache_key(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip("-").lower()


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(cmd, text=True, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(
            "command failed: "
            + " ".join(cmd)
            + f"\nexit code: {completed.returncode}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def read_cached_json(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def curl_text(url: str) -> str:
    cmd = [
        "curl",
        "--connect-timeout",
        "5",
        "--max-time",
        "45",
        "--retry",
        "4",
        "--retry-delay",
        "1",
        "--retry-connrefused",
        "-fsSL",
        url,
    ]
    return run(cmd).stdout


def fetch_json(url: str, cache_path: Path) -> dict[str, object]:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = json.loads(curl_text(url))
    except Exception:
        cached = read_cached_json(cache_path)
        if cached is not None:
            return cached
        raise
    cache_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def download_with_cache(url: str, target: Path, cache_path: Path) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not cache_path.exists():
        cmd = [
            "curl",
            "--connect-timeout",
            "5",
            "--max-time",
            "120",
            "--retry",
            "4",
            "--retry-delay",
            "1",
            "--retry-connrefused",
            "-fsSL",
            "-o",
            str(cache_path),
            url,
        ]
        try:
            run(cmd)
        except Exception:
            if not cache_path.exists():
                raise
    shutil.copy2(cache_path, target)


def parse_pin(spec: str) -> tuple[str, str]:
    match = PINNED_SPEC_RE.match(spec)
    if not match:
        raise ValueError("expected an exact pinned requirement like package==1.2.3")
    return match.group(1), match.group(2)


def slugify(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._-") or "package"


def requirement_to_exact(req: Requirement, version: str) -> str:
    extras = ""
    if req.extras:
        extras = "[" + ",".join(sorted(req.extras)) + "]"
    marker = f"; {req.marker}" if req.marker else ""
    return f"{req.name}{extras}=={version}{marker}"


def get_exact_pin_from_requirement(req: Requirement) -> str | None:
    specs = list(req.specifier)
    if len(specs) != 1:
        return None
    spec = specs[0]
    if spec.operator != "==" or "*" in spec.version:
        return None
    return spec.version


def select_matching_version(req: Requirement, releases: dict[str, object]) -> str:
    candidates: dict[Version, str] = {}
    for version_text, files in releases.items():
        if not isinstance(files, list) or not files:
            continue
        file_entries = [entry for entry in files if isinstance(entry, dict)]
        if file_entries and all(bool(entry.get("yanked")) for entry in file_entries):
            continue
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue
        candidates[version] = version_text
    if not candidates:
        raise RuntimeError(f"no usable releases found for {req.name}")
    versions = sorted(candidates.keys(), reverse=True)
    if req.specifier:
        filtered = list(req.specifier.filter(versions, prereleases=req.specifier.prereleases))
    else:
        filtered = [version for version in versions if not version.is_prerelease] or versions
    if not filtered:
        raise RuntimeError(f"no release matches requested specifier for {req.name}")
    return candidates[filtered[0]]


def resolve_requirement(spec: str, cache_root: Path) -> ResolvedRequirement:
    try:
        req = Requirement(spec)
    except InvalidRequirement as exc:
        raise ValueError(f"invalid package requirement: {spec}") from exc
    exact_version = get_exact_pin_from_requirement(req)
    if exact_version:
        return ResolvedRequirement(
            requested_spec=spec,
            exact_requirement=requirement_to_exact(req, exact_version),
            package_name=req.name,
            version=exact_version,
        )
    package_cache = cache_root / cache_key(req.name) / "index.json"
    package_payload = fetch_json(f"https://pypi.org/pypi/{quote(req.name, safe='')}/json", package_cache)
    releases = package_payload.get("releases", {})
    if not isinstance(releases, dict):
        raise RuntimeError(f"unexpected PyPI package metadata shape for {req.name}")
    selected_version = select_matching_version(req, releases)
    return ResolvedRequirement(
        requested_spec=spec,
        exact_requirement=requirement_to_exact(req, selected_version),
        package_name=req.name,
        version=selected_version,
    )


def select_artifacts(payload: dict[str, object]) -> list[Artifact]:
    urls = [entry for entry in payload.get("urls", []) if isinstance(entry, dict)]
    sdist = next((entry for entry in urls if entry.get("packagetype") == "sdist"), None)
    wheels = [entry for entry in urls if entry.get("packagetype") == "bdist_wheel"]
    preferred_wheel = next((entry for entry in wheels if "py3-none-any" in str(entry.get("filename", ""))), None)
    if preferred_wheel is None and wheels:
        preferred_wheel = wheels[0]

    selected: list[Artifact] = []
    for entry in (sdist, preferred_wheel):
        if not entry:
            continue
        artifact = Artifact(
            filename=str(entry["filename"]),
            url=str(entry["url"]),
            packagetype=str(entry.get("packagetype", "unknown")),
        )
        if artifact not in selected:
            selected.append(artifact)
    if not selected:
        raise RuntimeError("no sdist or wheel found for resolved release")
    return selected


def artifact_dir_name(filename: str) -> str:
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".whl", ".zip", ".tgz", ".tar"):
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    return Path(filename).stem


def unpack(artifact: Path, destination_root: Path) -> Path:
    target = destination_root / artifact_dir_name(artifact.name)
    target.mkdir(parents=True, exist_ok=True)
    name = artifact.name
    if name.endswith(".whl") or name.endswith(".zip"):
        with zipfile.ZipFile(artifact) as zf:
            zf.extractall(target)
    elif any(name.endswith(suffix) for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tar")):
        with tarfile.open(artifact) as tf:
            tf.extractall(target)
    else:
        shutil.copy2(artifact, target / artifact.name)
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description="Download and unpack a PyPI release without installing it.")
    parser.add_argument("package", help="Requirement spec, e.g. urllib3, urllib3>=1.26, or urllib3==1.25.0")
    parser.add_argument("--output-dir", default="runs", help="Directory for staged artifacts")
    parser.add_argument("--cache-dir", default="runtime/pypi-cache", help="Directory for reusable PyPI metadata and files")
    args = parser.parse_args()

    cache_root = Path(args.cache_dir).resolve()
    resolved = resolve_requirement(args.package, cache_root)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    root = Path(args.output_dir).resolve() / f"{slugify(resolved.exact_requirement)}-{timestamp}"
    downloads_dir = root / "downloads"
    extracted_dir = root / "artifacts"
    reports_dir = root / "reports"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    extracted_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    metadata_cache = cache_root / cache_key(resolved.package_name) / resolved.version / "metadata.json"
    metadata_url = f"https://pypi.org/pypi/{quote(resolved.package_name, safe='')}/{quote(resolved.version, safe='')}/json"
    payload = fetch_json(metadata_url, metadata_cache)
    artifacts = select_artifacts(payload)

    records: list[dict[str, str]] = []
    for artifact in artifacts:
        target = downloads_dir / artifact.filename
        cached_artifact = cache_root / cache_key(resolved.package_name) / resolved.version / "downloads" / artifact.filename
        download_with_cache(artifact.url, target, cached_artifact)
        unpacked = unpack(target, extracted_dir)
        records.append({
            "filename": artifact.filename,
            "url": artifact.url,
            "packagetype": artifact.packagetype,
            "download_path": str(target),
            "cache_path": str(cached_artifact),
            "unpacked_path": str(unpacked),
        })

    requirements_file = root / "requirements.txt"
    requirements_file.write_text(resolved.exact_requirement + "\n", encoding="utf-8")

    summary = {
        "requested_package": args.package,
        "package": resolved.exact_requirement,
        "resolved_package": resolved.exact_requirement,
        "resolved_name": resolved.package_name,
        "resolved_version": resolved.version,
        "cache_dir": str(cache_root),
        "root": str(root),
        "downloads_dir": str(downloads_dir),
        "artifacts_dir": str(extracted_dir),
        "reports_dir": str(reports_dir),
        "requirements_file": str(requirements_file),
        "artifacts": records,
    }
    (reports_dir / "stage.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
