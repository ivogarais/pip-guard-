#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib import error, request


def load_daytona_profile() -> tuple[str, str]:
    config_path = Path.home() / "Library" / "Application Support" / "daytona" / "config.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    profile = payload["profiles"][0]
    api = profile["api"]
    token = os.environ.get("DAYTONA_API_KEY") or api["token"] or api["key"]
    api_url = os.environ.get("DAYTONA_API_URL") or api["url"]
    if not token or not api_url:
        raise RuntimeError("could not load Daytona API credentials from env or local config")
    return api_url.rstrip("/"), token


def api_post(url: str, token: str, body: dict[str, object] | None = None) -> dict[str, object] | None:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8").strip()
            return json.loads(text) if text else None
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {details}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure Daytona sandbox lifecycle and optional resources.")
    parser.add_argument("--sandbox", default="pip-package-security-checker", help="Sandbox name or id")
    parser.add_argument("--auto-stop", type=int, default=0, help="Auto-stop interval in minutes; 0 disables it")
    parser.add_argument("--cpu", type=int, help="Optional CPU count for resize")
    parser.add_argument("--memory", type=int, help="Optional memory in GB for resize API")
    parser.add_argument("--disk", type=int, help="Optional disk in GB for resize API")
    args = parser.parse_args()

    api_url, token = load_daytona_profile()
    sandbox = args.sandbox

    results: dict[str, object] = {
        "sandbox": sandbox,
        "auto_stop": api_post(f"{api_url}/sandbox/{sandbox}/autostop/{args.auto_stop}", token),
    }

    resize_body = {}
    if args.cpu is not None:
        resize_body["cpu"] = args.cpu
    if args.memory is not None:
        resize_body["memory"] = args.memory
    if args.disk is not None:
        resize_body["disk"] = args.disk
    if resize_body:
        try:
            results["resize"] = api_post(f"{api_url}/sandbox/{sandbox}/resize", token, resize_body)
        except Exception as exc:
            results["resize_error"] = str(exc)

    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
