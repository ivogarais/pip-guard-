#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORKSPACE_DIR = Path("/home/daytona/pip-package-security-checker")
JOBS_DIR = WORKSPACE_DIR / "jobs"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


class Handler(BaseHTTPRequestHandler):
    server_version = "PipGuardDaytona/0.1"

    def _send_json(self, payload: object, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, payload: str, status: int = HTTPStatus.OK) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, payload: str, status: int = HTTPStatus.OK) -> None:
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _job_links(self, job_id: str) -> dict[str, str]:
        return {
            "status_url": f"/scan/{job_id}/status",
            "result_url": f"/scan/{job_id}/result",
            "summary_url": f"/scan/{job_id}/summary",
            "verdict_url": f"/scan/{job_id}/verdict",
            "report_url": f"/scan/{job_id}/report",
        }

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json({"status": "ok", "time": utc_now()})
            return

        if self.path == "/jobs":
            jobs = []
            for status_path in sorted(JOBS_DIR.glob("*/status.json")):
                jobs.append(read_json(status_path))
            self._send_json({"jobs": jobs})
            return

        parts = self.path.strip("/").split("/")
        if len(parts) < 3 or parts[0] != "scan":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        job_id = parts[1]
        action = parts[2]
        job_dir = JOBS_DIR / job_id
        status_payload = read_json(job_dir / "status.json")
        if not status_payload:
            self._send_json({"error": "unknown job"}, status=HTTPStatus.NOT_FOUND)
            return

        if action == "status":
            self._send_json(status_payload)
            return

        if action == "result":
            result_payload = read_json(job_dir / "result.json")
            if not result_payload:
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            enriched_payload = dict(result_payload)
            enriched_payload["links"] = self._job_links(job_id)
            self._send_json(enriched_payload)
            return

        if action == "summary":
            result_payload = read_json(job_dir / "result.json")
            summary_path = result_payload.get("summary_path")
            if not isinstance(summary_path, str):
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            path = Path(summary_path)
            if not path.exists():
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            self._send_text(path.read_text(encoding="utf-8"))
            return

        if action == "verdict":
            result_payload = read_json(job_dir / "result.json")
            verdict_path = result_payload.get("verdict_path")
            if not isinstance(verdict_path, str):
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            path = Path(verdict_path)
            if not path.exists():
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            self._send_json(read_json(path))
            return

        if action == "report":
            result_payload = read_json(job_dir / "result.json")
            report_path = result_payload.get("report_path")
            if not isinstance(report_path, str):
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            path = Path(report_path)
            if not path.exists():
                self._send_json(status_payload, status=HTTPStatus.ACCEPTED)
                return
            self._send_html(path.read_text(encoding="utf-8"))
            return

        self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path != "/scan":
            self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        body = self._json_body()
        package = str(body.get("package", "")).strip()
        if not package:
            self._send_json({"error": "package must be a non-empty requirement string"}, status=HTTPStatus.BAD_REQUEST)
            return

        job_id = uuid.uuid4().hex[:12]
        job_dir = JOBS_DIR / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        write_json(job_dir / "request.json", {"job_id": job_id, "requested_package": package, "package": package, "requested_at": utc_now()})
        write_json(
            job_dir / "status.json",
            {
                "job_id": job_id,
                "requested_package": package,
                "package": package,
                "state": "queued",
                "queued_at": utc_now(),
            },
        )

        log_path = job_dir / "service-launch.log"
        with log_path.open("w", encoding="utf-8") as handle:
            process = subprocess.Popen(
                [sys.executable, str(WORKSPACE_DIR / "tools" / "run_scan_job.py"), "--job-id", job_id, package],
                cwd=WORKSPACE_DIR,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        status_payload = read_json(job_dir / "status.json")
        status_payload.update({"pid": process.pid, "launched_at": utc_now()})
        write_json(job_dir / "status.json", status_payload)

        self._send_json(
            {
                "job_id": job_id,
                "package": package,
                "state": "queued",
                **self._job_links(job_id),
            },
            status=HTTPStatus.ACCEPTED,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve the Daytona package triage worker.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3001)
    args = parser.parse_args()

    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
