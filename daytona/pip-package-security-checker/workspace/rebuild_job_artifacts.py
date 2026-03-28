#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_scan_job as runner


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild verdict, summary, and HTML report for an existing scan job.")
    parser.add_argument("--job-id", required=True, help="Existing job id")
    parser.add_argument("--package", required=True, help="Pinned package, e.g. idna==2.7")
    parser.add_argument("--requested-package", help="Original requested package string if different from the resolved package")
    parser.add_argument("--run-dir", required=True, help="Existing run directory for the package")
    args = parser.parse_args()

    job_dir = runner.JOBS_DIR / args.job_id
    logs_dir = job_dir / "logs"
    run_dir = Path(args.run_dir)
    reports_dir = run_dir / "reports"

    overview = runner.build_report_overview(args.package, run_dir, reports_dir)
    vulnerabilities = runner.load_vulnerability_rows(reports_dir)
    verdict_path = runner.run_codex_verdict(args.package, run_dir, reports_dir, logs_dir)
    verdict = runner.read_json(verdict_path)
    summary_path = runner.build_markdown_summary(args.package, verdict, vulnerabilities, reports_dir)
    report_path = runner.render_html_report(args.job_id, args.package, verdict, overview, vulnerabilities, run_dir, reports_dir)
    requested_package = args.requested_package or args.package
    result = runner.build_result(args.job_id, requested_package, args.package, run_dir, job_dir, verdict)
    runner.write_json(job_dir / "result.json", result)
    status = runner.read_json(job_dir / "status.json")
    status.update(
        {
            "state": "completed",
            "phase": "completed",
            "requested_package": requested_package,
            "package": args.package,
            "resolved_package": args.package,
            "summary_path": str(summary_path),
            "verdict_path": str(verdict_path),
            "report_path": str(report_path),
            "decision": verdict["decision"],
            "risk_level": verdict["risk_level"],
            "confidence": verdict["confidence"],
            "malicious": verdict["malicious"],
            "known_vulnerabilities": verdict["known_vulnerabilities"],
        }
    )
    runner.write_json(job_dir / "status.json", status)
    print(
        json.dumps(
            {
                "summary_path": str(summary_path),
                "verdict_path": str(verdict_path),
                "report_path": str(report_path),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
