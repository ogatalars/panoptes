"""Summarise Trivy + Semgrep JSON reports into data/security.json (counts only:
the page is public, so no file paths or secret snippets are published).

Usage: python -m panoptes.scan <reports dir> <output json>
Reports are named trivy-<repo>.json and semgrep-<repo>.json.
"""
import json
import sys
import time
from collections import Counter
from pathlib import Path


def trivy_counts(report):
    c = {"vulnerabilities": Counter(), "secrets": Counter(), "misconfigurations": Counter()}
    for result in report.get("Results") or []:
        for key, field in (("vulnerabilities", "Vulnerabilities"), ("secrets", "Secrets"),
                           ("misconfigurations", "Misconfigurations")):
            c[key].update(f.get("Severity", "UNKNOWN") for f in result.get(field) or [])
    return {k: dict(v) for k, v in c.items()}


def semgrep_counts(report):
    return dict(Counter(r.get("extra", {}).get("severity", "UNKNOWN") for r in report.get("results", [])))


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None  # tool failed for this repo; shown as "not scanned"


def main(reports_dir, out):
    reports = Path(reports_dir)
    repos = sorted({p.stem.split("-", 1)[1] for p in reports.glob("*.json")})
    summary = []
    for repo in repos:
        trivy, semgrep = load(reports / f"trivy-{repo}.json"), load(reports / f"semgrep-{repo}.json")
        summary.append({
            "repo": repo,
            "trivy": trivy_counts(trivy) if trivy is not None else None,
            "semgrep": semgrep_counts(semgrep) if semgrep is not None else None,
        })
    Path(out).write_text(json.dumps({"generated_at": int(time.time()), "repos": summary}, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:3])
