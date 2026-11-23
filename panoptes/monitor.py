"""One monitoring round: probe every target, update the rolling history,
write status.json for the page and sync incident issues.

Usage: python -m panoptes.monitor [config] (data dir from PANOPTES_DATA, default ./data)
"""
import json
import os
import statistics
import sys
import time
from pathlib import Path

from . import incident, slo
from .probe import TLS_WARN_DAYS, is_good, probe_http, security_posture, tls_days_left


def load(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def daily_sli(samples, now, days):
    """SLI per UTC day, oldest first, None for days without data."""
    today = now - now % 86400
    out = []
    for d in range(days - 1, -1, -1):
        start = today - d * 86400
        out.append({"day": time.strftime("%Y-%m-%d", time.gmtime(start)),
                    "sli": slo.sli([s for s in samples if start <= s[0] < start + 86400])})
    return out


def p95(values):
    return round(statistics.quantiles(values, n=20)[-1]) if len(values) >= 2 else (values[0] if values else None)


def build_entry(target, samples, now, interval_s, window_days, tls_days, posture):
    sli = slo.sli(samples)
    last = samples[-1]
    day = slo.window(samples, now, 86400)
    alerts = slo.evaluate_alerts(samples, now, target["slo"])
    down = slo.is_down(samples)
    return {
        "id": target["id"], "name": target["name"], "url": target["url"],
        "slo": target["slo"], "sla": target["sla"], "latency_ms": target["latency_ms"],
        "last": {"ts": last[0], "status": last[1], "ms": last[2], "good": bool(last[3])},
        "sli": sli,
        "slo_budget_left": slo.error_budget_remaining(sli, target["slo"]),
        "sla_budget_left": slo.error_budget_remaining(sli, target["sla"]),
        "sla_met": sli is not None and sli >= target["sla"],
        "p95_ms_24h": p95([s[2] for s in day if s[1]]),
        "alerts": alerts,
        "down": down,
        "incident": down or any(a["firing"] and a["severity"] == "page" for a in alerts),
        "coverage": slo.coverage(samples, now, interval_s),
        "daily": daily_sli(samples, now, window_days),
        "recent": [[s[0], s[2], s[3]] for s in day],
        "security": {"tls_days_left": tls_days,
                     "tls_ok": tls_days is not None and tls_days >= TLS_WARN_DAYS,
                     "headers": posture},
    }


def main():
    cfg = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "targets.json").read_text())
    data = Path(os.environ.get("PANOPTES_DATA", "data"))
    data.mkdir(parents=True, exist_ok=True)
    history = load(data / "history.json", {})
    previous = {t["id"]: t for t in load(data / "status.json", {}).get("targets", [])}
    now = int(time.time())
    interval_s = cfg["probe_interval_minutes"] * 60
    window_s = cfg["window_days"] * 86400
    drill = os.environ.get("PANOPTES_DRILL", "")
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")

    entries, new_history = [], {}
    for t in cfg["targets"]:
        status, ms, headers, body = probe_http(t["url"])
        samples = [s for s in history.get(t["id"], []) if s[0] > now - window_s]
        samples.append([now, status, ms, int(is_good(status, ms, t["latency_ms"]))])
        new_history[t["id"]] = samples
        entry = build_entry(t, samples, now, interval_s, cfg["window_days"], tls_days_left(t["url"], now),
                            security_posture(headers, body, t.get("headers_configurable", True)))
        if drill == t["id"]:  # forces the incident path without touching the SLI data
            entry["drill"] = entry["incident"] = True
        entries.append(entry)
        print(f"{t['id']}: {status} {ms}ms good={samples[-1][3]} sli={entry['sli']:.4f} incident={entry['incident']}")

    for entry in entries:
        if token and repo:
            try:
                incident.sync(repo, token, entry, new_history[entry["id"]], now,
                              previous.get(entry["id"], {}).get("incident"))
            except OSError as e:  # never lose the probe data because the issues API hiccupped
                print(f"incident sync failed for {entry['id']}: {e}")
                entry["incident"] = previous.get(entry["id"], {}).get("incident", False)

    (data / "history.json").write_text(json.dumps(new_history, separators=(",", ":")))
    (data / "status.json").write_text(json.dumps({
        "generated_at": now, "interval_minutes": cfg["probe_interval_minutes"],
        "window_days": cfg["window_days"], "rules": slo.RULES, "min_bad": slo.MIN_BAD,
        "targets": entries,
    }, separators=(",", ":")))


if __name__ == "__main__":
    main()
