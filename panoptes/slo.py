"""SLO math. A sample is [epoch_seconds, http_status, latency_ms, good(0|1)]."""

# Multiwindow, multi-burn-rate rules (Google SRE workbook, ch. 5), stretched to a
# 15-minute probe cadence: the classic 5-minute short window would hold zero samples.
# (name, long window s, short window s, burn-rate factor, severity)
RULES = [
    ("fast", 3600, 1800, 14.4, "page"),
    ("slow", 6 * 3600, 3600, 6.0, "page"),
    ("drift", 3 * 86400, 6 * 3600, 1.0, "ticket"),
]
# With ~4 samples/hour a single failed probe already burns 50x; require two bad
# samples in the long window so one network blip on the runner never pages.
MIN_BAD = 2


def sli(samples):
    """Fraction of good samples, or None when there is no data."""
    if not samples:
        return None
    return sum(s[3] for s in samples) / len(samples)


def error_budget_remaining(sli_value, objective):
    """1 = budget untouched, 0 = fully spent, negative = overspent."""
    if sli_value is None:
        return None
    return 1 - (1 - sli_value) / (1 - objective)


def burn_rate(samples, objective):
    """How many times faster than 'exactly on budget' errors are arriving."""
    if not samples:
        return 0.0
    return (1 - sli(samples)) / (1 - objective)


def window(samples, now, seconds):
    return [s for s in samples if s[0] > now - seconds]


def evaluate_alerts(samples, now, objective):
    out = []
    for name, long_s, short_s, factor, severity in RULES:
        long_w, short_w = window(samples, now, long_s), window(samples, now, short_s)
        long_burn, short_burn = burn_rate(long_w, objective), burn_rate(short_w, objective)
        bad = sum(1 for s in long_w if not s[3])
        out.append({
            "rule": name,
            "severity": severity,
            "long_window_h": long_s / 3600,
            "short_window_h": short_s / 3600,
            "factor": factor,
            "long_burn": round(long_burn, 2),
            "short_burn": round(short_burn, 2),
            "firing": bad >= MIN_BAD and long_burn >= factor and short_burn >= factor,
        })
    return out


def is_down(samples, n=2):
    """Down = the last n probes all failed."""
    return len(samples) >= n and not any(s[3] for s in samples[-n:])


def coverage(samples, now, interval_s):
    """How honest is the SLI? Compare probes received with probes expected since
    the first sample, and report the biggest hole (cron delays/skips)."""
    if not samples:
        return {"observed": 0, "expected": 0, "ratio": None, "max_gap_min": None}
    ts = [s[0] for s in samples]
    expected = (now - ts[0]) // interval_s + 1
    gaps = [b - a for a, b in zip(ts, ts[1:])] + [now - ts[-1]]
    return {
        "observed": len(ts),
        "expected": int(expected),
        "ratio": round(min(1.0, len(ts) / expected), 4),
        "max_gap_min": round(max(gaps) / 60, 1),
    }
