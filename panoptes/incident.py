"""Open / update / close one GitHub incident issue per target, with an optional
LLM-drafted postmortem. The model only writes text into the issue body."""
import json
import os
import time
import urllib.request

API = "https://api.github.com"
LABEL = "incident"


def gh(method, path, token, body=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read() or b"null")


def title_for(entry):
    return f"[incident] {entry['name']}"


def find_open_issue(repo, token, title):
    issues = gh("GET", f"/repos/{repo}/issues?state=open&labels={LABEL}&per_page=100", token)
    return next((i for i in issues if i["title"] == title), None)


def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


def timeline(samples, now, hours=6):
    """Markdown table of the probes in the last `hours`, failures first-class."""
    rows = ["| time | status | latency | result |", "|---|---|---|---|"]
    for ts, status, ms, good in samples:
        if ts > now - hours * 3600:
            rows.append(f"| {fmt_ts(ts)} | {status or 'no response'} | {ms} ms | {'ok' if good else '**bad**'} |")
    return "\n".join(rows)


def triggers(entry):
    out = ["target down (last 2 probes failed)"] if entry["down"] else []
    out += [f"burn-rate alert '{a['rule']}' ({a['long_burn']}x over {a['long_window_h']:g}h)"
            for a in entry["alerts"] if a["firing"] and a["severity"] == "page"]
    if entry.get("drill"):
        out.append("manual drill (workflow_dispatch), not a real outage")
    return "; ".join(out) or "unknown"


def facts(entry):
    return "\n".join([
        f"- **Target:** {entry['url']}",
        f"- **Trigger:** {triggers(entry)}",
        f"- **Last probe:** {entry['last']['status'] or 'no response'} in {entry['last']['ms']} ms"
        f" (threshold {entry['latency_ms']} ms)",
        f"- **SLI 30d:** {pct(entry['sli'])} | SLO {pct(entry['slo'])} (budget left {pct(entry['slo_budget_left'])})"
        f" | SLA {pct(entry['sla'])} (budget left {pct(entry['sla_budget_left'])})",
    ])


def pct(x):
    return "n/a" if x is None else f"{x * 100:.2f}%"


def parse_completion(raw):
    """Extract the assistant text from an OpenAI-compatible response, else None."""
    try:
        text = json.loads(raw)["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        return None
    if not isinstance(text, str):
        return None
    return text.strip() or None


def draft_postmortem(entry, tline):
    """Ask an OpenAI-compatible chat endpoint for a draft. Returns None if no
    endpoint is configured or anything goes wrong; the issue opens anyway."""
    endpoint, model = os.environ.get("LLM_ENDPOINT"), os.environ.get("LLM_MODEL")
    if not endpoint or not model:
        return None
    prompt = (
        "You are an SRE drafting a short incident postmortem for a static site monitored "
        "from GitHub Actions. Use only the data below; say 'unknown' instead of guessing. "
        "Sections: Summary, Timeline, Probable cause, Suggested next actions. Markdown, "
        "under 250 words. Remember the probes run from GitHub-hosted runners, so runner "
        "network issues are a possible cause.\n\n" + facts(entry) + "\n\n" + tline
    )
    headers = {"Content-Type": "application/json"}
    if os.environ.get("LLM_API_KEY"):
        headers["Authorization"] = f"Bearer {os.environ['LLM_API_KEY']}"
    req = urllib.request.Request(
        endpoint, method="POST", headers=headers,
        data=json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}]}).encode(),
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return parse_completion(resp.read())
    except OSError as e:
        print(f"LLM draft skipped: {e}")
        return None


def issue_body(entry, tline, draft):
    ai = (
        "## Draft postmortem (AI-generated, review before trusting)\n\n" + draft
        if draft else
        "## Draft postmortem\n\n_AI draft unavailable (no model configured or the call failed). "
        "See README, section AI._"
    )
    return "\n\n".join([
        "## Facts (from probe data)", facts(entry),
        "## Timeline (last 6h)", tline, ai,
        "<sub>Opened by Panoptes. The AI only drafts text; it never changes code or config.</sub>",
    ])


def sync(repo, token, entry, samples, now, was_open):
    """Edge-triggered: act only when the incident state flips, so a long outage
    produces one issue, not one comment every 15 minutes."""
    is_open = entry["incident"]
    if is_open == bool(was_open):
        return
    title = title_for(entry)
    issue = find_open_issue(repo, token, title)
    if is_open:
        tline = timeline(samples, now)
        body = issue_body(entry, tline, draft_postmortem(entry, tline))
        if issue:
            gh("POST", f"/repos/{repo}/issues/{issue['number']}/comments", token, {"body": body})
        else:
            gh("POST", f"/repos/{repo}/issues", token, {"title": title, "body": body, "labels": [LABEL]})
        print(f"incident opened/updated: {title}")
    elif issue:
        gh("POST", f"/repos/{repo}/issues/{issue['number']}/comments", token,
           {"body": f"Recovered at {fmt_ts(now)}: last probe {entry['last']['status']} "
                    f"in {entry['last']['ms']} ms. Closing automatically."})
        gh("PATCH", f"/repos/{repo}/issues/{issue['number']}", token, {"state": "closed"})
        print(f"incident closed: {title}")
