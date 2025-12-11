"""
Alert schema:

number: int (alert ID)
state: str ("open", "dismissed", "fixed")
html_url: str (link to alert on GitHub)
rule:
  id: str (e.g. "js/code-injection")
  name: str
  description: str
  severity: str ("error", "warning")
  security_severity_level: str ("critical", "high", "medium", "low")
  tags: array of CWE strings
  help: str (detailed markdown explanation)
most_recent_instance:
  location:
    path: str (file path)
    start_line: int
    end_line: int
    start_column: int
    end_column: int
  message:
    text: str (description of the issue)
  commit_sha: str
instances_url: str (API URL to get all instances)
"""

import os
from functools import lru_cache
from pathlib import Path
import requests
import yaml


# ============================================================================
# Config
# ============================================================================

config_path = Path(".github/devin.yml")
if config_path.exists():
    config = yaml.safe_load(config_path.read_text()) or {}
else:
    config = {}


def get_config(env_key, config_key, default):
    """Priority: env var (from workflow_dispatch) > config file > default"""
    env_val = os.environ.get(env_key)
    if env_val is not None and env_val != "":
        return int(env_val)
    if config_key in config:
        return config[config_key]
    return default


min_batch_size = get_config("MIN_BATCH_SIZE", "min_batch_size", 5)
max_batch_size = get_config("MAX_BATCH_SIZE", "max_batch_size", 20)

print(f"Config: min_batch_size={min_batch_size}, max_batch_size={max_batch_size}")


# ============================================================================
# Fetch alerts from GitHub API
# ============================================================================

repo = os.environ["GITHUB_REPOSITORY"]
token = os.environ["GITHUB_TOKEN"]

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

alerts = []
url = f"https://api.github.com/repos/{repo}/code-scanning/alerts?per_page=100"

while url:
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    alerts.extend(response.json())

    url = None
    if "Link" in response.headers:
        for link in response.headers["Link"].split(", "):
            if 'rel="next"' in link:
                url = link[link.index("<")+1:link.index(">")]
                break

open_alerts = [a for a in alerts if a["state"] == "open"]

print(f"Total alerts: {len(alerts)}")
print(f"Open alerts: {len(open_alerts)}")


# ============================================================================
# Sorting and batching
# ============================================================================

def alert_sort_key(alert: dict) -> tuple:
    """Sort key: (rule_id, file, start_line, start_column)."""
    loc = alert.get("most_recent_instance", {}).get("location", {})
    return (
        alert.get("rule", {}).get("id", ""),
        loc.get("path", ""),
        loc.get("start_line") or 0,
        loc.get("start_column") or 0,
    )


def create_batches(alerts: list[dict], min_batch_size: int, max_batch_size: int) -> list[list[dict]]:
    """
    Create batches of alerts grouped by rule_id.

    - Alerts are accumulated by rule_id until max_batch_size is reached
    - When switching rule_id, flush current batch if >= min_batch_size
    - Otherwise, continue accumulating into same batch
    """
    if not alerts:
        return []

    batches = []
    current_batch = []
    current_rule_id = None

    for alert in alerts:
        rule_id = alert.get("rule", {}).get("id", "")

        if current_rule_id is not None and rule_id != current_rule_id:
            if len(current_batch) >= min_batch_size:
                batches.append(current_batch)
                current_batch = []

        if len(current_batch) >= max_batch_size:
            batches.append(current_batch)
            current_batch = []

        current_batch.append(alert)
        current_rule_id = rule_id

    if current_batch:
        batches.append(current_batch)

    return batches


# ============================================================================
# Source extraction
# ============================================================================

@lru_cache(maxsize=128)
def read_file_lines(file_path: str) -> list[str] | None:
    """Read and cache file contents as lines."""
    try:
        with open(file_path) as f:
            return f.readlines()
    except (FileNotFoundError, PermissionError):
        return None


def extract_source_text(alert: dict) -> str | None:
    """Extract the source line(s) for an alert from the actual file."""
    loc = alert.get("most_recent_instance", {}).get("location", {})
    file_path = loc.get("path")
    start_line = loc.get("start_line")
    end_line = loc.get("end_line") or start_line

    if not file_path or not start_line:
        return None

    lines = read_file_lines(file_path)
    if lines is None:
        return None

    start_idx = start_line - 1
    end_idx = end_line - 1

    if start_idx >= len(lines):
        return None

    result_lines = []
    for i in range(start_idx, min(end_idx + 1, len(lines))):
        line = lines[i].rstrip('\n')
        result_lines.append(f"{i + 1}: {line}")

    return '\n'.join(result_lines)


# ============================================================================
# Formatting
# ============================================================================

def format_location(alert: dict) -> str:
    """Format the location string for an alert."""
    loc = alert.get("most_recent_instance", {}).get("location", {})
    start_line = loc.get("start_line")
    start_col = loc.get("start_column")
    end_line = loc.get("end_line")

    if not start_line:
        return ""

    line_info = f"L{start_line}"
    if start_col:
        line_info += f":C{start_col}"
    if end_line and end_line != start_line:
        line_info += f"-L{end_line}"

    return line_info


def print_batches(batches: list[list[dict]]) -> None:
    """Print batches with full report info."""
    print(f"\n{'='*80}")
    print(f"BATCHES ({len(batches)} total)")
    print("=" * 80)

    for i, batch in enumerate(batches):
        rule_ids = set(a.get("rule", {}).get("id", "") for a in batch)
        files = set(a.get("most_recent_instance", {}).get("location", {}).get("path", "") for a in batch)

        print(f"\n--- Batch {i + 1} ({len(batch)} issues) ---")
        print(f"  Rules: {', '.join(sorted(rule_ids))}")
        print(f"  Files: {', '.join(sorted(files))}")

        for alert in batch:
            rule_id = alert.get("rule", {}).get("id", "")
            file_path = alert.get("most_recent_instance", {}).get("location", {}).get("path", "")
            loc = format_location(alert)
            message = alert.get("most_recent_instance", {}).get("message", {}).get("text", "")
            severity = alert.get("rule", {}).get("security_severity_level", "")

            print(f"\n    [{rule_id}] [{severity}] {file_path}:{loc}")
            print(f"      {message}")

            source = extract_source_text(alert)
            if source:
                indented = source.replace('\n', '\n        ')
                print(f"      Source: `{indented}`")


# ============================================================================
# Main
# ============================================================================

sorted_alerts = sorted(open_alerts, key=alert_sort_key)
batches = create_batches(sorted_alerts, min_batch_size, max_batch_size)

print(f"Unique rules: {len(set(a.get('rule', {}).get('id', '') for a in open_alerts))}")
print(f"Unique files: {len(set(a.get('most_recent_instance', {}).get('location', {}).get('path', '') for a in open_alerts))}")

print_batches(batches)

print(f"\n{'='*80}")
print(f"SUMMARY: {len(open_alerts)} open alerts in {len(batches)} batches")
print(f"  Min batch size: {min_batch_size}, Max batch size: {max_batch_size}")
print("=" * 80)
