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
import json
from pathlib import Path
import requests
import yaml

# Load config from .github/devin.yml or use defaults
config_path = Path(".github/devin.yml")
if config_path.exists():
    config = yaml.safe_load(config_path.read_text()) or {}
else:
    config = {}

min_batch_size = config.get("min_batch_size", 5)
max_batch_size = config.get("max_batch_size", 20)

print(f"Config: min_batch_size={min_batch_size}, max_batch_size={max_batch_size}")

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

    # Check for next page
    url = None
    if "Link" in response.headers:
        for link in response.headers["Link"].split(", "):
            if 'rel="next"' in link:
                url = link[link.index("<")+1:link.index(">")]
                break

open_alerts = [a for a in alerts if a["state"] == "open"]

print(f"Total alerts: {len(alerts)}")
print(f"Open alerts: {len(open_alerts)}")
