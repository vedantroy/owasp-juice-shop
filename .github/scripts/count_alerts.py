import os
import requests

repo = os.environ["GITHUB_REPOSITORY"]
token = os.environ["GITHUB_TOKEN"]

headers = {
    "Authorization": f"Bearer {token}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

url = f"https://api.github.com/repos/{repo}/code-scanning/alerts"
response = requests.get(url, headers=headers)
response.raise_for_status()

alerts = response.json()
open_alerts = [a for a in alerts if a["state"] == "open"]

print(f"Total alerts: {len(alerts)}")
print(f"Open alerts: {len(open_alerts)}")
