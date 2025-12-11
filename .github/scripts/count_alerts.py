import os
import json
import requests

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
