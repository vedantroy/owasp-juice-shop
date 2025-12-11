"""
SARIF-based alert processing with code flow support.

Can be run in two modes:
1. Local: python count_alerts.py --sarif path/to/file.sarif --local
2. GitHub Actions: Fetches SARIF from GitHub API and submits to Devin
"""

from __future__ import annotations

import argparse
import os
import json
from functools import lru_cache
from pathlib import Path
import requests
import yaml


# ============================================================================
# Devin API
# ============================================================================

DEVIN_SYSTEM_PROMPT = """You are fixing CodeQL security issues in a codebase.

For each issue, you will be given:
1. The rule ID and severity level
2. The location of the vulnerability (file and line)
3. A message describing the issue
4. The source code at that location
5. A "Code Flow" showing how tainted data flows from source to sink
6. A GitHub deeplink to the exact line in the codebase

IMPORTANT: When analyzing the Code Flow:
- The flow shows how untrusted data travels through the code
- The FIRST step is the SOURCE (where untrusted data enters)
- The LAST step is the SINK (where the vulnerability occurs)
- Sometimes the fix should be at the SINK (e.g., sanitize before use)
- Sometimes the fix should be EARLIER in the flow (e.g., a shared utility function)
- If you see a utility function like `utils.getErrorMessage(error)` in the flow, consider if the fix belongs there instead of at each call site

For each issue:
1. Analyze the code flow to understand where the data comes from
2. Determine the BEST place to fix (not always the final location)
3. Apply the appropriate fix (input validation, output encoding, parameterized queries, etc.)
4. Make sure your fix doesn't break existing functionality

IMPORTANT: Do NOT fix an issue if:
- You are not confident in the fix
- You need additional information or context to understand the issue
- The issue appears to be a FALSE POSITIVE (e.g., the data is actually safe, or there's validation you can't see)
- The fix would break functionality or change intended behavior
- The "vulnerability" is intentional (e.g., a security testing app, CTF challenge, or educational code)

If you skip an issue, briefly explain why in a comment or note.

IMPORTANT: Do NOT use the presence of comments like "vuln-code-snippet" or "Challenge" in the code as a reason to skip fixing. These are just metadata/documentation comments. You MUST still analyze each issue independently and fix it if you are confident in the fix. The comments do not indicate intentional vulnerabilities - they are simply labels.

IMPORTANT: When you create a Pull Request, include in the PR description:
1. A summary of what was fixed
2. For EACH issue fixed, include:
   - The original CodeQL rule ID and message
   - The GitHub deeplink to the vulnerable line (provided below as "Deeplink")
   - The code flow summary showing source -> sink
   - What fix was applied and why

This helps reviewers understand exactly what CodeQL issue triggered each fix.

Fix the issues you ARE confident about below:

"""


def format_batch_for_devin(batch: list[dict], repo: str, commit_sha: str) -> str:
    """Format a batch of issues as a prompt for Devin."""
    lines = [DEVIN_SYSTEM_PROMPT]
    lines.append("=" * 80)
    lines.append(f"ISSUES TO FIX ({len(batch)} total)")
    lines.append(f"Repository: {repo}")
    lines.append(f"Commit: {commit_sha}")
    lines.append("=" * 80)

    for idx, issue in enumerate(batch, 1):
        rule_id = issue.get("rule_id", "")
        level = issue.get("level", "")
        file_path = issue.get("file", "")
        start_line = issue.get("start_line")
        message = issue.get("message", "")

        # Build GitHub deeplink
        deeplink = f"https://github.com/{repo}/blob/{commit_sha}/{file_path}#L{start_line}"

        lines.append(f"\n--- Issue {idx} ---")
        lines.append(f"Rule: {rule_id}")
        lines.append(f"Severity: {level}")
        lines.append(f"File: {file_path}")
        lines.append(f"Line: {start_line}")
        lines.append(f"Deeplink: {deeplink}")
        lines.append(f"Message: {message}")

        # Source code
        source = extract_source_text(file_path, start_line, issue.get("end_line"))
        if source:
            lines.append(f"Source Code:\n{source}")

        # Code flows
        code_flows = issue.get("code_flows", [])
        if code_flows:
            lines.append(f"\nCode Flow ({len(code_flows)} paths):")
            for j, flow in enumerate(code_flows[:2]):  # Limit to first 2 flows
                lines.append(f"  Path {j+1}:")
                lines.append(format_code_flow(flow))

    return "\n".join(lines)


def submit_to_devin(prompt: str, title: str, api_key: str, snapshot_id: str) -> dict:
    """Submit a batch to Devin API."""
    response = requests.post(
        "https://api.devin.ai/v1/sessions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "prompt": prompt,
            "title": title,
            "snapshot_id": snapshot_id,
            "idempotent": False,
        },
    )
    response.raise_for_status()
    return response.json()


# ============================================================================
# Config
# ============================================================================

def load_config():
    config_path = Path(".github/devin.yml")
    if config_path.exists():
        return yaml.safe_load(config_path.read_text()) or {}
    return {}


def get_config_value(config, env_key, config_key, default):
    """Priority: env var (from workflow_dispatch) > config file > default"""
    env_val = os.environ.get(env_key)
    if env_val is not None and env_val != "":
        return int(env_val)
    if config_key in config:
        return config[config_key]
    return default


# ============================================================================
# SARIF Fetching (GitHub API)
# ============================================================================

def fetch_sarif_from_github(repo: str, token: str) -> dict:
    """Fetch the latest SARIF with results from GitHub API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Get list of analyses
    analyses_url = f"https://api.github.com/repos/{repo}/code-scanning/analyses"
    response = requests.get(analyses_url, headers=headers)
    response.raise_for_status()
    analyses = response.json()

    # Find the latest analysis with results
    analysis_id = None
    for analysis in analyses:
        if analysis.get("results_count", 0) > 0:
            analysis_id = analysis["id"]
            break

    if not analysis_id:
        raise RuntimeError("No analyses with results found")

    # Fetch the SARIF
    sarif_url = f"https://api.github.com/repos/{repo}/code-scanning/analyses/{analysis_id}"
    headers["Accept"] = "application/sarif+json"
    response = requests.get(sarif_url, headers=headers)
    response.raise_for_status()

    return response.json()


# ============================================================================
# SARIF Parsing
# ============================================================================

def get_commit_sha_from_sarif(sarif_data: dict) -> str | None:
    """Extract commit SHA from SARIF data if available."""
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            # GitHub adds commit info in properties
            props = result.get("properties", {})
            if "github/alertUrl" in props:
                # URL contains commit info, but let's check versionControlProvenance
                pass
        # Check versionControlProvenance
        vcp = run.get("versionControlProvenance", [])
        if vcp and "revisionId" in vcp[0]:
            return vcp[0]["revisionId"]
    return None


def parse_sarif(sarif_data: dict) -> list[dict]:
    """Parse SARIF data and return list of issues with code flows."""
    issues = []

    for run in sarif_data.get("runs", []):
        # Build artifact index -> uri mapping
        artifacts = {}
        for i, artifact in enumerate(run.get("artifacts", [])):
            uri = artifact.get("location", {}).get("uri", "")
            artifacts[i] = uri

        for result in run.get("results", []):
            # Get primary location
            locations = result.get("locations", [])
            if not locations:
                continue

            primary_loc = locations[0].get("physicalLocation", {})
            artifact_loc = primary_loc.get("artifactLocation", {})
            region = primary_loc.get("region", {})

            # Resolve file path
            file_path = artifact_loc.get("uri", "")
            if not file_path and "index" in artifact_loc:
                file_path = artifacts.get(artifact_loc["index"], "")

            # Extract code flows
            code_flows = []
            for flow in result.get("codeFlows", []):
                for thread_flow in flow.get("threadFlows", []):
                    steps = []
                    for loc_wrapper in thread_flow.get("locations", []):
                        loc = loc_wrapper.get("location", {})
                        phys = loc.get("physicalLocation", {})
                        art = phys.get("artifactLocation", {})
                        reg = phys.get("region", {})
                        msg = loc.get("message", {}).get("text", "")

                        step_file = art.get("uri", "")
                        if not step_file and "index" in art:
                            step_file = artifacts.get(art["index"], "")

                        steps.append({
                            "file": step_file,
                            "start_line": reg.get("startLine"),
                            "end_line": reg.get("endLine"),
                            "start_column": reg.get("startColumn"),
                            "end_column": reg.get("endColumn"),
                            "message": msg,
                        })
                    if steps:
                        code_flows.append(steps)

            # Extract related locations
            related_locations = []
            for rel_loc in result.get("relatedLocations", []):
                phys = rel_loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                reg = phys.get("region", {})
                msg = rel_loc.get("message", {}).get("text", "")

                rel_file = art.get("uri", "")
                if not rel_file and "index" in art:
                    rel_file = artifacts.get(art["index"], "")

                related_locations.append({
                    "id": rel_loc.get("id"),
                    "file": rel_file,
                    "start_line": reg.get("startLine"),
                    "message": msg,
                })

            issues.append({
                "rule_id": result.get("ruleId", ""),
                "level": result.get("level", "warning"),
                "message": result.get("message", {}).get("text", ""),
                "file": file_path,
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine"),
                "start_column": region.get("startColumn"),
                "end_column": region.get("endColumn"),
                "code_flows": code_flows,
                "related_locations": related_locations,
                "alert_url": result.get("properties", {}).get("github/alertUrl", ""),
            })

    return issues


# ============================================================================
# Sorting and batching
# ============================================================================

def issue_sort_key(issue: dict) -> tuple:
    """Sort key: (rule_id, file, start_line, start_column)."""
    return (
        issue.get("rule_id", ""),
        issue.get("file", ""),
        issue.get("start_line") or 0,
        issue.get("start_column") or 0,
    )


def create_batches(issues: list[dict], min_batch_size: int, max_batch_size: int) -> list[list[dict]]:
    """
    Create batches of issues grouped by rule_id.

    - Issues are accumulated by rule_id until max_batch_size is reached
    - When switching rule_id, flush current batch if >= min_batch_size
    - Otherwise, continue accumulating into same batch
    """
    if not issues:
        return []

    batches = []
    current_batch = []
    current_rule_id = None

    for issue in issues:
        rule_id = issue.get("rule_id", "")

        if current_rule_id is not None and rule_id != current_rule_id:
            if len(current_batch) >= min_batch_size:
                batches.append(current_batch)
                current_batch = []

        if len(current_batch) >= max_batch_size:
            batches.append(current_batch)
            current_batch = []

        current_batch.append(issue)
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


def extract_source_text(file_path: str, start_line: int, end_line: int = None) -> str | None:
    """Extract source line(s) from a file."""
    if not file_path or not start_line:
        return None

    end_line = end_line or start_line
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

def format_location(file: str, start_line: int, start_col: int = None, end_line: int = None) -> str:
    """Format a location string."""
    if not start_line:
        return file

    line_info = f"L{start_line}"
    if start_col:
        line_info += f":C{start_col}"
    if end_line and end_line != start_line:
        line_info += f"-L{end_line}"

    return f"{file}:{line_info}"


def format_code_flow(flow: list[dict]) -> str:
    """Format a code flow as a readable string."""
    lines = []
    for i, step in enumerate(flow):
        loc = format_location(step["file"], step["start_line"], step.get("start_column"))
        prefix = "  → " if i > 0 else "    "
        lines.append(f"{prefix}[{i+1}] {loc}")

        # Show source code for this step
        source = extract_source_text(step["file"], step["start_line"])
        if source:
            # Just the code, not the line number prefix (already shown in location)
            code_line = source.split(": ", 1)[1] if ": " in source else source
            lines.append(f"        {code_line.strip()}")
    return '\n'.join(lines)


def print_batches(batches: list[list[dict]]) -> None:
    """Print batches with full report info including code flows."""
    print(f"\n{'='*80}")
    print(f"BATCHES ({len(batches)} total)")
    print("=" * 80)

    for i, batch in enumerate(batches):
        rule_ids = set(issue.get("rule_id", "") for issue in batch)
        files = set(issue.get("file", "") for issue in batch)

        print(f"\n{'='*80}")
        print(f"Batch {i + 1} ({len(batch)} issues)")
        print(f"{'='*80}")
        print(f"Rules: {', '.join(sorted(rule_ids))}")
        print(f"Files: {', '.join(sorted(files))}")

        for issue in batch:
            rule_id = issue.get("rule_id", "")
            level = issue.get("level", "")
            file_path = issue.get("file", "")
            loc = format_location(file_path, issue.get("start_line"), issue.get("start_column"), issue.get("end_line"))
            message = issue.get("message", "")

            print(f"\n  [{rule_id}] [{level}]")
            print(f"  Location: {loc}")
            print(f"  Message: {message[:200]}{'...' if len(message) > 200 else ''}")

            # Print source
            source = extract_source_text(file_path, issue.get("start_line"), issue.get("end_line"))
            if source:
                indented = source.replace('\n', '\n      ')
                print(f"  Source:\n      {indented}")

            # Print code flows
            code_flows = issue.get("code_flows", [])
            if code_flows:
                print(f"  Code Flows ({len(code_flows)} paths):")
                for j, flow in enumerate(code_flows[:3]):  # Limit to first 3 flows
                    print(f"    Path {j+1}:")
                    print(format_code_flow(flow))
                if len(code_flows) > 3:
                    print(f"    ... and {len(code_flows) - 3} more paths")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Process CodeQL SARIF results")
    parser.add_argument("--sarif", type=str, help="Path to local SARIF file (if not provided, fetches from GitHub API)")
    parser.add_argument("--min-batch-size", type=int, help="Minimum batch size")
    parser.add_argument("--max-batch-size", type=int, help="Maximum batch size")
    parser.add_argument("--local", action="store_true", help="Local mode: print output only, don't submit to Devin")
    args = parser.parse_args()

    # Load config
    config = load_config()
    min_batch_size = args.min_batch_size or get_config_value(config, "MIN_BATCH_SIZE", "min_batch_size", 5)
    max_batch_size = args.max_batch_size or get_config_value(config, "MAX_BATCH_SIZE", "max_batch_size", 20)

    print(f"Config: min_batch_size={min_batch_size}, max_batch_size={max_batch_size}")
    print(f"Mode: {'local' if args.local else 'CI (will submit to Devin)'}")

    # Check for Devin credentials in CI mode
    devin_api_key = os.environ.get("DEVIN_API_KEY")
    devin_snapshot_id = os.environ.get("DEVIN_SNAPSHOT_ID")

    if not args.local:
        if not devin_api_key:
            print("Error: DEVIN_API_KEY not set (required in CI mode)")
            return 1
        if not devin_snapshot_id:
            print("Error: DEVIN_SNAPSHOT_ID not set (required in CI mode)")
            return 1

    # Load SARIF
    if args.sarif:
        print(f"Loading SARIF from: {args.sarif}")
        with open(args.sarif) as f:
            sarif_data = json.load(f)
    else:
        repo = os.environ.get("GITHUB_REPOSITORY")
        token = os.environ.get("GITHUB_TOKEN")
        if not repo or not token:
            print("Error: --sarif not provided and GITHUB_REPOSITORY/GITHUB_TOKEN not set")
            return 1
        print(f"Fetching SARIF from GitHub API for {repo}")
        sarif_data = fetch_sarif_from_github(repo, token)

    # Parse and process
    issues = parse_sarif(sarif_data)
    sorted_issues = sorted(issues, key=issue_sort_key)
    batches = create_batches(sorted_issues, min_batch_size, max_batch_size)

    print(f"\nTotal issues: {len(issues)}")
    print(f"Unique rules: {len(set(i.get('rule_id', '') for i in issues))}")
    print(f"Unique files: {len(set(i.get('file', '') for i in issues))}")
    print(f"Issues with code flows: {len([i for i in issues if i.get('code_flows')])}")

    # Print batches
    print_batches(batches)

    print(f"\n{'='*80}")
    print(f"SUMMARY: {len(issues)} issues in {len(batches)} batches")
    print(f"  Min batch size: {min_batch_size}, Max batch size: {max_batch_size}")
    print("=" * 80)

    # Submit to Devin if not in local mode
    if not args.local and batches:
        # Get repo and commit SHA for deeplinks
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        commit_sha = get_commit_sha_from_sarif(sarif_data) or os.environ.get("GITHUB_SHA", "main")

        print(f"\nSubmitting {len(batches)} batches to Devin...")
        print(f"  Repository: {repo}")
        print(f"  Commit SHA: {commit_sha}")

        for i, batch in enumerate(batches):
            rule_ids = set(issue.get("rule_id", "") for issue in batch)
            title = f"Fix CodeQL issues (Batch {i+1}/{len(batches)}): {', '.join(sorted(rule_ids)[:3])}"
            if len(rule_ids) > 3:
                title += f" +{len(rule_ids) - 3} more"

            prompt = format_batch_for_devin(batch, repo, commit_sha)

            print(f"\n  Batch {i+1}/{len(batches)}: {len(batch)} issues")
            print(f"    Title: {title}")

            try:
                result = submit_to_devin(prompt, title, devin_api_key, devin_snapshot_id)
                print(f"    Session ID: {result.get('session_id')}")
                print(f"    URL: {result.get('url')}")
            except requests.exceptions.RequestException as e:
                print(f"    Error submitting to Devin: {e}")
                # Continue with other batches

        print(f"\nAll batches submitted to Devin!")

    return 0


if __name__ == "__main__":
    exit(main())
