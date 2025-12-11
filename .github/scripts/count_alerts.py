"""
SARIF-based alert processing with code flow support.

Can be run in two modes:
1. Local: python count_alerts.py --sarif path/to/file.sarif
2. GitHub Actions: Fetches SARIF from GitHub API automatically
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
    args = parser.parse_args()

    # Load config
    config = load_config()
    min_batch_size = args.min_batch_size or get_config_value(config, "MIN_BATCH_SIZE", "min_batch_size", 5)
    max_batch_size = args.max_batch_size or get_config_value(config, "MAX_BATCH_SIZE", "max_batch_size", 20)

    print(f"Config: min_batch_size={min_batch_size}, max_batch_size={max_batch_size}")

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

    print_batches(batches)

    print(f"\n{'='*80}")
    print(f"SUMMARY: {len(issues)} issues in {len(batches)} batches")
    print(f"  Min batch size: {min_batch_size}, Max batch size: {max_batch_size}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    exit(main())
