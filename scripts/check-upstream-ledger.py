#!/usr/bin/env python3
"""Watch EternalTerminal master against the pin + commit ledger.

Stdlib only. Used by .github/workflows/upstream-watch.yml.

Gates:
  1. Latest release tag/SHA and default-branch *name* still match the pin.
  2. Every SHA in compare(baseline...master) appears in the ledger.
     Missing SHA = unclassified drift (fail + list).
  3. status=backlog and kind in {security, protocol} is visibility only.

Does not push ledger edits. Optional --file-issue opens or updates one
ticket titled "upstream: unclassified ET master commits".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

KINDS = frozenset({"security", "protocol", "product", "ci", "docs", "other"})
STATUSES = frozenset({"skip", "backlog", "porting", "ported"})
WATCH_KINDS = frozenset({"security", "protocol"})
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ISSUE_TITLE = "upstream: unclassified ET master commits"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / ".github" / "upstream-pin.yml"
DEFAULT_LEDGER = ROOT / ".github" / "upstream-ledger.yml"


class LedgerError(Exception):
    pass


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def parse_pin(path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        if key:
            meta[key] = unquote(value)
        else:
            raise LedgerError(f"{path}:{lineno}: empty key")
    return meta


def parse_ledger(path: Path) -> tuple[dict[str, str], list[dict[str, str]]]:
    meta: dict[str, str] = {}
    commits: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current is not None:
                commits.append(current)
            rest = stripped[2:]
            if ":" not in rest:
                raise LedgerError(f"{path}:{lineno}: expected '- key: value'")
            key, value = rest.split(":", 1)
            current = {key.strip(): unquote(value)}
            continue
        if ":" not in stripped:
            raise LedgerError(f"{path}:{lineno}: expected 'key: value'")
        key, value = stripped.split(":", 1)
        key, value = key.strip(), unquote(value)
        if current is not None and line[:1].isspace():
            current[key] = value
        else:
            if current is not None:
                commits.append(current)
                current = None
            if key and key != "commits":
                meta[key] = value
    if current is not None:
        commits.append(current)
    return meta, commits


def validate_commits(commits: list[dict[str, str]], origin: str) -> dict[str, dict[str, str]]:
    by_sha: dict[str, dict[str, str]] = {}
    for index, row in enumerate(commits, 1):
        sha = row.get("sha", "").lower()
        date = row.get("date", "")
        kind = row.get("kind", "")
        status = row.get("status", "")
        note = row.get("note", "")
        if not SHA_RE.match(sha):
            raise LedgerError(f"{origin} #{index}: sha must be 40-char lowercase hex")
        if not DATE_RE.match(date):
            raise LedgerError(f"{origin} #{index}: date must be YYYY-MM-DD")
        if kind not in KINDS:
            raise LedgerError(f"{origin} #{index}: kind must be one of {sorted(KINDS)}")
        if status not in STATUSES:
            raise LedgerError(f"{origin} #{index}: status must be one of {sorted(STATUSES)}")
        if not note:
            raise LedgerError(f"{origin} #{index}: note is required")
        if "et_pr" in row and row["et_pr"] and not row["et_pr"].isdigit():
            raise LedgerError(f"{origin} #{index}: et_pr must be an integer")
        if sha in by_sha:
            raise LedgerError(f"{origin}: duplicate sha {sha}")
        normalized = dict(row)
        normalized["sha"] = sha
        by_sha[sha] = normalized
    return by_sha


def gh_json(path: str) -> object:
    env = os.environ.copy()
    if "GH_TOKEN" not in env and "GITHUB_TOKEN" in env:
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    result = subprocess.run(
        ["gh", "api", path],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise LedgerError(f"gh api {path} failed: {result.stderr.strip() or result.stdout.strip()}")
    return json.loads(result.stdout)


def gh_run(args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if "GH_TOKEN" not in env and "GITHUB_TOKEN" in env:
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    return subprocess.run(["gh", *args], check=False, capture_output=True, text=True, env=env)


def compare_commits(owner: str, repo: str, baseline: str, head: str) -> tuple[list[dict[str, str]], int]:
    first = gh_json(f"repos/{owner}/{repo}/compare/{baseline}...{head}?per_page=100&page=1")
    if not isinstance(first, dict):
        raise LedgerError("compare API returned a non-object")
    ahead = int(first.get("ahead_by") or first.get("total_commits") or 0)
    raw = list(first.get("commits") or [])
    page = 2
    while len(raw) < ahead:
        data = gh_json(f"repos/{owner}/{repo}/compare/{baseline}...{head}?per_page=100&page={page}")
        if not isinstance(data, dict):
            break
        batch = list(data.get("commits") or [])
        existing = {row["sha"] for row in raw}
        added = [row for row in batch if row.get("sha") not in existing]
        if not added:
            break
        raw.extend(added)
        page += 1
        if page > 100:
            break
    if ahead > len(raw):
        raw = walk_commits_after(owner, repo, head, baseline)
        ahead = len(raw)
    return [_commit_row(row) for row in raw], ahead


def walk_commits_after(owner: str, repo: str, head: str, baseline: str) -> list[dict]:
    out: list[dict] = []
    page = 1
    while page <= 100:
        batch = gh_json(f"repos/{owner}/{repo}/commits?sha={head}&per_page=100&page={page}")
        if not isinstance(batch, list) or not batch:
            raise LedgerError(f"baseline {baseline} not found walking {head}")
        for row in batch:
            if row.get("sha") == baseline:
                return out
            out.append(row)
        page += 1
    raise LedgerError(f"gave up walking {head} before reaching baseline {baseline}")


def _commit_row(row: dict) -> dict[str, str]:
    commit = row.get("commit") or {}
    author = commit.get("author") or {}
    date = str(author.get("date") or "")[:10]
    message = str((commit.get("message") or "")).split("\n", 1)[0]
    return {"sha": row["sha"], "date": date, "message": message}


def write_output(key: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{key}={value}\n")


def write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)
        if not text.endswith("\n"):
            handle.write("\n")


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def this_repo() -> str:
    return os.environ.get("GITHUB_REPOSITORY") or "minpeter/et.rs"


def upsert_unclassified_issue(unclassified: list[dict[str, str]], baseline: str, head: str) -> None:
    repo = this_repo()
    rows = [
        [
            f"[`{row['sha']}`](https://github.com/MisterTea/EternalTerminal/commit/{row['sha']})",
            row.get("date") or "",
            (row.get("message") or "").replace("|", "\\|"),
        ]
        for row in unclassified
    ]
    body = "\n".join(
        [
            "## Unclassified EternalTerminal master commits",
            "",
            f"Watch compared `{baseline}...{head}` and these SHAs are missing from "
            "`.github/upstream-ledger.yml`.",
            "",
            "Unclassified = drift. Classify in a PR. Actions must not auto-push ledger edits.",
            "",
            md_table(["sha", "date", "subject"], rows),
            "",
            "See `docs/upstream-factory.md`.",
            "",
        ]
    )
    listed = gh_run(
        ["issue", "list", "--repo", repo, "--state", "open", "--limit", "50", "--json", "number,title"]
    )
    if listed.returncode != 0:
        raise LedgerError(f"gh issue list failed: {listed.stderr.strip()}")
    number = None
    for issue in json.loads(listed.stdout or "[]"):
        if issue.get("title") == ISSUE_TITLE:
            number = issue.get("number")
            break
    if number is not None:
        edited = gh_run(["issue", "edit", str(number), "--repo", repo, "--body", body])
        if edited.returncode != 0:
            raise LedgerError(f"gh issue edit failed: {edited.stderr.strip()}")
        write_summary(f"\nUpdated issue #{number}: {ISSUE_TITLE}\n")
        return
    created = gh_run(["issue", "create", "--repo", repo, "--title", ISSUE_TITLE, "--body", body])
    if created.returncode != 0:
        raise LedgerError(f"gh issue create failed: {created.stderr.strip()}")
    write_summary(f"\nOpened issue: {created.stdout.strip()}\n")


def check(pin_path: Path, ledger_path: Path, file_issue: bool) -> int:
    pin = parse_pin(pin_path)
    ledger_meta, ledger_rows = parse_ledger(ledger_path)
    by_sha = validate_commits(ledger_rows, str(ledger_path))

    owner = pin["upstream_owner"]
    repo = pin["upstream_repo"]
    pin_tag = pin["reviewed_release_tag"]
    pin_release_sha = pin["reviewed_release_sha"]
    pin_branch = pin["reviewed_default_branch"]
    pin_tip = pin.get("reviewed_default_branch_sha", "")
    baseline = ledger_meta.get("baseline_sha") or pin_release_sha
    if baseline != pin_release_sha:
        raise LedgerError(
            f"ledger baseline_sha {baseline} != pin reviewed_release_sha {pin_release_sha}"
        )

    latest_tag = gh_json(f"repos/{owner}/{repo}/releases/latest")["tag_name"]
    latest_release_sha = gh_json(f"repos/{owner}/{repo}/commits/{latest_tag}")["sha"]
    default_branch = gh_json(f"repos/{owner}/{repo}")["default_branch"]
    tip_sha = gh_json(f"repos/{owner}/{repo}/commits/{default_branch}")["sha"]
    compare_rows, ahead_by = compare_commits(owner, repo, baseline, default_branch)

    unclassified = [row for row in compare_rows if row["sha"] not in by_sha]
    extra = sorted(set(by_sha) - {row["sha"] for row in compare_rows})
    backlog = [
        by_sha[row["sha"]]
        for row in compare_rows
        if row["sha"] in by_sha
        and by_sha[row["sha"]]["status"] == "backlog"
        and by_sha[row["sha"]]["kind"] in WATCH_KINDS
    ]

    pin_rows = [
        ["release tag", f"`{pin_tag}`", f"`{latest_tag}`"],
        ["release SHA", f"`{pin_release_sha}`", f"`{latest_release_sha}`"],
        ["default branch", f"`{pin_branch}`", f"`{default_branch}`"],
        ["default-branch SHA (pin tip, last classified)", f"`{pin_tip}`", f"`{tip_sha}`"],
        ["baseline (ledger)", f"`{baseline}`", f"ahead_by {ahead_by}"],
    ]
    summary = [
        "## EternalTerminal vs pin + ledger",
        "",
        md_table(["", "pin / ledger", "live"], pin_rows),
        "",
        f"Compared `{baseline}...{default_branch}`: **{len(compare_rows)}** commits, "
        f"**{len(unclassified)}** unclassified, **{len(by_sha)}** ledger rows.",
        "",
        "Pin = last reviewed / last classified tip, not already ported. "
        "See docs/upstream-factory.md.",
        "",
    ]

    if compare_rows:
        classified_table = []
        for row in compare_rows:
            entry = by_sha.get(row["sha"])
            if entry:
                classified_table.append(
                    [
                        f"`{row['sha'][:12]}`",
                        entry["kind"],
                        entry["status"],
                        entry["note"].replace("|", "\\|"),
                    ]
                )
            else:
                classified_table.append(
                    [f"`{row['sha'][:12]}`", "—", "**unclassified**", row.get("message") or ""]
                )
        summary.extend(
            [
                "### Ledger vs compare",
                "",
                md_table(["sha", "kind", "status", "note"], classified_table),
                "",
            ]
        )

    if backlog:
        summary.extend(
            [
                "### Classified but unported (visibility only; does not fail)",
                "",
                md_table(
                    ["sha", "kind", "status", "note"],
                    [
                        [f"`{row['sha']}`", row["kind"], row["status"], row["note"].replace("|", "\\|")]
                        for row in backlog
                    ],
                ),
                "",
            ]
        )

    if extra:
        summary.extend(
            [
                "### Ledger SHAs not in compare (ignored)",
                "",
                *[f"- `{sha}`" for sha in extra],
                "",
            ]
        )

    drift = []
    if latest_tag != pin_tag:
        drift.append(f"latest release tag moved past pin ({pin_tag} -> {latest_tag})")
    if latest_release_sha != pin_release_sha:
        drift.append(f"latest release SHA moved past pin ({pin_release_sha} -> {latest_release_sha})")
    if default_branch != pin_branch:
        drift.append(f"default branch name changed ({pin_branch} -> {default_branch})")
    if unclassified:
        drift.append(f"{len(unclassified)} unclassified ET master commit(s)")
        summary.extend(
            [
                "### Unclassified (fail)",
                "",
                *[f"- `{row['sha']}` {row.get('message') or ''}" for row in unclassified],
                "",
                "Update `.github/upstream-ledger.yml` in a PR. Do not auto-push ledger edits from Actions.",
                "",
            ]
        )

    write_summary("\n".join(summary))
    write_output("unclassified", "true" if unclassified else "false")
    write_output("unclassified_count", str(len(unclassified)))

    if unclassified and file_issue:
        upsert_unclassified_issue(unclassified, baseline, default_branch)

    if drift:
        for item in drift:
            print(f"drift: {item}", file=sys.stderr)
        return 1
    write_summary(
        "Release pin and default-branch name still match. "
        "Every compare SHA is classified.\n"
    )
    return 0


def self_test() -> int:
    pin = """
upstream_owner: MisterTea
upstream_repo: EternalTerminal
reviewed_release_tag: et-v7.0.0
reviewed_release_sha: 7656a32a5bc15c6746726a27a5a4ba1e468fab6e
reviewed_default_branch: master
"""
    ledger = """
baseline_sha: 7656a32a5bc15c6746726a27a5a4ba1e468fab6e
commits:
  - sha: f6cf43707bde07eb6d11495586a35b9f2d64b032
    date: "2026-07-08"
    kind: ci
    status: skip
    note: "deployment fixes"
  - sha: 69b33537ab12f324cf619aca04dc483728dc30c3
    date: "2026-07-30"
    kind: security
    status: backlog
    note: "#784 leftover"
    et_pr: 784
"""
    with tempfile.TemporaryDirectory() as tmp:
        pin_path = Path(tmp) / "pin.yml"
        ledger_path = Path(tmp) / "ledger.yml"
        pin_path.write_text(pin, encoding="utf-8")
        ledger_path.write_text(ledger, encoding="utf-8")
        parsed_pin = parse_pin(pin_path)
        meta, rows = parse_ledger(ledger_path)
        by_sha = validate_commits(rows, "self-test")
        assert parsed_pin["reviewed_release_tag"] == "et-v7.0.0"
        assert meta["baseline_sha"] == parsed_pin["reviewed_release_sha"]
        assert by_sha["69b33537ab12f324cf619aca04dc483728dc30c3"]["status"] == "backlog"
        assert by_sha["69b33537ab12f324cf619aca04dc483728dc30c3"]["et_pr"] == "784"

        missing = [
            row
            for row in [
                {"sha": "f6cf43707bde07eb6d11495586a35b9f2d64b032"},
                {"sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            ]
            if row["sha"] not in by_sha
        ]
        assert [row["sha"] for row in missing] == ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

        try:
            validate_commits(
                [{"sha": "abc", "date": "2026-01-01", "kind": "ci", "status": "skip", "note": "x"}],
                "bad",
            )
        except LedgerError:
            pass
        else:
            raise AssertionError("short sha must fail")

    real_meta, real_rows = parse_ledger(DEFAULT_LEDGER)
    validate_commits(real_rows, str(DEFAULT_LEDGER))
    real_pin = parse_pin(DEFAULT_PIN)
    if real_meta.get("baseline_sha") != real_pin["reviewed_release_sha"]:
        raise AssertionError("real ledger baseline != pin release sha")
    print("self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument(
        "--file-issue",
        action="store_true",
        help="open or update the unclassified-drift issue (schedule/dispatch)",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            return self_test()
        return check(args.pin, args.ledger, args.file_issue)
    except (LedgerError, KeyError, json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
