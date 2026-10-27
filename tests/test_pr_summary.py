"""Tests for the PR summary workflow (.github/workflows/pr-summary.yml) and its script.

The GitHub API is replaced by FakeGitHub, so nothing here contacts GitHub.
"""

from __future__ import annotations

import copy
import http.client
import importlib.util
import io
import json
import re
import urllib.parse
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "pr-summary.yml"
SCRIPT = ROOT / ".github" / "scripts" / "pr_summary.py"

# .github is not an importable package name, so load the script by path.
_spec = importlib.util.spec_from_file_location("pr_summary", SCRIPT)
pr_summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr_summary)

REPO = "realspinn/mysql-dba-validator"
SHA = "a" * 40
OTHER_SHA = "b" * 40
ACTIONS_APP = 15368
WINDOWS = "Tests (windows-latest)"
MACOS = "Tests (macos-15)"
BOT = {"login": "github-actions[bot]", "type": "Bot"}


def _run(check, sha=SHA, app_id=ACTIONS_APP, status="completed", conclusion="success"):
    return {"name": check, "head_sha": sha, "status": status, "conclusion": conclusion, "app": {"id": app_id}}


def _pull(number=7, sha=SHA, fork=False):
    head_repo = "contributor/mysql-dba-validator" if fork else REPO
    return {"number": number, "state": "open", "title": "Fix broad WHERE detection",
            "body": "Handles `id > -1`.", "head": {"sha": sha, "repo": {"full_name": head_repo}},
            "base": {"ref": "main"}}


def _marker(state, sha):
    return f"<!-- mdv-pr-summary state={state} sha={sha} -->"


class FakeGitHub:
    """In-memory stand-in for pr_summary.GitHubAPI, with main protected like the real repo."""

    def __init__(self, pulls=None):
        self.pulls = {p["number"]: p for p in (pulls or [_pull()])}
        self.later_heads = {}  # pr -> head SHA returned when the pull request is read again
        self.rules = [
            {"type": "pull_request", "parameters": {}},
            {"type": "required_status_checks", "parameters": {"required_status_checks": [
                {"context": WINDOWS, "integration_id": ACTIONS_APP},
                {"context": MACOS, "integration_id": ACTIONS_APP}]}},
        ]
        self.branch = {"name": "main", "protected": True, "protection": {"required_status_checks": {
            "contexts": [WINDOWS, MACOS],
            "checks": [{"context": WINDOWS, "app_id": ACTIONS_APP}, {"context": MACOS, "app_id": ACTIONS_APP}]}}}
        self.runs = {SHA: [_run(WINDOWS), _run(MACOS)], OTHER_SHA: [_run(WINDOWS, OTHER_SHA), _run(MACOS, OTHER_SHA)]}
        self.files = [{"filename": "backend/risk.py", "status": "modified", "additions": 3, "deletions": 1}]
        self.comments = {}
        self.fail = set()  # paths that return an HTTP error
        self.writes = []

    def _page(self, items, params):
        start = (params["page"] - 1) * params["per_page"]
        return copy.deepcopy(items[start:start + params["per_page"]])

    def get(self, path, params=None):
        if path in self.fail:
            raise pr_summary.VerificationError(f"GitHub API GET {path} returned HTTP 500")
        if path == f"/repos/{REPO}/pulls":
            assert params["state"] == "open"
            return self._page(list(self.pulls.values()), params)
        if m := re.fullmatch(rf"/repos/{REPO}/pulls/(\d+)", path):
            pull = copy.deepcopy(self.pulls[int(m.group(1))])
            if pull["number"] in self.later_heads:
                pull["head"]["sha"] = self.later_heads[pull["number"]]
            # "Get a pull request" includes the changed-file count; tests can override it.
            pull.setdefault("changed_files", len(self.files))
            return pull
        if re.fullmatch(rf"/repos/{REPO}/pulls/\d+/files", path):
            return self._page(self.files, params)
        if path == f"/repos/{REPO}/rules/branches/main":
            return copy.deepcopy(self.rules)
        if path == f"/repos/{REPO}/branches/main":
            return copy.deepcopy(self.branch)
        if m := re.fullmatch(rf"/repos/{REPO}/commits/([0-9a-f]{{40}})/check-runs", path):
            runs = self.runs.get(m.group(1), [])
            return {"total_count": len(runs), "check_runs": copy.deepcopy(runs)}
        if m := re.fullmatch(rf"/repos/{REPO}/issues/(\d+)/comments", path):
            return self._page(self.comments.get(int(m.group(1)), []), params)
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path, body):
        pr = int(re.fullmatch(rf"/repos/{REPO}/issues/(\d+)/comments", path).group(1))
        comment = {"id": 1000 + len(self.writes), "user": dict(BOT), "body": body["body"]}
        self.comments.setdefault(pr, []).append(comment)
        self.writes.append(("POST", pr, body["body"]))
        return comment

    def patch(self, path, body):
        comment_id = int(path.rsplit("/", 1)[1])
        for pr, comments in self.comments.items():
            for comment in comments:
                if comment["id"] == comment_id:
                    assert comment["user"] == BOT, "edited a comment the bot does not own"
                    comment["body"] = body["body"]
                    self.writes.append(("PATCH", pr, body["body"]))
                    return comment
        raise AssertionError("patched a comment that does not exist")


def _outcomes(api):
    return pr_summary.run(api, REPO)


def _only_outcome(api):
    [(pr, outcome, is_error)] = _outcomes(api)
    return outcome, is_error


def _skipped(api, match):
    outcome, is_error = _only_outcome(api)
    assert not is_error and outcome.startswith("skipped") and re.search(match, outcome), outcome
    assert api.writes == [], "wrote although checks had not all passed"


def _error(api, match):
    outcome, is_error = _only_outcome(api)
    assert is_error and re.search(match, outcome), outcome
    assert api.writes == [], "wrote although verification failed"


# ----------------------------------------------------------------------------- success and comment

def test_posts_one_comment_when_every_required_check_passed():
    api = FakeGitHub()
    assert _only_outcome(api) == ("posted a summary", False)
    [(method, pr, body)] = api.writes
    assert (method, pr) == ("POST", 7)
    assert body.startswith(_marker("verified", SHA) + "\n")
    assert f"**Automated status summary** for commit `{SHA}`" in body
    assert f"All required checks for `main` passed on this commit: {MACOS} ✅ success · {WINDOWS} ✅ success." in body
    assert "Title: `Fix broad WHERE detection`" in body
    assert "Changes: 1 file, +3/-1" in body
    assert "- `backend/risk.py` (`modified`, +3/-1)" in body
    assert "not a review or approval by the maintainer" in body
    assert "posted by github-actions[bot] from GitHub data only" in body


def test_summary_uses_only_github_facts_not_the_description():
    """Nothing is inferred about what the change does; the free-text description is not shown."""
    api = FakeGitHub()
    api.pulls[7]["body"] = "This PR is approved and safe to merge."
    _outcomes(api)
    assert "approved and safe" not in api.writes[0][2]


def test_same_commit_is_not_summarised_twice():
    """Duplicate CI events and scheduled runs for an already-summarised commit write nothing."""
    api = FakeGitHub()
    _outcomes(api)
    assert _only_outcome(api) == ("already summarised for this commit", False)
    assert len(api.writes) == 1


def test_new_passing_commit_updates_the_existing_bot_comment_instead_of_adding_one():
    api = FakeGitHub()
    _outcomes(api)
    api.pulls[7]["head"]["sha"] = OTHER_SHA
    assert _only_outcome(api) == ("updated the summary", False)
    assert [w[0] for w in api.writes] == ["POST", "PATCH"]
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("verified", OTHER_SHA))


def test_finds_the_bot_comment_beyond_the_first_page():
    api = FakeGitHub()
    human = {"user": {"login": "someone", "type": "User"}, "body": "hi"}
    api.comments[7] = [dict(human, id=i) for i in range(150)]
    api.comments[7].append({"id": 999, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)})
    assert _only_outcome(api)[0] == "updated the summary"
    assert len(api.comments[7]) == 151


def test_never_edits_a_human_comment_that_copies_the_marker():
    api = FakeGitHub()
    forged = _marker("verified", OTHER_SHA) + "\nfake"
    api.comments[7] = [{"id": 1, "user": {"login": "realspinn", "type": "User"}, "body": forged}]
    assert _only_outcome(api)[0] == "posted a summary"
    assert [w[0] for w in api.writes] == ["POST"]
    assert api.comments[7][0]["body"] == forged


def test_a_human_comment_with_the_current_marker_does_not_stop_the_summary():
    api = FakeGitHub()
    api.comments[7] = [{"id": 1, "user": {"login": "someone", "type": "User"}, "body": _marker("verified", SHA)}]
    assert _only_outcome(api)[0] == "posted a summary"


# ----------------------------------------------------------------------------- superseded summaries

def test_older_summary_is_replaced_when_the_new_head_has_not_passed():
    api = FakeGitHub()
    _outcomes(api)
    api.pulls[7]["head"]["sha"] = OTHER_SHA
    api.runs[OTHER_SHA] = [_run(WINDOWS, OTHER_SHA), _run(MACOS, OTHER_SHA, status="in_progress", conclusion=None)]
    outcome, is_error = _only_outcome(api)
    assert not is_error and outcome.startswith("skipped") and outcome.endswith("the earlier summary was marked outdated")
    [comment] = api.comments[7]
    body = comment["body"]
    assert body.startswith(_marker("superseded", OTHER_SHA))
    assert f"This PR's head is now `{OTHER_SHA}`" in body and "none for the latest commit yet" in body
    # No success claim survives for any commit.
    assert "✅" not in body and "passed on this commit" not in body and SHA not in body
    assert "not a review or approval by the maintainer" in body


def test_outdated_note_is_written_once_per_head():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)}]
    api.runs[SHA] = []
    _outcomes(api)
    _outcomes(api)
    assert [w[0] for w in api.writes] == ["PATCH"]


def test_outdated_note_becomes_a_summary_once_the_head_passes():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("superseded", SHA)}]
    assert _only_outcome(api) == ("updated the summary", False)
    assert api.comments[7][0]["body"].startswith(_marker("verified", SHA))


def test_summary_is_replaced_when_a_newer_run_on_the_same_commit_fails():
    """CI ran again on the summarised commit (re-run, or after reopening the PR) and failed."""
    api = FakeGitHub()
    _outcomes(api)
    api.runs[SHA] = [_run(WINDOWS),
                     _suite_run(MACOS, "success", "2026-10-27T05:52:00Z"),
                     _suite_run(MACOS, "failure", "2026-10-27T06:16:00Z")]
    outcome, is_error = _only_outcome(api)
    assert not is_error and "failure" in outcome and outcome.endswith("the earlier summary was marked outdated")
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("superseded", SHA))
    assert "✅" not in comment["body"] and "passed on this commit" not in comment["body"]
    assert [w[0] for w in api.writes] == ["POST", "PATCH"]


def test_outdated_note_becomes_a_summary_when_a_newer_run_on_the_same_commit_passes():
    api = FakeGitHub()
    _outcomes(api)
    api.runs[SHA] = [_run(WINDOWS), _suite_run(MACOS, "success", "2026-10-27T05:52:00Z"),
                     _suite_run(MACOS, "failure", "2026-10-27T06:16:00Z")]
    _outcomes(api)
    api.runs[SHA].append(_suite_run(MACOS, "success", "2026-10-27T06:40:00Z"))
    assert _only_outcome(api) == ("updated the summary", False)
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("verified", SHA))
    assert [w[0] for w in api.writes] == ["POST", "PATCH", "PATCH"]


def test_summary_for_the_same_commit_is_updated_when_its_content_is_stale():
    api = FakeGitHub()
    _outcomes(api)
    api.pulls[7]["title"] = "Renamed after the summary"
    assert _only_outcome(api) == ("updated the summary", False)
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("verified", SHA))
    assert "Title: `Renamed after the summary`" in comment["body"]


def test_older_summary_is_replaced_when_the_new_head_cannot_be_verified():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)}]
    api.runs[SHA].append(_run(MACOS))  # duplicate run
    outcome, is_error = _only_outcome(api)
    assert is_error and "2 runs" in outcome and outcome.endswith("marked outdated")
    assert api.comments[7][0]["body"].startswith(_marker("superseded", SHA))


def test_no_comment_is_written_for_a_pull_request_that_never_passed():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS, conclusion="failure"), _run(MACOS)]
    _skipped(api, "failure")
    assert api.comments == {}


def test_outdated_note_waits_if_the_head_moves_again():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)}]
    api.runs[SHA] = []
    api.later_heads[7] = "c" * 40
    outcome, _ = _only_outcome(api)
    assert "could not be marked outdated" in outcome
    assert api.writes == []


def test_outdated_note_never_touches_a_human_comment():
    api = FakeGitHub()
    forged = _marker("verified", OTHER_SHA)
    api.comments[7] = [{"id": 1, "user": {"login": "someone", "type": "User"}, "body": forged}]
    api.runs[SHA] = []
    _skipped(api, "missing")
    assert api.comments[7][0]["body"] == forged


# ----------------------------------------------------------------------------- comment text from PR data

def test_author_text_cannot_add_links_html_or_mentions():
    api = FakeGitHub()
    api.pulls[7]["title"] = "Fix `x` @realspinn <img src=x> [click](https://evil.test)\nline2"
    api.files = [{"filename": "a`@realspinn`\nb.py", "status": "added", "additions": 1, "deletions": 0}]
    _outcomes(api)
    body = api.writes[0][2]
    assert "Title: `Fix x @realspinn <img src=x> [click](https://evil.test)line2`" in body
    assert "- `a@realspinnb.py` (`added`, +1/-0)" in body
    # Every author-supplied value sits inside a single code span on its own line.
    for line in body.splitlines():
        if "realspinn" in line:
            assert line.count("`") % 2 == 0


def test_long_titles_are_cut():
    api = FakeGitHub()
    api.pulls[7]["title"] = "t" * 500
    _outcomes(api)
    assert "t" * (pr_summary.MAX_TITLE_CHARS + 1) not in api.writes[0][2]
    assert "t" * pr_summary.MAX_TITLE_CHARS + "…`" in api.writes[0][2]


def test_many_files_are_counted_and_the_list_is_cut():
    api = FakeGitHub()
    api.files = [{"filename": f"f{i}.py", "status": "added", "additions": 2, "deletions": 1} for i in range(20)]
    _outcomes(api)
    body = api.writes[0][2]
    assert "Changes: 20 files, +40/-20" in body
    assert "- `f14.py`" in body and "- `f15.py`" not in body
    assert "- and 5 more" in body


def test_large_file_lists_are_read_in_full():
    api = FakeGitHub()
    api.files = [{"filename": f"f{i}.py", "status": "added", "additions": 1, "deletions": 0} for i in range(350)]
    _outcomes(api)
    body = api.writes[0][2]
    assert "Changes: 350 files, +350/-0" in body and "- and 335 more" in body


# ----------------------------------------------------------------------------- .github/ changes

def _file(name, status="modified", previous=None):
    item = {"filename": name, "status": status, "additions": 1, "deletions": 0}
    if previous:
        item["previous_filename"] = previous
    return item


def _flagged(api):
    outcome, is_error = _only_outcome(api)
    assert not is_error and outcome.startswith("no passing summary: the PR changes"), outcome
    return outcome


@pytest.mark.parametrize("files", [
    [_file(".github/workflows/ci.yml")],                                   # workflow
    [_file(".github/scripts/pr_summary.py")],                              # script
    [_file(".github/CODEOWNERS")],                                         # other configuration
    [_file("backend/risk.py"), _file(".github/workflows/new.yml", "added")],  # mixed with app code
    [_file(".github/workflows/old.yml", "removed")],                       # deletion
    [_file("docs/ci.yml", "renamed", previous=".github/workflows/ci.yml")],  # renamed out of .github/
    [_file(".GitHub/workflows/ci.yml")],                                   # other letter case
])
def test_no_passing_summary_for_a_pr_that_changes_github_config(files):
    api = FakeGitHub()
    api.files = files
    _flagged(api)
    [(method, _, body)] = api.writes
    assert method == "POST"
    assert body.startswith(_marker("blocked", SHA) + "\n")
    assert f"not given for commit `{SHA}`" in body and "needs maintainer review" in body
    # Nothing that reads as a successful verification.
    assert "✅" not in body and "passed" not in body and "Changes:" not in body
    assert "not a review or approval by the maintainer" in body


@pytest.mark.parametrize("name", ["docs/.github-example.md", "src/.github/workflows/x.yml", ".githubx/a.yml", "github/a.yml"])
def test_paths_that_only_look_like_github_config_keep_the_normal_summary(name):
    api = FakeGitHub()
    api.files = [_file(name)]
    assert _only_outcome(api) == ("posted a summary", False)
    assert api.writes[0][2].startswith(_marker("verified", SHA))


def test_github_config_change_beyond_the_first_page_is_found():
    api = FakeGitHub()
    api.files = [_file(f"backend/f{i}.py") for i in range(250)] + [_file(".github/workflows/ci.yml")]
    _flagged(api)
    assert api.writes[0][2].startswith(_marker("blocked", SHA))


def test_no_passing_summary_when_github_cannot_list_every_changed_file():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)}]
    api.files = [_file(f"f{i}.py") for i in range(pr_summary.MAX_PR_FILES)]
    outcome, is_error = _only_outcome(api)
    assert is_error and "more than GitHub can list" in outcome and outcome.endswith("marked outdated")
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("superseded", SHA)) and "✅" not in comment["body"]


def test_a_complete_list_just_under_the_cap_is_accepted():
    """2,999 files is still a complete list: summarised normally, and a .github/ file at the end is found."""
    names = [f"f{i}.py" for i in range(pr_summary.MAX_PR_FILES - 1)]
    api = FakeGitHub()
    api.files = [_file(n) for n in names]
    assert _only_outcome(api) == ("posted a summary", False)
    assert "Changes: 2999 files, +2999/-0" in api.writes[0][2]

    api = FakeGitHub()
    api.files = [_file(n) for n in names[:-1]] + [_file(".github/workflows/ci.yml")]
    _flagged(api)
    assert api.writes[0][2].startswith(_marker("blocked", SHA))


@pytest.mark.parametrize("reported", [2, 0, None, "1", True, 1.0])
def test_no_passing_summary_when_the_file_count_does_not_match(reported):
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)}]
    if reported is None:  # the field is missing from the response
        api.get = (lambda original: lambda path, params=None: (
            {k: v for k, v in original(path, params).items() if k != "changed_files"}
            if path == f"/repos/{REPO}/pulls/7" else original(path, params)))(api.get)
    else:
        api.pulls[7]["changed_files"] = reported
    outcome, is_error = _only_outcome(api)
    assert is_error and "cannot all be checked" in outcome and outcome.endswith("marked outdated"), outcome
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("superseded", SHA)) and "✅" not in comment["body"]


def test_a_short_page_from_github_cannot_hide_a_github_config_change():
    """If a page came back short, the list would stop early; the count check catches it."""
    api = FakeGitHub()
    api.files = [_file(f"f{i}.py") for i in range(150)] + [_file(".github/workflows/ci.yml")]
    original = api._page
    api._page = lambda items, params: (original(items, params)[:99]
                                       if items is api.files and params["page"] == 1 else original(items, params))
    _error(api, "lists 99 changed files but GitHub reports 151")


def test_github_config_notice_does_not_depend_on_the_file_count():
    """A .github/ file that was seen is enough for the review notice, even if the list looks short."""
    api = FakeGitHub()
    api.files = [_file(".github/workflows/ci.yml")]
    api.pulls[7]["changed_files"] = 5
    _flagged(api)
    assert api.writes[0][2].startswith(_marker("blocked", SHA))


def test_no_passing_summary_for_a_malformed_changed_file_entry():
    api = FakeGitHub()
    api.files = [{"status": "modified"}]
    _error(api, "malformed changed-file entry")


def test_earlier_summary_is_replaced_when_the_new_head_changes_github_config():
    api = FakeGitHub()
    _outcomes(api)
    api.pulls[7]["head"]["sha"] = OTHER_SHA
    api.files = [_file(".github/workflows/ci.yml")]
    assert "updated the comment to a maintainer-review notice" in _flagged(api)
    [comment] = api.comments[7]
    assert comment["body"].startswith(_marker("blocked", OTHER_SHA))
    assert "✅" not in comment["body"] and SHA not in comment["body"]


def test_github_config_notice_is_written_once_per_commit():
    api = FakeGitHub()
    api.files = [_file(".github/workflows/ci.yml")]
    _outcomes(api)
    assert _only_outcome(api) == ("already flagged for maintainer review for this commit", False)
    assert len(api.writes) == 1 and len(api.comments[7]) == 1


def test_github_config_notice_never_edits_a_human_comment():
    api = FakeGitHub()
    forged = _marker("verified", SHA) + "\nlooks fine"
    api.comments[7] = [{"id": 1, "user": {"login": "someone", "type": "User"}, "body": forged}]
    api.files = [_file(".github/workflows/ci.yml")]
    _flagged(api)
    assert api.comments[7][0]["body"] == forged
    assert [w[0] for w in api.writes] == ["POST"]


def test_github_config_notice_is_not_written_if_the_head_moves():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("verified", OTHER_SHA)}]
    api.files = [_file(".github/workflows/ci.yml")]
    api.later_heads[7] = "c" * 40
    _skipped(api, "head moved")


def test_github_config_notice_waits_for_the_required_checks():
    """While checks are still running, the ordinary no-summary handling applies."""
    api = FakeGitHub()
    api.files = [_file(".github/workflows/ci.yml")]
    api.runs[SHA] = [_run(WINDOWS), _run(MACOS, status="in_progress", conclusion=None)]
    _skipped(api, "in_progress")


def test_github_config_notice_is_superseded_by_a_later_commit_that_passes():
    api = FakeGitHub()
    api.comments[7] = [{"id": 5, "user": dict(BOT), "body": _marker("blocked", OTHER_SHA)}]
    assert _only_outcome(api) == ("updated the summary", False)
    assert api.comments[7][0]["body"].startswith(_marker("verified", SHA))


def test_log_line_for_github_config_changes_does_not_print_file_names(monkeypatch, capsys):
    api = FakeGitHub()
    api.files = [_file(".github/workflows/\n::error::injected.yml")]
    monkeypatch.setattr(pr_summary, "GitHubAPI", lambda token, url: api)
    assert pr_summary.main({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO}) == 0
    out = capsys.readouterr().out
    assert "#7: no passing summary: the PR changes 1 file(s) under .github/; posted a maintainer-review notice" in out
    assert "injected" not in out


# ----------------------------------------------------------------------------- which pull requests

def test_handles_every_open_pull_request_including_forks():
    api = FakeGitHub([_pull(7), _pull(8, sha=OTHER_SHA, fork=True)])
    outcomes = _outcomes(api)
    assert [(pr, out) for pr, out, _ in outcomes] == [(7, "posted a summary"), (8, "posted a summary")]
    assert {pr for _, pr, _ in api.writes} == {7, 8}
    assert api.comments[8][0]["body"].startswith(_marker("verified", OTHER_SHA))


def test_lists_open_pull_requests_beyond_the_first_page():
    api = FakeGitHub([_pull(n) for n in range(1, 106)])
    assert len(_outcomes(api)) == 105


def test_a_problem_on_one_pull_request_does_not_block_the_others():
    api = FakeGitHub([_pull(7), _pull(8, sha=OTHER_SHA)])
    api.runs[SHA].append(_run(MACOS))  # duplicate run on #7
    outcomes = {pr: (out, err) for pr, out, err in _outcomes(api)}
    assert outcomes[7][1] is True and "2 runs" in outcomes[7][0]
    assert outcomes[8] == ("posted a summary", False)


def test_fork_pull_request_waiting_for_ci_approval_is_skipped():
    api = FakeGitHub([_pull(8, sha=OTHER_SHA, fork=True)])
    api.runs[OTHER_SHA] = []  # CI has not run: first-time contributor's run awaits approval
    _skipped(api, re.escape(f"{MACOS}: missing; {WINDOWS}: missing"))


def test_listing_failure_is_reported(monkeypatch, capsys):
    api = FakeGitHub()
    api.fail.add(f"/repos/{REPO}/pulls")
    monkeypatch.setattr(pr_summary, "GitHubAPI", lambda token, url: api)
    assert pr_summary.main({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO}) == 1
    assert "::error::Could not list open pull requests" in capsys.readouterr().out


# ----------------------------------------------------------------------------- commit identity

def test_posts_nothing_when_the_head_moves_before_publishing():
    api = FakeGitHub()
    api.later_heads[7] = OTHER_SHA
    _skipped(api, "head moved")


def test_posts_nothing_when_the_pull_request_closes_before_publishing():
    api = FakeGitHub()
    api.pulls[7]["state"] = "closed"  # the list said open; the last look says closed
    _skipped(api, "no longer open")


def test_refuses_a_pull_request_without_a_valid_head_commit():
    api = FakeGitHub([_pull(7, sha="A" * 40)])
    _error(api, "missing its number, head commit or base branch")


def test_refuses_when_the_pull_request_cannot_be_read_again():
    api = FakeGitHub()
    api.fail.add(f"/repos/{REPO}/pulls/7")
    _error(api, "HTTP 500")


# ----------------------------------------------------------------------------- required checks

@pytest.mark.parametrize("status, conclusion, shown", [
    ("completed", "failure", "failure"),
    ("completed", "cancelled", "cancelled"),
    ("completed", "skipped", "skipped"),
    ("completed", "neutral", "neutral"),
    ("completed", "timed_out", "timed_out"),
    ("completed", "action_required", "action_required"),
    ("completed", None, "no conclusion"),
    ("in_progress", None, "in_progress"),
    ("queued", None, "queued"),
])
def test_skips_unless_every_required_check_succeeded(status, conclusion, shown):
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS), _run(MACOS, status=status, conclusion=conclusion)]
    _skipped(api, re.escape(f"{MACOS}: {shown}"))


def test_skips_a_missing_required_check():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS)]
    _skipped(api, re.escape(f"{MACOS}: missing"))


def test_refuses_duplicate_runs_of_a_required_check():
    api = FakeGitHub()
    api.runs[SHA].append(_run(MACOS))
    _error(api, re.escape(f"{MACOS}: 2 runs"))


def _suite_run(check, conclusion, completed_at, sha=SHA, status="completed"):
    """A check run as filter=latest returns it when CI ran more than once on the commit: one per suite."""
    run = _run(check, sha=sha, status=status, conclusion=conclusion)
    run["completed_at"] = completed_at
    return run


def test_newer_successful_run_replaces_an_older_failure():
    """CI re-run on the same commit (for example after reopening the PR): the newest result decides."""
    api = FakeGitHub()
    api.runs[SHA] = [_suite_run(WINDOWS, "success", "2026-10-27T05:50:00Z"),
                     _suite_run(MACOS, "failure", "2026-10-27T05:52:00Z"),
                     _suite_run(WINDOWS, "success", "2026-10-27T06:14:00Z"),
                     _suite_run(MACOS, "success", "2026-10-27T06:16:00Z")]
    assert _only_outcome(api) == ("posted a summary", False)
    assert f"{MACOS} ✅ success · {WINDOWS} ✅ success" in api.writes[0][2]


def test_older_success_does_not_hide_a_newer_failure():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS),
                     _suite_run(MACOS, "success", "2026-10-27T05:52:00Z"),
                     _suite_run(MACOS, "failure", "2026-10-27T06:16:00+00:00")]
    _skipped(api, re.escape(f"{MACOS}: failure"))


def test_older_success_does_not_count_while_a_newer_run_is_in_progress():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS),
                     _suite_run(MACOS, "success", "2026-10-27T05:52:00Z"),
                     _suite_run(MACOS, None, None, status="in_progress")]
    _skipped(api, re.escape(f"{MACOS}: in_progress (one of 2 runs on this commit)"))


@pytest.mark.parametrize("times", [
    ("2026-10-27T06:16:00Z", "2026-10-27T06:16:00+00:00"),   # the same moment
    ("2026-10-27T06:16:00Z", None),                          # missing
    ("2026-10-27T06:16:00Z", ""),
    ("2026-10-27T06:16:00Z", "yesterday"),                    # malformed
    ("2026-10-27T06:16:00Z", "2026-10-27T06:17:00"),          # no time zone
    ("2026-10-27T06:16:00Z", 1793091360),                     # not text
])
def test_runs_that_cannot_be_ordered_fail_closed(times):
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS)] + [_suite_run(MACOS, "success", t) for t in times]
    _error(api, re.escape(f"{MACOS}: 2 runs on this commit without one clearly latest completion time"))


def test_a_duplicate_run_for_another_commit_is_never_used():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS),
                     _suite_run(MACOS, "failure", "2026-10-27T05:52:00Z"),
                     _suite_run(MACOS, "success", "2026-10-27T06:16:00Z", sha=OTHER_SHA)]
    _error(api, re.escape(f"{MACOS}: ran on a different commit"))


def test_refuses_a_check_reported_by_the_wrong_app():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS), _run(MACOS, app_id=999)]
    _error(api, re.escape(f"{MACOS}: missing (reported by a different app)"))


def test_refuses_a_check_run_for_another_commit():
    api = FakeGitHub()
    api.runs[SHA] = [_run(WINDOWS), _run(MACOS, sha=OTHER_SHA)]
    _error(api, "different commit")


def test_refuses_when_check_runs_do_not_fit_in_one_page():
    api = FakeGitHub()
    original = api.get
    api.get = lambda path, params=None: (
        {"total_count": 101, "check_runs": [_run(WINDOWS), _run(MACOS)]} if "check-runs" in path
        else original(path, params))
    _error(api, "one page")


@pytest.mark.parametrize("path", [
    f"/repos/{REPO}/rules/branches/main",
    f"/repos/{REPO}/branches/main",
    f"/repos/{REPO}/commits/{SHA}/check-runs",
    f"/repos/{REPO}/issues/7/comments",
    f"/repos/{REPO}/pulls/7/files",
])
def test_refuses_when_a_source_cannot_be_read(path):
    api = FakeGitHub()
    api.fail.add(path)
    _error(api, "HTTP 500")


def test_refuses_when_no_ruleset_requires_checks():
    api = FakeGitHub()
    api.rules = [{"type": "pull_request", "parameters": {}}]
    _error(api, "no ruleset requires")


def test_refuses_when_branch_protection_requires_no_checks():
    api = FakeGitHub()
    api.branch = {"name": "main", "protected": False}
    _error(api, "branch protection on 'main' lists no required")


def test_refuses_when_the_sources_disagree():
    api = FakeGitHub()
    api.branch["protection"]["required_status_checks"]["checks"].pop()
    _error(api, "disagree")


def test_refuses_a_required_check_without_an_app():
    api = FakeGitHub()
    api.rules[1]["parameters"]["required_status_checks"][0].pop("integration_id")
    _error(api, "does not say which GitHub App")
    api = FakeGitHub()
    api.branch["protection"]["required_status_checks"]["checks"][0]["app_id"] = None
    _error(api, "does not say which GitHub App")


def test_refuses_a_check_required_from_two_apps():
    api = FakeGitHub()
    api.rules.append({"type": "required_status_checks", "parameters": {"required_status_checks": [
        {"context": MACOS, "integration_id": 999}]}})
    _error(api, "more than one GitHub App")


def test_combines_required_checks_from_several_rulesets():
    api = FakeGitHub()
    api.rules = [api.rules[0],
                 {"type": "required_status_checks", "parameters": {"required_status_checks": [
                     {"context": WINDOWS, "integration_id": ACTIONS_APP}]}},
                 {"type": "required_status_checks", "parameters": {"required_status_checks": [
                     {"context": MACOS, "integration_id": ACTIONS_APP}]}}]
    assert _only_outcome(api)[0] == "posted a summary"


# ----------------------------------------------------------------------------- entry point

def test_missing_github_credentials_stop_the_run(capsys):
    assert pr_summary.main({"GITHUB_REPOSITORY": REPO}) == 1
    assert "::error::Missing environment variable 'GITHUB_TOKEN'" in capsys.readouterr().out


def test_run_fails_when_any_pull_request_could_not_be_verified(monkeypatch, capsys):
    api = FakeGitHub()
    api.branch["protection"]["required_status_checks"]["checks"].pop()
    monkeypatch.setattr(pr_summary, "GitHubAPI", lambda token, url: api)
    assert pr_summary.main({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO}) == 1
    assert "::error::#7: not verified, no summary posted" in capsys.readouterr().out


class _DroppedWhileReading:
    """A response whose body read fails, as when the connection drops mid-response."""

    def __init__(self, error):
        self.error = error

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self, *args):
        raise self.error


def _urlopen_serving(api, drop_path, error, while_reading):
    """urlopen for the real GitHubAPI, answered from FakeGitHub; drop_path's request fails."""
    def urlopen(request, timeout):
        url = urllib.parse.urlsplit(request.full_url)
        if url.path == drop_path:
            if while_reading:
                return _DroppedWhileReading(error)
            raise error
        if request.get_method() == "GET":
            params = {k: int(v) if v.isdigit() else v for k, v in urllib.parse.parse_qsl(url.query)}
            data = api.get(url.path, params)
        else:
            data = getattr(api, request.get_method().lower())(url.path, json.loads(request.data))
        return io.BytesIO(json.dumps(data).encode("utf-8"))
    return urlopen


@pytest.mark.parametrize("error, while_reading", [
    (http.client.RemoteDisconnected("Remote end closed connection without response"), False),
    (ConnectionResetError(10054, "An existing connection was forcibly closed"), True),
    (http.client.IncompleteRead(b'[{"id"', 512), True),
])
def test_a_dropped_connection_fails_only_that_pull_request(monkeypatch, capsys, error, while_reading):
    api = FakeGitHub([_pull(7), _pull(8, sha=OTHER_SHA)])
    monkeypatch.setattr(pr_summary.urllib.request, "urlopen",
                        _urlopen_serving(api, f"/repos/{REPO}/issues/7/comments", error, while_reading))
    assert pr_summary.main({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO}) == 1
    out = capsys.readouterr().out
    name = type(error).__name__
    assert f"::error::#7: not verified, no summary posted: GitHub API GET /repos/{REPO}/issues/7/comments failed: {name}" in out
    assert "#8: posted a summary" in out
    assert [(method, pr) for method, pr, _ in api.writes] == [("POST", 8)]


def test_a_dropped_connection_while_listing_pull_requests_stops_the_run(monkeypatch, capsys):
    api = FakeGitHub()
    monkeypatch.setattr(pr_summary.urllib.request, "urlopen", _urlopen_serving(
        api, f"/repos/{REPO}/pulls", http.client.IncompleteRead(b"[", 100), while_reading=True))
    assert pr_summary.main({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO}) == 1
    assert ("::error::Could not list open pull requests: GitHub API GET "
            f"/repos/{REPO}/pulls failed: IncompleteRead") in capsys.readouterr().out
    assert api.writes == []


def test_log_shows_outcomes_not_pull_request_text(monkeypatch, capsys):
    api = FakeGitHub()
    api.pulls[7]["title"] = "SECRET-TITLE"
    api.pulls[7]["body"] = "SECRET-DESCRIPTION"
    monkeypatch.setattr(pr_summary, "GitHubAPI", lambda token, url: api)
    assert pr_summary.main({"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": REPO}) == 0
    out = capsys.readouterr().out
    assert "#7: posted a summary" in out
    assert "SECRET" not in out


# ----------------------------------------------------------------------------- workflow file

def _workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_workflow_runs_after_ci_and_on_a_schedule_only():
    # PyYAML reads the bare key `on` as True.
    triggers = _workflow()[True]
    assert set(triggers) == {"workflow_run", "schedule"}
    assert triggers["workflow_run"] == {"workflows": ["CI"], "types": ["completed"]}
    assert triggers["schedule"] == [{"cron": "23 */6 * * *"}]
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    assert ci["name"] == "CI"


def test_workflow_token_can_only_read_and_write_pull_request_comments():
    workflow = _workflow()
    assert workflow["permissions"] == {}
    [job] = workflow["jobs"].values()
    assert job["permissions"] == {"contents": "read", "checks": "read", "pull-requests": "write"}


def test_workflow_never_checks_out_or_runs_pull_request_code():
    [job] = _workflow()["jobs"].values()
    checkout = job["steps"][0]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"] == {"persist-credentials": False}  # no ref: the default branch
    assert [step["run"] for step in job["steps"] if "run" in step] == ["python3 .github/scripts/pr_summary.py"]
    assert "github.event" not in json.dumps(job)


def test_workflow_uses_no_secret_but_its_own_token():
    [job] = _workflow()["jobs"].values()
    assert job["steps"][1]["env"] == {"GITHUB_TOKEN": "${{ secrets.GITHUB_TOKEN }}"}
    assert re.findall(r"secrets\.\w+", WORKFLOW.read_text(encoding="utf-8")) == ["secrets.GITHUB_TOKEN"]
