"""Post one automated status summary on each open pull request once its required CI has passed.

Run by .github/workflows/pr-summary.yml after every CI run and on a schedule.
Each run goes through every open pull request, whoever opened it, including
pull requests from forks; nothing is taken from the event that started it. For
each pull request it checks, from the GitHub API:

  * the required checks for the base branch can be read from BOTH the branch
    ruleset and the classic branch protection, are non-empty, name the GitHub
    App that must report each check, and agree with each other;
  * every required check has exactly one run on the pull request's current head
    commit, from that App, that completed with conclusion `success`.

A pull request whose checks have not all passed (failed, pending, cancelled,
skipped, missing...) gets no summary. Anything that cannot be verified (an
unreadable or inconsistent protection setup, unexpected check runs, API errors)
is reported as an error and the run fails so the maintainer sees it. If CI ran
more than once on the commit, the most recently completed run of each check
decides.

The summary is a fixed template filled only from GitHub data: the commit it
covers, the required-check results, the pull request title and the changed
files. Nothing is sent anywhere else and nothing is generated or guessed about
what the change does. Text written by the pull request's author (the title and
file names) is shown only inside code formatting, so it cannot add links,
images, HTML or @mentions.

Each pull request has at most one summary comment, written by
github-actions[bot] and found again by a marker at the start of its body plus
that author; a comment by anyone else is never edited, even if it copies the
marker. The marker records which commit the comment covers:

  * state=verified: every required check passed on that commit. It is not
    written again while that commit is still the head.
  * state=superseded: the head moved to a commit that has not (yet) passed, so
    the earlier summary was replaced by a short "no summary for the latest
    commit" note. No check results are shown for a commit that did not pass.
  * state=blocked: the checks passed, but the pull request changes files under
    .github/. A pull request's CI runs the workflow files from its own merge
    commit, so it can change what produces its green checks; the comment says
    the commit needs maintainer review and shows no check results. The complete
    changed-file list is read (renames included); if GitHub cannot return all
    of it, or it does not hold as many entries as the pull request's
    changed_files count, nothing passing is posted.

The head commit is read again just before every write. That narrows, but cannot
close, the gap between the check and the write; the comment names the commit it
covers.

Standard library only; the workflow runs it with the runner's own python3.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

BOT_LOGIN = "github-actions[bot]"
MARKER_PREFIX = "<!-- mdv-pr-summary"
MARKER_RE = re.compile(r"<!-- mdv-pr-summary state=(verified|superseded|blocked) sha=([0-9a-f]{40}) -->")
PAGE_SIZE = 100
MAX_PR_FILES = 3000  # GitHub lists at most 3000 changed files for a pull request
MAX_FILES_LISTED = 15
MAX_TITLE_CHARS = 200


class VerificationError(Exception):
    """Could not verify a pull request; no summary is posted and the run fails."""


class NotReady(VerificationError):
    """The pull request is not eligible yet (checks not all passed, head moved); skipped."""


# ----------------------------------------------------------------------------- GitHub API

class GitHubAPI:
    """Minimal REST client. Tests replace it with a fake that has the same methods."""

    def __init__(self, token: str, api_url: str = "https://api.github.com"):
        self._token = token
        self._api_url = api_url.rstrip("/")

    def _request(self, method: str, path: str, params: dict | None = None, body: dict | None = None):
        url = self._api_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mdv-pr-summary",
        })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            raise VerificationError(f"GitHub API {method} {path} returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise VerificationError(f"GitHub API {method} {path} failed: {type(exc).__name__}") from None

    def get(self, path: str, params: dict | None = None):
        return self._request("GET", path, params=params)

    def post(self, path: str, body: dict):
        return self._request("POST", path, body=body)

    def patch(self, path: str, body: dict):
        return self._request("PATCH", path, body=body)


def get_pages(api, path: str, params: dict | None = None, max_pages: int | None = None):
    """All items of a paginated list endpoint, and whether max_pages cut it short."""
    items, page = [], 1
    while True:
        batch = api.get(path, {**(params or {}), "per_page": PAGE_SIZE, "page": page})
        if not isinstance(batch, list):
            raise VerificationError(f"GitHub API GET {path} did not return a list")
        items.extend(batch)
        if len(batch) < PAGE_SIZE:
            return items, False
        if max_pages is not None and page >= max_pages:
            return items, True
        page += 1


# ----------------------------------------------------------------------------- verification

def open_pull_request(api, repo: str, pr: int, sha: str) -> dict:
    pull = api.get(f"/repos/{repo}/pulls/{pr}")
    if not isinstance(pull, dict) or pull.get("number") != pr:
        raise VerificationError(f"could not read pull request #{pr}")
    if pull.get("state") != "open":
        raise NotReady(f"pull request #{pr} is no longer open")
    head_sha = (pull.get("head") or {}).get("sha")
    if head_sha != sha:
        raise NotReady(f"pull request #{pr} head moved from {sha} to {head_sha}")
    return pull


def _add_required(required: dict, context, app_id, source: str) -> None:
    if not isinstance(context, str) or not context:
        raise VerificationError(f"{source} lists a required check without a name")
    if not isinstance(app_id, int) or isinstance(app_id, bool):
        raise VerificationError(f"{source} does not say which GitHub App must report {context!r}")
    if required.get(context, app_id) != app_id:
        raise VerificationError(f"{source} requires {context!r} from more than one GitHub App")
    required[context] = app_id


def ruleset_required_checks(api, repo: str, branch: str) -> dict:
    """{check name: app id} from every active ruleset rule that applies to the branch."""
    path = f"/repos/{repo}/rules/branches/{urllib.parse.quote(branch, safe='')}"
    rules = api.get(path, {"per_page": PAGE_SIZE})
    if not isinstance(rules, list):
        raise VerificationError("branch ruleset response was not a list")
    if len(rules) >= PAGE_SIZE:
        raise VerificationError("branch ruleset response may be truncated")
    required: dict = {}
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_status_checks":
            continue
        checks = (rule.get("parameters") or {}).get("required_status_checks")
        if not isinstance(checks, list):
            raise VerificationError("a ruleset required_status_checks rule has no check list")
        for check in checks:
            if not isinstance(check, dict):
                raise VerificationError("a ruleset required check is malformed")
            _add_required(required, check.get("context"), check.get("integration_id"), "the ruleset")
    if not required:
        raise VerificationError(f"no ruleset requires status checks on {branch!r}")
    return required


def protection_required_checks(api, repo: str, branch: str) -> dict:
    """{check name: app id} from the classic branch protection."""
    info = api.get(f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}")
    protection = info.get("protection") if isinstance(info, dict) else None
    status_checks = protection.get("required_status_checks") if isinstance(protection, dict) else None
    checks = status_checks.get("checks") if isinstance(status_checks, dict) else None
    if not isinstance(checks, list) or not checks:
        raise VerificationError(f"branch protection on {branch!r} lists no required status checks")
    required: dict = {}
    for check in checks:
        if not isinstance(check, dict):
            raise VerificationError("a branch protection required check is malformed")
        _add_required(required, check.get("context"), check.get("app_id"), "branch protection")
    return required


def required_checks(api, repo: str, branch: str) -> dict:
    from_ruleset = ruleset_required_checks(api, repo, branch)
    from_protection = protection_required_checks(api, repo, branch)
    if from_ruleset != from_protection:
        raise VerificationError(
            f"the ruleset and branch protection disagree about required checks on {branch!r}: "
            f"{sorted(from_ruleset.items())} vs {sorted(from_protection.items())}")
    return from_ruleset


def _timestamp(value):
    """A GitHub ISO 8601 timestamp with a time zone, or None if it is missing or malformed."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def check_results(api, repo: str, sha: str, required: dict) -> list:
    """[(check name, conclusion)] for every required check; raise unless all succeeded.

    Checks that are missing, unfinished or did not succeed are an ordinary state
    for a pull request (NotReady). Runs from another app or for another commit,
    and several runs that cannot be put in order by completion time, are
    unexpected and cannot be verified (VerificationError).
    """
    response = api.get(f"/repos/{repo}/commits/{sha}/check-runs", {"filter": "latest", "per_page": PAGE_SIZE})
    runs = response.get("check_runs") if isinstance(response, dict) else None
    if not isinstance(runs, list):
        raise VerificationError(f"could not read check runs for {sha}")
    if response.get("total_count") != len(runs):
        raise VerificationError(f"check runs for {sha} did not fit in one page")

    results, not_passed, anomalies = [], [], []
    for name in sorted(required):
        app_id = required[name]
        named = [run for run in runs if isinstance(run, dict) and run.get("name") == name]
        matching = [run for run in named if (run.get("app") or {}).get("id") == app_id]
        if not matching:
            if named:
                anomalies.append(f"{name}: missing (reported by a different app)")
            else:
                not_passed.append(f"{name}: missing")
            continue
        if any(run.get("head_sha") != sha for run in matching):
            anomalies.append(f"{name}: ran on a different commit")
            continue
        run = matching[0]
        if len(matching) > 1:
            # Every CI run on the commit (for example after the PR is reopened) is its own check
            # suite, and filter=latest returns the latest run from each suite. The most recently
            # completed one decides; a run still in progress means the result is not known yet.
            unfinished = [r for r in matching if r.get("status") != "completed"]
            if unfinished:
                not_passed.append(f"{name}: {unfinished[0].get('status') or 'unknown status'} "
                                  f"(one of {len(matching)} runs on this commit)")
                continue
            times = [_timestamp(r.get("completed_at")) for r in matching]
            if None in times or times.count(max(times)) > 1:
                anomalies.append(f"{name}: {len(matching)} runs on this commit without one clearly latest "
                                 "completion time")
                continue
            run = matching[times.index(max(times))]
        if run.get("status") != "completed":
            not_passed.append(f"{name}: {run.get('status') or 'unknown status'}")
        elif run.get("conclusion") != "success":
            not_passed.append(f"{name}: {run.get('conclusion') or 'no conclusion'}")
        else:
            results.append((name, "success"))
    if anomalies:
        raise VerificationError(f"required checks on {sha} cannot be verified: " + "; ".join(anomalies + not_passed))
    if not_passed:
        raise NotReady(f"required checks on {sha} have not all passed: " + "; ".join(not_passed))
    return results


def changed_files(api, repo: str, pr: int) -> list:
    """Every file the pull request changes; raise if GitHub cannot return the complete list."""
    files, cut_off = get_pages(api, f"/repos/{repo}/pulls/{pr}/files", max_pages=MAX_PR_FILES // PAGE_SIZE)
    if cut_off:
        raise VerificationError(f"pull request #{pr} changes {MAX_PR_FILES} or more files, "
                                "more than GitHub can list, so its changed files cannot all be checked")
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
            raise VerificationError(f"pull request #{pr} has a malformed changed-file entry")
    return files


def is_github_config(path) -> bool:
    """A path in the repository's root .github/ directory. Any letter case, to be conservative."""
    return isinstance(path, str) and (path.lower() == ".github" or path.lower().startswith(".github/"))


def github_config_changes(files: list) -> int:
    """How many changed files are, or were renamed from, a path under .github/."""
    return sum(1 for f in files if is_github_config(f["filename"]) or is_github_config(f.get("previous_filename")))


# ----------------------------------------------------------------------------- comment text

FOOTER = ("<sub>Automated status summary, posted by github-actions[bot] from GitHub data only "
          "(required checks are read from the branch ruleset and branch protection). "
          "It is not a review or approval by the maintainer, and passing CI doesn't mean "
          "the change is correct or safe.</sub>")


def _code(text: str, limit: int | None = None) -> str:
    """Author-supplied text shown inertly: inside `code`, on one line, without backticks."""
    text = re.sub(r"[`\x00-\x1f\x7f]", "", text).strip()
    if limit is not None and len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return f"`{text}`" if text else "(none)"


def summary_body(pull: dict, sha: str, branch: str, results: list, files: list) -> str:
    checks = " · ".join(f"{name} ✅ {conclusion}" for name, conclusion in results)
    additions = sum(int(f.get("additions") or 0) for f in files)
    deletions = sum(int(f.get("deletions") or 0) for f in files)
    count = f"{len(files)} file{'' if len(files) == 1 else 's'}"
    lines = [
        f"{MARKER_PREFIX} state=verified sha={sha} -->",
        f"**Automated status summary** for commit `{sha}`, the head of this PR when it was checked.",
        "",
        f"All required checks for `{branch}` passed on this commit: {checks}.",
        "",
        f"Title: {_code(str(pull.get('title') or ''), MAX_TITLE_CHARS)}",
        f"Changes: {count}, +{additions}/-{deletions}",
    ]
    for f in files[:MAX_FILES_LISTED]:
        lines.append(f"- {_code(str(f.get('filename') or ''))} ({_code(str(f.get('status') or ''))}, "
                     f"+{int(f.get('additions') or 0)}/-{int(f.get('deletions') or 0)})")
    hidden = len(files) - min(len(files), MAX_FILES_LISTED)
    if hidden:
        lines.append(f"- and {hidden} more")
    lines += ["", "This is replaced when a newer commit is pushed.", "", "---", FOOTER]
    return "\n".join(lines)


def superseded_body(sha: str) -> str:
    return "\n".join([
        f"{MARKER_PREFIX} state=superseded sha={sha} -->",
        f"**Automated status summary: none for the latest commit yet.** This PR's head is now `{sha}`, "
        "and its required checks haven't all passed on that commit (or couldn't be verified), "
        "so the earlier summary was removed. A new one will appear here once they pass.",
        "",
        "---",
        FOOTER,
    ])


def blocked_body(sha: str) -> str:
    return "\n".join([
        f"{MARKER_PREFIX} state=blocked sha={sha} -->",
        f"**Automated status summary: not given for commit `{sha}`.** This PR changes files under "
        "`.github/` (GitHub Actions workflows or other repository automation). A pull request's CI runs "
        "the workflow files from the pull request itself, so its check results can't be taken as evidence "
        "that the usual tests ran. This needs maintainer review.",
        "",
        "---",
        FOOTER,
    ])


def find_bot_comment(api, repo: str, pr: int):
    """The first comment that starts with the marker AND was written by github-actions[bot]."""
    comments, _ = get_pages(api, f"/repos/{repo}/issues/{pr}/comments")
    for comment in comments:
        user = comment.get("user") or {}
        if (user.get("login") == BOT_LOGIN and user.get("type") == "Bot"
                and (comment.get("body") or "").startswith(MARKER_PREFIX)):
            return comment
    return None


# ----------------------------------------------------------------------------- run

class Run:
    def __init__(self, api, repo: str):
        self.api, self.repo = api, repo
        self._required: dict = {}

    def required(self, branch: str) -> dict:
        if branch not in self._required:
            self._required[branch] = required_checks(self.api, self.repo, branch)
        return self._required[branch]

    def _write(self, pr: int, existing, body: str) -> None:
        if existing:
            self.api.patch(f"/repos/{self.repo}/issues/comments/{existing['id']}", {"body": body})
        else:
            self.api.post(f"/repos/{self.repo}/issues/{pr}/comments", {"body": body})

    def _supersede(self, pr: int, sha: str, existing, marker) -> str:
        """Replace an earlier summary that does not cover the current head. Returns a note."""
        if not existing or (marker and marker.groups() == ("superseded", sha)):
            return ""
        try:
            open_pull_request(self.api, self.repo, pr, sha)  # last look, as before any write
            self._write(pr, existing, superseded_body(sha))
        except VerificationError as exc:
            return f"; the earlier summary could not be marked outdated ({exc})"
        return "; the earlier summary was marked outdated"

    def process(self, pull: dict) -> str:
        pr = pull.get("number")
        sha = (pull.get("head") or {}).get("sha")
        branch = (pull.get("base") or {}).get("ref")
        if not isinstance(pr, int) or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha) \
                or not isinstance(branch, str) or not branch:
            raise VerificationError("an open pull request is missing its number, head commit or base branch")

        existing = find_bot_comment(self.api, self.repo, pr)
        marker = MARKER_RE.match((existing or {}).get("body") or "")
        if marker and marker.groups() == ("verified", sha):
            return "already summarised for this commit"
        if marker and marker.groups() == ("blocked", sha):
            return "already flagged for maintainer review for this commit"

        try:
            results = check_results(self.api, self.repo, sha, self.required(branch))
            files = changed_files(self.api, self.repo, pr)
        except VerificationError as exc:
            # No summary for this commit. Never leave an earlier one looking current.
            raise type(exc)(f"{exc}{self._supersede(pr, sha, existing, marker)}") from None

        # Green checks are not evidence for a PR that can change the workflows producing them.
        config_changes = github_config_changes(files)
        body = blocked_body(sha) if config_changes else summary_body(pull, sha, branch, results, files)

        # Last look: if a commit was pushed while we were checking, post nothing.
        current = open_pull_request(self.api, self.repo, pr, sha)
        if not config_changes:
            # A passing summary needs the whole file list: it must hold exactly as many entries as
            # GitHub says the PR changes. This narrows, but does not close, a push-and-revert race.
            expected = current.get("changed_files")
            if not isinstance(expected, int) or isinstance(expected, bool) or expected != len(files):
                raise VerificationError(
                    f"pull request #{pr} lists {len(files)} changed files but GitHub reports "
                    f"{expected!r}, so its changed files cannot all be checked"
                    f"{self._supersede(pr, sha, existing, marker)}")
        self._write(pr, existing, body)
        if config_changes:
            return (f"no passing summary: the PR changes {config_changes} file(s) under .github/; "
                    f"{'updated the comment to' if existing else 'posted'} a maintainer-review notice")
        return "updated the summary" if existing else "posted a summary"


def run(api, repo: str) -> list:
    """Process every open pull request. Returns [(pr, outcome, is_error)]."""
    pulls, _ = get_pages(api, f"/repos/{repo}/pulls", {"state": "open"})
    job = Run(api, repo)
    outcomes = []
    for pull in pulls:
        pr = pull.get("number") if isinstance(pull, dict) else None
        try:
            outcomes.append((pr, job.process(pull), False))
        except NotReady as exc:
            outcomes.append((pr, f"skipped: {exc}", False))
        except VerificationError as exc:
            outcomes.append((pr, f"not verified, no summary posted: {exc}", True))
    return outcomes


def main(environ=os.environ) -> int:
    try:
        api = GitHubAPI(environ["GITHUB_TOKEN"], environ.get("GITHUB_API_URL", "https://api.github.com"))
        repo = environ["GITHUB_REPOSITORY"]
    except KeyError as exc:
        print(f"::error::Missing environment variable {exc}")
        return 1
    try:
        outcomes = run(api, repo)
    except VerificationError as exc:
        print(f"::error::Could not list open pull requests: {exc}")
        return 1
    for pr, outcome, is_error in outcomes:
        print(f"{'::error::' if is_error else ''}#{pr}: {outcome}")
    if not outcomes:
        print("No open pull requests.")
    return 1 if any(is_error for _, _, is_error in outcomes) else 0


if __name__ == "__main__":
    sys.exit(main())
