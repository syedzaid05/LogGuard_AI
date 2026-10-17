"""GitHub repository scanner: fetch a public (or tokenised) repo as a ZIP."""
from __future__ import annotations

import re

import requests

from . import config
from .input_manager import SourceBundle, from_uploaded_file
from .secure_processing import ValidationError

_URL_RE = re.compile(
    r"^(?:https?://(?:www\.)?github\.com/)?"
    r"(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+?)"
    r"(?:\.git)?"
    r"(?:/tree/(?P<ref>[^/\s]+))?"
    r"/?$"
)


def parse_repo_url(url: str) -> tuple[str, str, str | None]:
    match = _URL_RE.match(url.strip())
    if not match:
        raise ValidationError(
            "Invalid repository reference. Use 'owner/repo' or a github.com URL."
        )
    return match.group("owner"), match.group("repo"), match.group("ref")


def fetch_repo(url: str) -> SourceBundle:
    owner, repo, ref = parse_repo_url(url)
    archive_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    if ref:
        archive_url += f"/{ref}"

    headers = {"Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"

    try:
        resp = requests.get(archive_url, headers=headers, timeout=60, allow_redirects=True)
    except requests.RequestException as exc:
        raise ValidationError(f"Could not reach GitHub: {exc}") from exc

    if resp.status_code == 404:
        raise ValidationError(
            f"Repository '{owner}/{repo}' not found (or private without GITHUB_TOKEN)."
        )
    if resp.status_code >= 400:
        raise ValidationError(
            f"GitHub returned HTTP {resp.status_code} for '{owner}/{repo}'."
        )

    archive_name = f"{owner}-{repo}.zip"
    bundle = from_uploaded_file(archive_name, resp.content)
    bundle.name = f"{owner}/{repo}" + (f"@{ref}" if ref else "")
    return bundle
