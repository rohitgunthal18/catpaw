"""Git utility functions for RepoSentinel.

Handles GitHub URL parsing, validation, and repository information extraction.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from reposentinel.utils.constants import GITHUB_URL_PATTERN


def parse_github_url(url: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Parse a GitHub URL to extract owner, repo name, and branch.

    Supports formats:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - https://github.com/owner/repo/tree/branch
      - https://github.com/owner/repo/tree/branch/path
      - git@github.com:owner/repo.git

    Args:
        url: GitHub URL string.

    Returns:
        Tuple of (owner, repo_name, branch). Branch may be None.
    """
    url = url.strip().rstrip("/")

    # Handle SSH URLs: git@github.com:owner/repo.git
    ssh_match = re.match(r"git@github\.com:(.+?)/(.+?)(?:\.git)?$", url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2), None

    # Handle HTTPS URLs
    parsed = urlparse(url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        return None, None, None

    path_parts = [p for p in parsed.path.split("/") if p]

    if len(path_parts) < 2:
        return None, None, None

    owner = path_parts[0]
    repo = path_parts[1].replace(".git", "")
    branch = None

    # Check for /tree/branch pattern
    if len(path_parts) >= 4 and path_parts[2] == "tree":
        branch = path_parts[3]

    return owner, repo, branch


def validate_github_url(url: str) -> Tuple[bool, str]:
    """Validate if a string is a valid GitHub repository URL.

    Args:
        url: URL string to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not url:
        return False, "URL cannot be empty"

    url = url.strip()

    # Check SSH format
    if url.startswith("git@"):
        if re.match(r"git@github\.com:.+/.+", url):
            return True, ""
        return False, "Invalid SSH GitHub URL format. Use: git@github.com:owner/repo.git"

    # Check HTTPS format
    if not url.startswith(("http://", "https://")):
        return False, "URL must start with https:// or http://"

    parsed = urlparse(url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        return False, "Only GitHub URLs are supported (github.com)"

    owner, repo, _ = parse_github_url(url)
    if not owner or not repo:
        return False, "Could not extract owner/repo from URL. Use: https://github.com/owner/repo"

    # Validate owner and repo names
    if not re.match(r"^[\w.-]+$", owner):
        return False, f"Invalid repository owner: '{owner}'"
    if not re.match(r"^[\w.-]+$", repo):
        return False, f"Invalid repository name: '{repo}'"

    return True, ""


def build_clone_url(owner: str, repo: str) -> str:
    """Build a clone URL from owner and repo name.

    Args:
        owner: Repository owner (username or organization).
        repo: Repository name.

    Returns:
        HTTPS clone URL.
    """
    return f"https://github.com/{owner}/{repo}.git"


def build_zip_url(owner: str, repo: str, branch: str = "main") -> str:
    """Build a ZIP download URL from owner, repo, and branch.

    Args:
        owner: Repository owner.
        repo: Repository name.
        branch: Branch name (default: main).

    Returns:
        GitHub API ZIP download URL.
    """
    return f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"


def build_api_url(owner: str, repo: str) -> str:
    """Build the GitHub API URL for repository metadata.

    Args:
        owner: Repository owner.
        repo: Repository name.

    Returns:
        GitHub API repository URL.
    """
    return f"https://api.github.com/repos/{owner}/{repo}"


def get_repo_display_name(url: str) -> str:
    """Get a human-readable display name for a repository URL.

    Args:
        url: GitHub URL.

    Returns:
        Display name in "owner/repo" format, or the URL if parsing fails.
    """
    owner, repo, _ = parse_github_url(url)
    if owner and repo:
        return f"{owner}/{repo}"
    return url
