"""Repository fetcher for RepoSentinel.

Handles cloning repositories via Git or downloading ZIP archives
via the GitHub API as a fallback.
"""

import io
import os
import shutil
import tempfile
import zipfile
from typing import Optional, Tuple

import requests
from git import Repo, GitCommandError


class RepoFetcher:
    """Fetches GitHub repositories for scanning.

    Supports two methods:
    1. Git clone (preferred, uses depth=1 for speed)
    2. ZIP download via GitHub API (fallback if git not available)

    Usage:
        fetcher = RepoFetcher()
        with fetcher.fetch(url) as repo_dir:
            # scan repo_dir
    """

    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.environ.get('GITHUB_TOKEN')
        self._temp_dir = None

    def fetch(self, url: str) -> 'RepoContext':
        """Create a context manager that fetches and auto-cleans the repo."""
        return RepoContext(self, url)

    def clone_repo(self, url: str, target_dir: str) -> Tuple[bool, str]:
        """Clone a repo using git.

        Args:
            url: Git repository URL.
            target_dir: Directory to clone into.

        Returns:
            Tuple of (success_boolean, error_message_or_empty)
        """
        try:
            # Use depth=1 for shallow clone (much faster, saves bandwidth)
            Repo.clone_from(url, target_dir, depth=1)
            return True, ""
        except GitCommandError as e:
            return False, f"Git clone failed: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error during clone: {str(e)}"

    def download_zip(self, owner: str, repo: str, target_dir: str,
                     branch: str = 'main') -> Tuple[bool, str]:
        """Download repo as ZIP via GitHub API.

        Args:
            owner: Repository owner.
            repo: Repository name.
            target_dir: Directory to extract into.
            branch: Branch to download.

        Returns:
            Tuple of (success_boolean, error_message_or_empty)
        """
        headers = {}
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'

        # Try specified branch first
        api_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
        
        try:
            response = requests.get(api_url, headers=headers, stream=True, timeout=30)
            
            # Fallback to master if main doesn't exist
            if response.status_code == 404 and branch == 'main':
                api_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/master"
                response = requests.get(api_url, headers=headers, stream=True, timeout=30)
                
            if response.status_code != 200:
                return False, f"Failed to download ZIP API returned {response.status_code}"
                
            # Extract zip in memory to target directory
            z = zipfile.ZipFile(io.BytesIO(response.content))
            
            # GitHub ZIPs put everything in a root folder (e.g., owner-repo-hash/)
            # We want to extract the contents of that folder directly into target_dir
            root_dir = None
            for name in z.namelist():
                if '/' in name:
                    root = name.split('/')[0]
                    if not root_dir:
                        root_dir = root
                    elif root_dir != root:
                        # Multiple root dirs, shouldn't happen with GitHub ZIPs
                        z.extractall(target_dir)
                        return True, ""
                        
            if root_dir:
                # Extract all files, stripping the root directory
                for member in z.namelist():
                    if not member.startswith(f"{root_dir}/") or member == f"{root_dir}/":
                        continue
                        
                    # Remove the root_dir from the path
                    target_path = os.path.join(target_dir, member[len(root_dir)+1:])
                    
                    if member.endswith('/'):
                        os.makedirs(target_path, exist_ok=True)
                    else:
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with z.open(member) as source, open(target_path, "wb") as target:
                            shutil.copyfileobj(source, target)
            else:
                z.extractall(target_dir)
                
            return True, ""
            
        except requests.RequestException as e:
            return False, f"Network error downloading ZIP: {str(e)}"
        except zipfile.BadZipFile:
            return False, "Downloaded file is not a valid ZIP archive"
        except Exception as e:
            return False, f"Unexpected error processing ZIP: {str(e)}"


class RepoContext:
    """Context manager for fetched repository."""
    
    def __init__(self, fetcher: RepoFetcher, url: str):
        self.fetcher = fetcher
        self.url = url
        self.repo_dir = None
        self._temp_dir = None
        self.error = None

    def __enter__(self) -> str:
        """Create temp dir, try clone, fallback to ZIP."""
        self._temp_dir = tempfile.mkdtemp(prefix="reposentinel_")
        self.repo_dir = os.path.join(self._temp_dir, "repo")
        
        # 1. Try git clone first
        success, error = self.fetcher.clone_repo(self.url, self.repo_dir)
        
        # 2. If clone fails, try ZIP download fallback
        if not success:
            # Import here to avoid circular imports if git_utils imports fetcher
            from reposentinel.utils.git_utils import parse_github_url
            
            owner, repo, branch = parse_github_url(self.url)
            if owner and repo:
                os.makedirs(self.repo_dir, exist_ok=True)
                zip_success, zip_error = self.fetcher.download_zip(
                    owner, repo, self.repo_dir, branch or 'main'
                )
                
                if not zip_success:
                    self.error = f"Clone failed ({error}) AND ZIP download failed ({zip_error})"
                    raise RuntimeError(self.error)
            else:
                self.error = f"Clone failed ({error}) and URL could not be parsed for ZIP fallback"
                raise RuntimeError(self.error)
                
        return self.repo_dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup temporary directory."""
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                # Handle readonly files on Windows
                def remove_readonly(func, path, _):
                    import stat
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                shutil.rmtree(self._temp_dir, onerror=remove_readonly)
            except Exception:
                pass  # Ignore cleanup errors
