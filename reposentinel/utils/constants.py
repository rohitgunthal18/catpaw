"""RepoSentinel - Application constants and configuration."""

import os

# ─── Application Info ──────────────────────────────────────────────────────
APP_NAME = "Cat Paw"
APP_VERSION = "1.0.0"
APP_TAGLINE = "GitHub Repository Security Scanner"
APP_DESCRIPTION = "Protect yourself from malicious scripts"

# ─── ASCII Banner ──────────────────────────────────────────────────────────
BANNER = r"""
[bold orange3]
   /\_/\                                            oOo
  ( o.o )   ██████╗ █████╗ ████████╗    ██████╗  █████╗ ██╗    ██╗
   > ^ <    ██╔════╝██╔══██╗╚══██╔══╝    ██╔══██╗██╔══██╗██║    ██║
  /  _  \   ██║     ███████║   ██║       ██████╔╝███████║██║ █╗ ██║
 /_ / \ _\  ██║     ██╔══██║   ██║       ██╔═══╝ ██╔══██║██║███╗██║
 \__\ /__/  ╚██████╗██║  ██║   ██║       ██║     ██║  ██║╚███╔███╔╝
     v       ╚═════╝╚═╝  ╚═╝   ╚═╝       ╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ 
[/bold orange3]
[dim]  🐾  {tagline}  v{version}[/dim]
[dim]  🔍  {description}[/dim]
"""

# ─── Supported File Extensions ─────────────────────────────────────────────
SCANNABLE_EXTENSIONS = {
    # Python
    ".py": "python",
    ".pyw": "python",
    ".pyx": "python",
    # Shell / Bash
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".csh": "shell",
    # JavaScript / Node.js
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    # PowerShell
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    # Ruby
    ".rb": "ruby",
    ".rake": "ruby",
    # PHP
    ".php": "php",
    ".phtml": "php",
    # Go
    ".go": "go",
    # Perl
    ".pl": "perl",
    ".pm": "perl",
    # Configuration (can contain malicious entries)
    ".yml": "config",
    ".yaml": "config",
    ".json": "config",
    ".toml": "config",
    ".ini": "config",
    ".cfg": "config",
    ".conf": "config",
    # Makefiles / Build scripts
    ".makefile": "shell",
    ".dockerfile": "shell",
}

# Files that are always scanned regardless of extension
SPECIAL_FILENAMES = {
    "Makefile": "shell",
    "Dockerfile": "shell",
    "Vagrantfile": "ruby",
    "Gemfile": "ruby",
    "Rakefile": "ruby",
    "Jenkinsfile": "shell",
    "Procfile": "shell",
    ".bashrc": "shell",
    ".bash_profile": "shell",
    ".zshrc": "shell",
    ".profile": "shell",
    "setup.py": "python",
    "setup.cfg": "config",
    "pyproject.toml": "config",
    "package.json": "config",
    ".env": "config",
    ".npmrc": "config",
}

# ─── Files/Directories to Skip ────────────────────────────────────────────
SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    ".tox",
    ".eggs",
    "*.egg-info",
    ".mypy_cache",
    ".pytest_cache",
    "venv",
    ".venv",
    "env",
    ".env_dir",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

SKIP_FILES = {
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
}

# ─── File Size Limits ─────────────────────────────────────────────────────
MAX_FILE_SIZE_BYTES = 1_000_000  # 1MB - skip files larger than this
MAX_LINE_LENGTH = 10_000  # Skip lines longer than this (likely minified/binary)
MAX_REPO_SIZE_MB = 500  # Maximum repo size to scan

# ─── Risk Score Thresholds ─────────────────────────────────────────────────
RISK_THRESHOLDS = {
    "safe": (0, 15),
    "low": (16, 35),
    "moderate": (36, 55),
    "high": (56, 75),
    "critical": (76, 100),
}

# ─── Severity Weights ─────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 2,
    "info": 1,
}

# ─── Entropy Thresholds ───────────────────────────────────────────────────
HIGH_ENTROPY_THRESHOLD = 4.5  # Shannon entropy above this is suspicious
VERY_HIGH_ENTROPY_THRESHOLD = 5.5  # Almost certainly encoded/obfuscated
MIN_STRING_LENGTH_FOR_ENTROPY = 20  # Minimum string length to check entropy

# ─── Database Path ─────────────────────────────────────────────────────────
DATABASE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "patterns")

# ─── GitHub URL Pattern ───────────────────────────────────────────────────
GITHUB_URL_PATTERN = r"^https?://github\.com/[\w.-]+/[\w.-]+/?.*$"
GITHUB_API_BASE = "https://api.github.com"

# ─── Scan History ─────────────────────────────────────────────────────────
HISTORY_DIR = os.path.join(os.path.expanduser("~"), ".reposentinel", "history")
MAX_HISTORY_ENTRIES = 100
