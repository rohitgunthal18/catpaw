"""File utility functions for RepoSentinel.

Handles file type detection, filtering, and content reading with
safety guards for binary files and size limits.
"""

import os
from typing import Optional, Tuple, List

from reposentinel.utils.constants import (
    SCANNABLE_EXTENSIONS,
    SPECIAL_FILENAMES,
    SKIP_DIRECTORIES,
    SKIP_FILES,
    MAX_FILE_SIZE_BYTES,
    MAX_LINE_LENGTH,
)


def detect_language(file_path: str) -> Optional[str]:
    """Detect the programming language of a file by extension or name.

    Args:
        file_path: Path to the file.

    Returns:
        Language string (e.g., 'python', 'shell') or None if unsupported.
    """
    basename = os.path.basename(file_path)

    # Check special filenames first
    if basename in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[basename]

    # Check by extension
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    if ext in SCANNABLE_EXTENSIONS:
        return SCANNABLE_EXTENSIONS[ext]

    # Check for shebang line in extensionless files
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            first_line = f.readline(256).strip()
            if first_line.startswith("#!"):
                shebang = first_line.lower()
                if "python" in shebang:
                    return "python"
                elif "bash" in shebang or "sh" in shebang or "zsh" in shebang:
                    return "shell"
                elif "node" in shebang:
                    return "javascript"
                elif "ruby" in shebang:
                    return "ruby"
                elif "perl" in shebang:
                    return "perl"
                elif "php" in shebang:
                    return "php"
    except (OSError, UnicodeDecodeError):
        pass

    return None


def should_skip_directory(dir_name: str) -> bool:
    """Check if a directory should be skipped during scanning.

    Args:
        dir_name: Name of the directory (not full path).

    Returns:
        True if the directory should be skipped.
    """
    if dir_name in SKIP_DIRECTORIES:
        return True
    # Check wildcard patterns (e.g., *.egg-info)
    for pattern in SKIP_DIRECTORIES:
        if "*" in pattern:
            suffix = pattern.replace("*", "")
            if dir_name.endswith(suffix):
                return True
    return False


def should_skip_file(file_path: str) -> Tuple[bool, str]:
    """Check if a file should be skipped during scanning.

    Args:
        file_path: Full path to the file.

    Returns:
        Tuple of (should_skip, reason).
    """
    basename = os.path.basename(file_path)

    # Skip explicitly excluded files
    if basename in SKIP_FILES:
        return True, "excluded file"

    # Skip hidden files (except special ones)
    if basename.startswith(".") and basename not in SPECIAL_FILENAMES:
        return True, "hidden file"

    # Check file size
    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE_BYTES:
            return True, f"file too large ({file_size / 1_000_000:.1f}MB)"
        if file_size == 0:
            return True, "empty file"
    except OSError:
        return True, "cannot read file"

    # Check if it's a binary file
    if is_binary_file(file_path):
        return True, "binary file"

    # Check if language is supported
    lang = detect_language(file_path)
    if lang is None:
        return True, "unsupported file type"

    return False, ""


def is_binary_file(file_path: str, sample_size: int = 8192) -> bool:
    """Check if a file is binary by reading a sample.

    Args:
        file_path: Path to the file.
        sample_size: Number of bytes to sample.

    Returns:
        True if the file appears to be binary.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            if b"\x00" in chunk:
                return True
            # Check for high ratio of non-text bytes
            text_chars = (
                set(range(32, 127))
                | {9, 10, 13}  # tab, newline, carriage return
            )
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            return non_text / max(len(chunk), 1) > 0.30
    except OSError:
        return True


def read_file_lines(file_path: str) -> Tuple[List[str], Optional[str]]:
    """Read a file and return its lines with error handling.

    Args:
        file_path: Path to the file.

    Returns:
        Tuple of (lines, error_message). If error, lines is empty.
    """
    encodings = ["utf-8", "latin-1", "cp1252", "ascii"]

    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding, errors="strict") as f:
                lines = f.readlines()
            return lines, None
        except (UnicodeDecodeError, UnicodeError):
            continue
        except OSError as e:
            return [], f"Cannot read file: {e}"

    # Fallback: read with error replacement
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return lines, None
    except OSError as e:
        return [], f"Cannot read file: {e}"


def read_file_content(file_path: str) -> Tuple[str, Optional[str]]:
    """Read entire file content as a single string.

    Args:
        file_path: Path to the file.

    Returns:
        Tuple of (content, error_message). If error, content is empty.
    """
    lines, error = read_file_lines(file_path)
    if error:
        return "", error
    return "".join(lines), None


def collect_scannable_files(root_dir: str) -> List[Tuple[str, str, str]]:
    """Walk a directory tree and collect all scannable files.

    Args:
        root_dir: Root directory to scan.

    Returns:
        List of (absolute_path, relative_path, language) tuples.
    """
    scannable = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Filter out directories to skip (modifies dirnames in-place)
        dirnames[:] = [
            d for d in dirnames if not should_skip_directory(d)
        ]

        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(file_path, root_dir)

            should_skip, reason = should_skip_file(file_path)
            if should_skip:
                continue

            language = detect_language(file_path)
            if language:
                scannable.append((file_path, relative_path, language))

    return scannable


def get_file_size_human(size_bytes: int) -> str:
    """Convert file size in bytes to human-readable string.

    Args:
        size_bytes: File size in bytes.

    Returns:
        Human-readable file size string (e.g., '1.2 KB').
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
