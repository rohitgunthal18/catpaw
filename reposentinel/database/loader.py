"""Pattern database loader for RepoSentinel.

Loads and indexes YAML pattern files for efficient lookup during scanning.
"""

import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from reposentinel.utils.constants import DATABASE_DIR


class PatternEntry:
    """A single pattern rule loaded from the YAML database."""

    __slots__ = [
        "id", "name", "category", "subcategory", "severity", "weight",
        "languages", "description", "user_message", "compiled_patterns",
        "mitre_attack", "false_positive_note",
    ]

    def __init__(self, data: dict):
        self.id: str = data.get("id", "UNKNOWN")
        self.name: str = data.get("name", "Unknown Pattern")
        self.category: str = data.get("category", "unknown")
        self.subcategory: str = data.get("subcategory", "unknown")
        self.severity: str = data.get("severity", "info")
        self.weight: int = int(data.get("weight", 0))
        self.languages: List[str] = data.get("languages", ["all"])
        self.description: str = data.get("description", "")
        self.user_message: str = data.get("user_message", "")
        self.mitre_attack: str = data.get("mitre_attack", "")
        self.false_positive_note: str = data.get("false_positive_note", "")

        # Compile regex patterns at load time for performance
        self.compiled_patterns: List[Tuple[Optional[re.Pattern], str, str]] = []
        for mp in data.get("match_patterns", []):
            pattern_str = mp.get("pattern", "")
            pattern_type = mp.get("type", "literal")
            try:
                if pattern_type == "regex":
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                else:
                    # For literal patterns, escape and compile
                    compiled = re.compile(re.escape(pattern_str), re.IGNORECASE)
                self.compiled_patterns.append((compiled, pattern_str, pattern_type))
            except re.error:
                # Skip invalid patterns
                self.compiled_patterns.append((None, pattern_str, pattern_type))

    def __repr__(self) -> str:
        return f"<PatternEntry {self.id}: {self.name}>"


class PatternDatabase:
    """Loads, indexes, and provides efficient lookups for malicious code patterns."""

    def __init__(self, patterns_dir: Optional[str] = None):
        self.patterns_dir = patterns_dir or DATABASE_DIR
        self._all_patterns: List[PatternEntry] = []
        self._by_language: Dict[str, List[PatternEntry]] = {}
        self._by_category: Dict[str, List[PatternEntry]] = {}
        self._loaded = False

    def load(self) -> int:
        """Load all YAML pattern files from the patterns directory.

        Returns:
            Number of patterns loaded.
        """
        self._all_patterns = []
        self._by_language = {}
        self._by_category = {}

        if not os.path.isdir(self.patterns_dir):
            return 0

        yaml_files = [
            f for f in os.listdir(self.patterns_dir)
            if f.endswith(('.yaml', '.yml'))
        ]

        for yaml_file in sorted(yaml_files):
            filepath = os.path.join(self.patterns_dir, yaml_file)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)

                if not data or 'patterns' not in data:
                    continue

                for pattern_data in data['patterns']:
                    entry = PatternEntry(pattern_data)
                    if not entry.compiled_patterns:
                        continue  # Skip entries with no valid patterns

                    self._all_patterns.append(entry)

                    # Index by language
                    for lang in entry.languages:
                        if lang not in self._by_language:
                            self._by_language[lang] = []
                        self._by_language[lang].append(entry)

                    # Index by category
                    if entry.category not in self._by_category:
                        self._by_category[entry.category] = []
                    self._by_category[entry.category].append(entry)

            except (yaml.YAMLError, OSError, KeyError) as e:
                # Skip files that can't be loaded
                continue

        self._loaded = True
        return len(self._all_patterns)

    def get_patterns_for_language(self, language: str) -> List[PatternEntry]:
        """Get all patterns applicable to a specific language.

        Includes language-specific patterns AND 'all' language patterns.

        Args:
            language: Language name (e.g., 'python', 'shell').

        Returns:
            List of applicable PatternEntry objects.
        """
        patterns = []
        # Get language-specific patterns
        if language in self._by_language:
            patterns.extend(self._by_language[language])
        # Get universal patterns (language='all')
        if 'all' in self._by_language:
            patterns.extend(self._by_language['all'])
        return patterns

    def get_all_patterns(self) -> List[PatternEntry]:
        """Get all loaded patterns.

        Returns:
            List of all PatternEntry objects.
        """
        return self._all_patterns

    def get_patterns_by_category(self, category: str) -> List[PatternEntry]:
        """Get patterns for a specific category.

        Args:
            category: Category name (e.g., 'network', 'persistence').

        Returns:
            List of PatternEntry objects in that category.
        """
        return self._by_category.get(category, [])

    @property
    def total_patterns(self) -> int:
        """Total number of loaded patterns."""
        return len(self._all_patterns)

    @property
    def categories(self) -> List[str]:
        """List of all pattern categories."""
        return sorted(self._by_category.keys())

    @property
    def languages(self) -> List[str]:
        """List of all supported languages."""
        return sorted(self._by_language.keys())

    @property
    def is_loaded(self) -> bool:
        """Whether the database has been loaded."""
        return self._loaded
