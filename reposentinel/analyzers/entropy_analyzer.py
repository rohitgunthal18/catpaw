"""Shannon entropy analysis for detecting obfuscated or encoded code.

High-entropy strings are indicative of encoded payloads, encrypted data,
or obfuscated malware.
"""

import math
import re
from collections import Counter
from typing import List, Tuple

from reposentinel.database.severity import Finding


class EntropyAnalyzer:
    """Detects high-entropy strings that may indicate obfuscation."""

    HIGH_ENTROPY_THRESHOLD = 4.5
    VERY_HIGH_ENTROPY_THRESHOLD = 5.5
    MIN_STRING_LENGTH = 20

    def scan_file(self, file_path: str, content: str,
                  lines: List[str]) -> Tuple[List[Finding], float]:
        """Analyze file for high-entropy strings that may indicate obfuscation.

        Args:
            file_path: Path to the file.
            content: Full file content.
            lines: List of lines.

        Returns:
            Tuple of (findings list, obfuscation_score 0-100).
        """
        findings = []
        high_entropy_count = 0
        entropy_values = []

        for line_num, line in enumerate(lines, start=1):
            line_stripped = line.strip()
            # Skip short lines, comments, and blank lines
            if len(line_stripped) < self.MIN_STRING_LENGTH:
                continue
            if line_stripped.startswith(('#', '//', '/*', '*', '--')):
                continue

            strings = self._extract_strings(line_stripped)
            for s in strings:
                if len(s) < self.MIN_STRING_LENGTH:
                    continue

                entropy = self.calculate_entropy(s)
                entropy_values.append(entropy)

                if entropy >= self.VERY_HIGH_ENTROPY_THRESHOLD:
                    high_entropy_count += 1
                    findings.append(Finding(
                        rule_id="ENTROPY-HIGH",
                        name="Very High Entropy String",
                        category="obfuscation",
                        subcategory="entropy",
                        severity="high",
                        weight=70,
                        description=f"String entropy {entropy:.2f} exceeds threshold — likely encoded/encrypted",
                        user_message=f"🟠 OBFUSCATION! High entropy string detected (entropy: {entropy:.1f}) — may be encoded malicious payload",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_stripped[:200],
                        matched_pattern=f"entropy={entropy:.2f}",
                        confidence=min(1.0, (entropy - 4.0) / 2.0),
                    ))
                elif entropy >= self.HIGH_ENTROPY_THRESHOLD:
                    high_entropy_count += 1
                    findings.append(Finding(
                        rule_id="ENTROPY-MED",
                        name="High Entropy String",
                        category="obfuscation",
                        subcategory="entropy",
                        severity="medium",
                        weight=40,
                        description=f"String entropy {entropy:.2f} is elevated — could be encoded data",
                        user_message=f"🟡 Elevated entropy string (entropy: {entropy:.1f}) — could be encoded content",
                        file_path=file_path,
                        line_number=line_num,
                        line_content=line_stripped[:200],
                        matched_pattern=f"entropy={entropy:.2f}",
                        confidence=min(0.8, (entropy - 4.0) / 2.0),
                    ))

        # Calculate overall obfuscation score
        obfuscation_score = self._calculate_obfuscation_score(
            high_entropy_count, entropy_values, len(lines)
        )

        return findings, obfuscation_score

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            data: The string to analyze.

        Returns:
            Shannon entropy value (0-8 for ASCII).
        """
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy

    def _extract_strings(self, line: str) -> List[str]:
        """Extract string literals and long tokens from a line.

        Args:
            line: A single line of source code.

        Returns:
            List of extracted string candidates.
        """
        strings = []

        # Extract quoted strings (single and double)
        for match in re.finditer(r'''(['"])((?:(?!\1).){20,})\1''', line):
            strings.append(match.group(2))

        # Extract base64-like tokens (long alphanumeric + /+=)
        for match in re.finditer(r'\b([A-Za-z0-9+/=]{30,})\b', line):
            strings.append(match.group(1))

        # Extract hex strings
        for match in re.finditer(r'\b([0-9a-fA-F]{40,})\b', line):
            strings.append(match.group(1))

        # If no specific strings found, check the whole line if it's long
        if not strings and len(line) >= 100:
            strings.append(line)

        return strings

    def _calculate_obfuscation_score(self, high_entropy_count: int,
                                      entropy_values: List[float],
                                      total_lines: int) -> float:
        """Calculate overall obfuscation score for a file.

        Args:
            high_entropy_count: Number of high-entropy strings found.
            entropy_values: All entropy measurements.
            total_lines: Total number of lines in the file.

        Returns:
            Obfuscation score from 0 to 100.
        """
        if not entropy_values or total_lines == 0:
            return 0.0

        # Factor 1: Percentage of high-entropy lines (0-40 points)
        high_pct = high_entropy_count / max(total_lines, 1)
        pct_score = min(40, high_pct * 400)

        # Factor 2: Average entropy of flagged strings (0-40 points)
        high_entropies = [e for e in entropy_values if e >= self.HIGH_ENTROPY_THRESHOLD]
        if high_entropies:
            avg_entropy = sum(high_entropies) / len(high_entropies)
            entropy_score = min(40, (avg_entropy - 4.0) * 20)
        else:
            entropy_score = 0

        # Factor 3: Absolute count bonus (0-20 points)
        count_score = min(20, high_entropy_count * 4)

        return min(100.0, pct_score + entropy_score + count_score)
