"""Regex-based pattern matching engine for RepoSentinel.

Scans file content against the YAML pattern database and detects
dangerous pattern combinations.
"""

from typing import List

from reposentinel.database.loader import PatternDatabase, PatternEntry
from reposentinel.database.severity import Finding


class PatternMatcher:
    """Main pattern matching engine using compiled regex from the database."""

    # Dangerous pattern combinations that escalate severity
    COMBO_PATTERNS = [
        {
            "name": "Reverse Shell (socket + dup2 + subprocess)",
            "requires": ["os.dup2", "socket", "subprocess"],
            "severity": "critical",
            "weight": 98,
            "user_message": "🔴 REVERSE SHELL COMBO DETECTED! socket + dup2 + subprocess = classic reverse shell backdoor!",
            "mitre": "T1059.006",
        },
        {
            "name": "Encoded Execution (base64 + exec)",
            "requires": ["base64", "exec"],
            "severity": "critical",
            "weight": 92,
            "user_message": "🔴 ENCODED EXECUTION! base64 decode + exec = hidden malicious code being executed!",
            "mitre": "T1027",
        },
        {
            "name": "Data Exfiltration (file read + HTTP POST)",
            "requires": ["open(", "requests.post"],
            "severity": "critical",
            "weight": 90,
            "user_message": "🔴 DATA EXFILTRATION! Reads files and sends them to an external server!",
            "mitre": "T1041",
        },
        {
            "name": "Keylogger (keyboard hook + file/network)",
            "requires": ["pynput", "send"],
            "severity": "critical",
            "weight": 95,
            "user_message": "🔴 KEYLOGGER WITH EXFIL! Records keystrokes AND sends them to an attacker!",
            "mitre": "T1056.001",
        },
        {
            "name": "Credential Theft (browser data + webhook)",
            "requires": ["Chrome", "webhook"],
            "severity": "critical",
            "weight": 96,
            "user_message": "🔴 CREDENTIAL THEFT! Steals browser passwords and sends them via webhook!",
            "mitre": "T1555.003",
        },
        {
            "name": "Download and Execute (curl/wget + exec/eval)",
            "requires": ["requests.get", "exec"],
            "severity": "critical",
            "weight": 93,
            "user_message": "🔴 DOWNLOAD & EXECUTE! Downloads code from internet and runs it immediately!",
            "mitre": "T1105",
        },
    ]

    def __init__(self, database: PatternDatabase):
        self.database = database

    def scan_file(self, file_path: str, content: str, lines: List[str],
                  language: str) -> List[Finding]:
        """Scan file content against all patterns for the given language.

        Args:
            file_path: Absolute path to the file.
            content: Full file content as string.
            lines: List of lines in the file.
            language: Detected language of the file.

        Returns:
            List of Finding objects with line numbers.
        """
        findings = []
        patterns = self.database.get_patterns_for_language(language)

        for pattern_entry in patterns:
            for compiled_regex, pattern_str, pattern_type in pattern_entry.compiled_patterns:
                if compiled_regex is None:
                    continue

                for line_num, line in enumerate(lines, start=1):
                    line_stripped = line.rstrip('\n\r')
                    match = compiled_regex.search(line_stripped)
                    if match:
                        finding = Finding(
                            rule_id=pattern_entry.id,
                            name=pattern_entry.name,
                            category=pattern_entry.category,
                            subcategory=pattern_entry.subcategory,
                            severity=pattern_entry.severity,
                            weight=pattern_entry.weight,
                            description=pattern_entry.description,
                            user_message=pattern_entry.user_message,
                            file_path=file_path,
                            line_number=line_num,
                            line_content=line_stripped[:200],
                            matched_pattern=pattern_str,
                            mitre_attack=pattern_entry.mitre_attack,
                        )
                        findings.append(finding)
                        break  # One match per pattern per file is enough

        # Check for dangerous pattern combinations
        combo_findings = self._check_combination_patterns(findings, content, file_path)
        findings.extend(combo_findings)

        return findings

    def _check_combination_patterns(self, findings: List[Finding],
                                     content: str,
                                     file_path: str) -> List[Finding]:
        """Detect dangerous pattern combinations that escalate severity.

        Args:
            findings: Already-detected findings for this file.
            content: Full file content.
            file_path: Path to the file.

        Returns:
            Additional combo findings.
        """
        combo_findings = []
        content_lower = content.lower()

        for combo in self.COMBO_PATTERNS:
            required = combo["requires"]
            all_present = all(
                req.lower() in content_lower for req in required
            )

            if all_present:
                finding = Finding(
                    rule_id=f"COMBO-{combo['name'][:10].upper().replace(' ', '')}",
                    name=f"⚡ Combo: {combo['name']}",
                    category="combination",
                    subcategory="pattern_combo",
                    severity=combo["severity"],
                    weight=combo["weight"],
                    description=f"Dangerous pattern combination: {combo['name']}",
                    user_message=combo["user_message"],
                    file_path=file_path,
                    line_number=0,
                    line_content="[Multiple locations — combined pattern detection]",
                    matched_pattern=" + ".join(required),
                    mitre_attack=combo["mitre"],
                    confidence=0.85,
                    context_multiplier=1.5,
                )
                combo_findings.append(finding)

        return combo_findings
