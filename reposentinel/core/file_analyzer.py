"""Per-file analysis engine for RepoSentinel.

Coordinates all individual analyzers (pattern, AST, entropy, permissions, network)
to generate a comprehensive FileResult for a single file.
"""

from typing import List

from reposentinel.analyzers.ast_analyzer import ASTAnalyzer
from reposentinel.analyzers.entropy_analyzer import EntropyAnalyzer
from reposentinel.analyzers.network_analyzer import NetworkAnalyzer
from reposentinel.analyzers.pattern_matcher import PatternMatcher
from reposentinel.analyzers.permission_analyzer import PermissionAnalyzer
from reposentinel.database.severity import FileResult, Finding
from reposentinel.utils.file_utils import read_file_content, read_file_lines


class FileAnalyzer:
    """Analyzes a single file using all available analyzers."""

    def __init__(self, pattern_matcher: PatternMatcher,
                 ast_analyzer: ASTAnalyzer,
                 entropy_analyzer: EntropyAnalyzer,
                 permission_analyzer: PermissionAnalyzer,
                 network_analyzer: NetworkAnalyzer,
                 deep_scan: bool = False):
        self.pattern_matcher = pattern_matcher
        self.ast_analyzer = ast_analyzer
        self.entropy_analyzer = entropy_analyzer
        self.permission_analyzer = permission_analyzer
        self.network_analyzer = network_analyzer
        self.deep_scan = deep_scan

    def analyze_file(self, file_path: str, relative_path: str,
                     language: str) -> FileResult:
        """Run all applicable analyzers on a single file.

        Args:
            file_path: Absolute path to the file.
            relative_path: Path relative to repository root.
            language: Detected programming language.

        Returns:
            Populated FileResult object.
        """
        result = FileResult(
            file_path=file_path,
            relative_path=relative_path,
            language=language,
            file_size=0
        )

        # 1. Read file content and lines
        content, error_content = read_file_content(file_path)
        lines, error_lines = read_file_lines(file_path)

        if error_content or error_lines:
            result.scan_error = error_content or error_lines
            return result

        result.file_size = len(content)
        all_findings: List[Finding] = []

        # 2. Run pattern matcher (all languages)
        pattern_findings = self.pattern_matcher.scan_file(
            file_path, content, lines, language
        )
        all_findings.extend(pattern_findings)

        # 3. Run AST analyzer (Python only) if deep scan is enabled
        if language == "python" and self.deep_scan:
            ast_findings = self.ast_analyzer.scan_file(file_path, content, lines)
            all_findings.extend(ast_findings)

        # 4. Run entropy analyzer (all languages)
        entropy_findings, obf_score = self.entropy_analyzer.scan_file(
            file_path, content, lines
        )
        all_findings.extend(entropy_findings)
        result.obfuscation_score = obf_score

        # 5. Run permission analyzer (all languages)
        perm_findings, detected_perms = self.permission_analyzer.scan_file(
            file_path, content, lines, language
        )
        all_findings.extend(perm_findings)
        result.permissions_detected = detected_perms

        # 6. Run network analyzer (all languages)
        net_findings, net_indicators = self.network_analyzer.scan_file(
            file_path, content, lines, language
        )
        all_findings.extend(net_findings)
        result.network_indicators = net_indicators

        # 7. Deduplicate findings
        result.findings = self._deduplicate_findings(all_findings)

        return result

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings for the same line and category.

        Keep the highest-weight finding for each line+category combo to
        prevent alert fatigue on the same snippet of code.
        """
        deduped = {}

        for finding in findings:
            # Combo rules and AST rules apply to the whole file or structural blocks,
            # so they get a special key (-1 for line number) if line_number is 0
            line_key = finding.line_number
            if finding.rule_id.startswith("COMBO-"):
                line_key = -1
                
            key = (line_key, finding.category)

            if key not in deduped:
                deduped[key] = finding
            else:
                # Keep the one with the higher effective weight
                existing = deduped[key]
                if finding.effective_weight > existing.effective_weight:
                    deduped[key] = finding

        # Sort findings by line number, then by severity
        return sorted(list(deduped.values()), key=lambda x: (x.line_number, -x.effective_weight))
