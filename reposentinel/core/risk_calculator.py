"""Risk calculator for RepoSentinel.

Computes weighted risk scores for individual files and entire repositories
based on findings, confidence, obfuscation, and frequency.
"""

import math
from typing import List, Tuple

from reposentinel.database.severity import Finding, FileResult, RISK_VERDICTS, ScanResult


class RiskCalculator:
    """Calculates risk scores for files and repositories."""

    def calculate_file_risk(self, findings: List[Finding], obfuscation_score: float = 0.0) -> float:
        """Calculate risk score for a single file (0-100).

        Formula:
        score = min(100, sum(finding.effective_weight * frequency_factor * context_multiplier)) + obfuscation_bonus

        Where:
        - effective_weight = weight * confidence * context_multiplier
        - frequency_factor = log2(1 + occurrence_count) for same rule_id (diminishing returns)
        - obfuscation_bonus = obfuscation_score * 0.15 (add up to 15 points for obfuscation)
        """
        if not findings and obfuscation_score == 0.0:
            return 0.0

        score = 0.0
        rule_counts = {}

        # Sort findings by weight descending so we process the most severe first
        sorted_findings = sorted(findings, key=lambda f: f.effective_weight, reverse=True)

        for finding in sorted_findings:
            # Track occurrence count for diminishing returns
            rule_id = finding.rule_id
            rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            occurrence_count = rule_counts[rule_id]

            # Calculate diminishing returns factor: 1st=1.0, 2nd~=0.58, 3rd~=0.41...
            # Using log2(2/occurrence_count + 1) gives a nice curve
            frequency_factor = math.log2(2.0 / occurrence_count + 1.0) if occurrence_count > 1 else 1.0

            # Add to total score
            score += finding.effective_weight * frequency_factor

        # Add obfuscation bonus (up to 15 points)
        obfuscation_bonus = obfuscation_score * 0.15
        score += obfuscation_bonus

        return min(100.0, score)

    def calculate_repo_risk(self, file_results: List[FileResult]) -> float:
        """Calculate overall repository risk score (0-100).

        Method:
        1. Take the top 5 highest-scoring files
        2. Weighted average: 1st file = 40%, 2nd = 25%, 3rd = 15%, 4th = 12%, 5th = 8%
        3. Apply combination bonus if critical findings exist in multiple files
        """
        if not file_results:
            return 0.0

        # Filter out safe files and sort by score descending
        risky_files = sorted(
            [f for f in file_results if f.risk_score > 0],
            key=lambda x: x.risk_score,
            reverse=True
        )

        if not risky_files:
            return 0.0

        # Base score from top 5 files using weighted average
        weights = [0.40, 0.25, 0.15, 0.12, 0.08]
        base_score = 0.0
        
        for i in range(min(5, len(risky_files))):
            base_score += risky_files[i].risk_score * weights[i]
            
        # If there are fewer than 5 files, normalize the score
        # e.g., if only 1 file, it should count for 100%, not 40%
        if len(risky_files) < 5:
            weight_sum = sum(weights[:len(risky_files)])
            if weight_sum > 0:
                base_score = base_score / weight_sum

        # Cross-file combination bonus
        # If there are critical findings spread across multiple files, it indicates
        # a distributed malicious architecture, which is more dangerous
        critical_files_count = sum(1 for f in risky_files if f.critical_count > 0)
        combo_bonus = 0.0
        if critical_files_count > 1:
            # +5 points for each additional file with critical findings, up to 15
            combo_bonus = min(15.0, (critical_files_count - 1) * 5.0)

        # High obfuscation across repo bonus
        highly_obfuscated = sum(1 for f in risky_files if f.obfuscation_score > 60.0)
        if highly_obfuscated > 2:
            combo_bonus += 10.0

        final_score = base_score + combo_bonus
        return min(100.0, final_score)

    def generate_verdict(self, scan_result: ScanResult) -> Tuple[str, str]:
        """Generate verdict label and summary message based on scan results.

        Returns:
            Tuple of (verdict_key, summary_message)
        """
        score = scan_result.overall_risk_score
        
        # Determine verdict key based on thresholds
        if score >= 90:
            verdict_key = "critical"
        elif score >= 70:
            verdict_key = "high"
        elif score >= 40:
            verdict_key = "moderate"
        elif score > 10:
            verdict_key = "low"
        else:
            verdict_key = "safe"
            
        verdict_data = RISK_VERDICTS[verdict_key]
        
        # Build summary message
        msg_parts = [verdict_data["message"]]
        
        # Add context based on findings
        total_critical = scan_result.critical_findings
        if total_critical > 0:
            msg_parts.append(f"Found {total_critical} CRITICAL security issues.")
            
        if scan_result.all_permissions:
            perms = scan_result.all_permissions[:3] # Top 3
            msg_parts.append(f"Script requests access to: {', '.join(perms)}.")
            
        # Add recommendation
        msg_parts.append(f"\nRecommendation: {verdict_data['recommendation']}")
        
        return verdict_key, " ".join(msg_parts)
