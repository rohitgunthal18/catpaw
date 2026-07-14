"""JSON reporter for RepoSentinel.

Exports scan results to a machine-readable JSON format for integration
with other security tools or CI/CD pipelines.
"""

import json
from dataclasses import asdict
from typing import Any, Dict

from reposentinel.database.severity import ScanResult, Finding, FileResult


class JSONReporter:
    """Exports scan results to JSON."""

    def export(self, scan_result: ScanResult, output_path: str) -> bool:
        """Export scan results to JSON file.

        Args:
            scan_result: The populated ScanResult object.
            output_path: Path where the JSON file should be written.

        Returns:
            True if export was successful, False otherwise.
        """
        try:
            data = self._to_dict(scan_result)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except (IOError, TypeError, ValueError) as e:
            print(f"Error exporting JSON report: {str(e)}")
            return False

    def _to_dict(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to a structured, JSON-serializable dictionary."""
        # Convert dataclass to dict
        data = asdict(scan_result)
        
        # Add computed properties that aren't included by asdict
        data["risk_level"] = scan_result.risk_level
        data["critical_findings"] = scan_result.critical_findings
        data["high_findings"] = scan_result.high_findings
        data["total_findings"] = scan_result.total_findings
        data["all_permissions"] = scan_result.all_permissions
        data["file_type_breakdown"] = scan_result.file_type_breakdown
        
        # Enhance file results with their computed properties
        for i, file_res in enumerate(scan_result.file_results):
            data["file_results"][i]["finding_count"] = file_res.finding_count
            data["file_results"][i]["critical_count"] = file_res.critical_count
            data["file_results"][i]["high_count"] = file_res.high_count
            data["file_results"][i]["severity_label"] = file_res.severity_label
            
            # The top finding is an object, handle it explicitly
            top = file_res.top_finding
            if top:
                # Add a reference to the top finding
                data["file_results"][i]["top_finding_id"] = top.rule_id
                
        # Reorder for better readability (summary at top, details at bottom)
        ordered_data = {
            "metadata": {
                "timestamp": scan_result.scan_timestamp,
                "target_url": scan_result.repo_url,
                "target_name": scan_result.repo_name,
                "duration_seconds": round(scan_result.scan_duration, 2),
            },
            "summary": {
                "overall_risk_score": round(scan_result.overall_risk_score, 1),
                "risk_level": scan_result.risk_level,
                "verdict": scan_result.verdict,
                "verdict_message": scan_result.summary_message,
                "files_scanned": scan_result.total_files_scanned,
                "files_skipped": scan_result.total_files_skipped,
                "total_findings": scan_result.total_findings,
                "critical_findings": scan_result.critical_findings,
                "high_findings": scan_result.high_findings,
                "all_permissions": scan_result.all_permissions,
            },
            "file_type_breakdown": scan_result.file_type_breakdown,
            "results": data["file_results"]
        }
        
        return ordered_data
