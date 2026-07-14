"""Severity level definitions and risk score mapping for RepoSentinel."""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Finding:
    """Represents a single security finding in a scanned file."""

    rule_id: str
    name: str
    category: str
    subcategory: str
    severity: str  # critical, high, medium, low, info
    weight: int  # 0-100
    description: str
    user_message: str
    file_path: str
    line_number: int
    line_content: str
    matched_pattern: str
    mitre_attack: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    context_multiplier: float = 1.0  # Adjusted by context

    @property
    def effective_weight(self) -> float:
        """Calculate effective weight with confidence and context."""
        return self.weight * self.confidence * self.context_multiplier


@dataclass
class FileResult:
    """Scan results for a single file."""

    file_path: str
    relative_path: str
    language: str
    file_size: int
    risk_score: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    permissions_detected: List[str] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    obfuscation_score: float = 0.0
    scan_error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def top_finding(self) -> Optional[Finding]:
        """Return the highest-severity finding."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: f.effective_weight)

    @property
    def severity_label(self) -> str:
        """Return severity label based on risk score."""
        if self.risk_score >= 76:
            return "critical"
        elif self.risk_score >= 56:
            return "high"
        elif self.risk_score >= 36:
            return "moderate"
        elif self.risk_score >= 16:
            return "low"
        return "safe"


@dataclass
class ScanResult:
    """Complete scan results for a repository."""

    repo_url: str
    repo_name: str
    total_files_scanned: int
    total_files_skipped: int
    scan_duration: float  # seconds
    overall_risk_score: float = 0.0
    file_results: List[FileResult] = field(default_factory=list)
    summary_message: str = ""
    verdict: str = ""
    scan_timestamp: str = ""

    @property
    def total_findings(self) -> int:
        return sum(fr.finding_count for fr in self.file_results)

    @property
    def critical_findings(self) -> int:
        return sum(fr.critical_count for fr in self.file_results)

    @property
    def high_findings(self) -> int:
        return sum(fr.high_count for fr in self.file_results)

    @property
    def all_findings(self) -> List[Finding]:
        """Return all findings across all files, sorted by severity."""
        findings = []
        for fr in self.file_results:
            findings.extend(fr.findings)
        return sorted(findings, key=lambda f: f.effective_weight, reverse=True)

    @property
    def all_permissions(self) -> List[str]:
        """Return all unique permissions detected across files."""
        perms = set()
        for fr in self.file_results:
            perms.update(fr.permissions_detected)
        return sorted(perms)

    @property
    def network_indicators(self) -> List[str]:
        """Return all unique network indicators detected across files."""
        indicators = set()
        for fr in self.file_results:
            if hasattr(fr, 'network_indicators'):
                indicators.update(fr.network_indicators)
        return sorted(indicators)

    @property
    def risk_level(self) -> str:
        """Return risk level based on overall score."""
        if self.overall_risk_score >= 76:
            return "critical"
        elif self.overall_risk_score >= 56:
            return "high"
        elif self.overall_risk_score >= 36:
            return "moderate"
        elif self.overall_risk_score >= 16:
            return "low"
        return "safe"

    @property
    def risk_color(self) -> str:
        """Return Rich color string for risk level."""
        colors = {
            "critical": "bold red",
            "high": "bold bright_red",
            "moderate": "bold yellow",
            "low": "bold blue",
            "safe": "bold green",
        }
        return colors.get(self.risk_level, "white")

    @property
    def risk_emoji(self) -> str:
        """Return emoji for risk level."""
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "moderate": "🟡",
            "low": "🔵",
            "safe": "✅",
        }
        return emojis.get(self.risk_level, "⚪")

    @property
    def file_type_breakdown(self) -> dict:
        """Return count of files by language."""
        breakdown = {}
        for fr in self.file_results:
            lang = fr.language
            breakdown[lang] = breakdown.get(lang, 0) + 1
        return breakdown


# ─── Severity Display Configuration ───────────────────────────────────────

SEVERITY_CONFIG = {
    "critical": {
        "emoji": "🔴",
        "color": "bold red",
        "label": "CRITICAL",
        "weight_range": (85, 100),
    },
    "high": {
        "emoji": "🟠",
        "color": "bold bright_red",
        "label": "HIGH",
        "weight_range": (60, 84),
    },
    "medium": {
        "emoji": "🟡",
        "color": "bold yellow",
        "label": "MEDIUM",
        "weight_range": (30, 59),
    },
    "low": {
        "emoji": "🟢",
        "color": "bold blue",
        "label": "LOW",
        "weight_range": (10, 29),
    },
    "info": {
        "emoji": "ℹ️",
        "color": "dim",
        "label": "INFO",
        "weight_range": (1, 9),
    },
}

RISK_VERDICTS = {
    "safe": {
        "emoji": "✅",
        "label": "SAFE",
        "message": "This repository appears safe to use.",
        "recommendation": "You can proceed with using this code, but always review it yourself.",
    },
    "low": {
        "emoji": "🔵",
        "label": "LOW RISK",
        "message": "Minor concerns found — review the flagged items below.",
        "recommendation": "Check the flagged patterns to ensure they are expected for this type of project.",
    },
    "moderate": {
        "emoji": "🟡",
        "label": "MODERATE RISK",
        "message": "Several suspicious patterns detected — proceed with caution.",
        "recommendation": "Carefully review ALL flagged items. Consider running in a sandboxed environment first.",
    },
    "high": {
        "emoji": "🟠",
        "label": "HIGH RISK",
        "message": "Potentially dangerous code found — NOT recommended for execution.",
        "recommendation": "Do NOT run this code without thorough expert review. Multiple suspicious patterns detected.",
    },
    "critical": {
        "emoji": "🔴",
        "label": "CRITICAL RISK",
        "message": "⚠️ MALICIOUS CODE DETECTED — DO NOT EXECUTE THIS CODE!",
        "recommendation": "This code contains patterns strongly associated with malware. AVOID running it entirely.",
    },
}
