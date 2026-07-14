"""Main scanning orchestrator for RepoSentinel.

Coordinates the fetcher, analyzers, and risk calculator to perform
a complete repository scan.
"""

import time
from datetime import datetime
from typing import Callable, Optional

from reposentinel.analyzers.ast_analyzer import ASTAnalyzer
from reposentinel.analyzers.entropy_analyzer import EntropyAnalyzer
from reposentinel.analyzers.network_analyzer import NetworkAnalyzer
from reposentinel.analyzers.pattern_matcher import PatternMatcher
from reposentinel.analyzers.permission_analyzer import PermissionAnalyzer
from reposentinel.core.fetcher import RepoFetcher
from reposentinel.core.file_analyzer import FileAnalyzer
from reposentinel.core.risk_calculator import RiskCalculator
from reposentinel.database.loader import PatternDatabase
from reposentinel.database.severity import ScanResult
from reposentinel.utils.file_utils import collect_scannable_files
from reposentinel.utils.git_utils import get_repo_display_name, validate_github_url


class RepoScanner:
    """Main orchestrator for scanning repositories."""

    def __init__(self, deep_scan: bool = False, github_token: Optional[str] = None):
        """Initialize the scanner and all its components.

        Args:
            deep_scan: If True, enables slower but more thorough AST analysis.
            github_token: Optional GitHub API token for rate limits/private repos.
        """
        self.deep_scan = deep_scan
        
        # Initialize database
        self.database = PatternDatabase()
        self.database.load()
        
        # Initialize analyzers
        pattern_matcher = PatternMatcher(self.database)
        ast_analyzer = ASTAnalyzer()
        entropy_analyzer = EntropyAnalyzer()
        permission_analyzer = PermissionAnalyzer()
        network_analyzer = NetworkAnalyzer()
        
        # Initialize core components
        self.file_analyzer = FileAnalyzer(
            pattern_matcher,
            ast_analyzer,
            entropy_analyzer,
            permission_analyzer,
            network_analyzer,
            deep_scan=deep_scan
        )
        self.risk_calculator = RiskCalculator()
        self.fetcher = RepoFetcher(github_token)

    def scan_repo(self, url: str, 
                  progress_callback: Optional[Callable] = None) -> ScanResult:
        """Fetch and scan a GitHub repository.

        Args:
            url: GitHub repository URL.
            progress_callback: Optional callback for scan progress reporting.
                               Signature: callback(completed_files, total_files, current_file)

        Returns:
            Populated ScanResult object.
        """
        # 1. Validate URL
        is_valid, error_msg = validate_github_url(url)
        if not is_valid:
            raise ValueError(f"Invalid GitHub URL: {error_msg}")
            
        repo_name = get_repo_display_name(url)
        
        # 2. Fetch/clone repo using context manager
        try:
            with self.fetcher.fetch(url) as repo_dir:
                # 3-7. Perform actual scan on local directory
                return self._perform_scan(repo_dir, url, repo_name, progress_callback)
        except Exception as e:
            # Create a failed scan result
            result = ScanResult(
                repo_url=url,
                repo_name=repo_name,
                total_files_scanned=0,
                total_files_skipped=0,
                scan_duration=0.0,
                summary_message=f"Scan failed: {str(e)}",
                verdict="critical" # Fail safe
            )
            return result

    def scan_local_dir(self, directory: str, 
                       progress_callback: Optional[Callable] = None) -> ScanResult:
        """Scan a local directory directly (useful for testing)."""
        return self._perform_scan(
            repo_dir=directory, 
            repo_url=f"file://{directory}", 
            repo_name="Local Directory", 
            progress_callback=progress_callback
        )

    def _perform_scan(self, repo_dir: str, repo_url: str, repo_name: str,
                      progress_callback: Optional[Callable] = None) -> ScanResult:
        """Internal scan logic shared by scan_repo and scan_local_dir."""
        start_time = time.time()
        
        # Initialize result
        result = ScanResult(
            repo_url=repo_url,
            repo_name=repo_name,
            total_files_scanned=0,
            total_files_skipped=0,
            scan_duration=0.0,
            scan_timestamp=datetime.now().isoformat()
        )
        
        # 1. Collect scannable files
        files_to_scan = collect_scannable_files(repo_dir)
        total_files = len(files_to_scan)
        
        if total_files == 0:
            result.summary_message = "No scannable source code files found."
            result.verdict = "safe"
            return result
            
        # 2. Analyze each file
        for i, (abs_path, rel_path, language) in enumerate(files_to_scan, start=1):
            if progress_callback:
                progress_callback(i, total_files, rel_path)
                
            # Analyze file
            file_result = self.file_analyzer.analyze_file(abs_path, rel_path, language)
            
            # Calculate file risk
            file_result.risk_score = self.risk_calculator.calculate_file_risk(
                file_result.findings, 
                file_result.obfuscation_score
            )
            
            # Store result
            result.file_results.append(file_result)
            
        # 3. Finalize results
        result.total_files_scanned = total_files
        result.scan_duration = time.time() - start_time
        
        # 4. Calculate overall repository risk
        result.overall_risk_score = self.risk_calculator.calculate_repo_risk(result.file_results)
        
        # 5. Generate verdict
        verdict_key, summary = self.risk_calculator.generate_verdict(result)
        result.verdict = verdict_key
        result.summary_message = summary
        
        return result
