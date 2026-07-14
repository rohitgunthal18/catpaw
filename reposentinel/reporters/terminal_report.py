"""Rich-powered terminal reporting for RepoSentinel.

Provides beautiful, colorful, and highly readable terminal output
for scan results.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.align import Align
from rich.rule import Rule
from rich.padding import Padding
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn, 
    TimeElapsedColumn, TaskID
)

from reposentinel.database.severity import ScanResult, SEVERITY_CONFIG, RISK_VERDICTS
from reposentinel.utils.constants import BANNER, APP_VERSION, APP_TAGLINE, APP_DESCRIPTION


class TerminalReporter:
    """Handles all terminal-based visual output."""

    def __init__(self):
        self.console = Console()
        self.progress: Progress = None
        self.scan_task: TaskID = None

    def print_banner(self):
        """Print the ASCII art banner with styling."""
        formatted_banner = BANNER.format(
            version=APP_VERSION,
            tagline=APP_TAGLINE,
            description=APP_DESCRIPTION
        )
        self.console.print(f"[bold cyan]{formatted_banner}[/bold cyan]")
        self.console.print()

    def print_scan_start(self, url: str):
        """Print scan initiation message."""
        self.console.print(f"[bold]Target:[/bold] [link={url}]{url}[/link]")
        self.console.print("[dim]Initializing scanners and loading patterns...[/dim]")

    def print_fetch_status(self, status: str, success: bool = True):
        """Print repo fetch status (cloning/downloading)."""
        if success:
            self.console.print(f"[green]✓[/green] {status}")
        else:
            self.console.print(f"[red]✗[/red] {status}")

    def create_progress(self):
        """Create and return a Rich Progress bar and a live status display."""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold orange3]Scanning..."),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TextColumn("[dim]{task.completed}/{task.total} files[/dim]"),
            TimeElapsedColumn(),
            console=self.console,
        )
        return self.progress

    def print_results(self, scan_result: ScanResult):
        """Print complete scan results."""
        self.console.print("\n")
        
        # 1. Title
        title = Text("Cat Paw Scan Complete", style="bold white on dark_orange", justify="center")
        self.console.print(Panel(title, box=box.ASCII))
        
        # 2. Overall Risk Score & Gauge
        verdict_data = RISK_VERDICTS.get(scan_result.verdict, RISK_VERDICTS["safe"])
        color = SEVERITY_CONFIG.get(scan_result.verdict, SEVERITY_CONFIG["info"])["color"]
        emoji = verdict_data["emoji"]
        
        score_text = Text(f"{scan_result.overall_risk_score:.1f}/100", style=f"bold {color}")
        
        cols = Columns([
            Panel(
                Align.center(score_text, vertical="middle"), 
                title="Overall Risk Score", 
                border_style=color,
                box=box.ASCII,
                width=30
            ),
            Panel(
                self._create_risk_gauge(scan_result.overall_risk_score, color),
                title="Risk Level",
                border_style=color,
                box=box.ASCII
            )
        ])
        self.console.print(cols)
        self.console.print()

        # 3. Quick Stats
        stats = Table.grid(padding=(0, 2))
        stats.add_row(
            "[bold]Repository:[/bold]", scan_result.repo_name,
            "[bold]Duration:[/bold]", f"{scan_result.scan_duration:.1f}s"
        )
        stats.add_row(
            "[bold]Files Scanned:[/bold]", str(scan_result.total_files_scanned),
            "[bold]Total Findings:[/bold]", str(scan_result.total_findings)
        )
        self.console.print(Padding(stats, (0, 2)))
        self.console.print(Rule(characters="-", style="dim"))

        if scan_result.total_findings == 0:
            self.console.print("\n[bold green]✅ No malicious patterns or suspicious code found![/bold green]")
            return

        # 4. Permissions & Network (Moved up)
        if scan_result.all_permissions or scan_result.network_indicators:
            cols_data = []
            if scan_result.all_permissions:
                perms_list = "\n".join(scan_result.all_permissions)
                cols_data.append(Panel(perms_list, title="Permissions Requested", border_style="cyan"))
                
            if scan_result.network_indicators:
                net_list = "\n".join(list(set(scan_result.network_indicators))[:5])
                if len(set(scan_result.network_indicators)) > 5:
                    net_list += "\n[dim]...and more[/dim]"
                cols_data.append(Panel(net_list, title="Network Indicators", border_style="blue"))
                
            self.console.print(Columns(cols_data))
            self.console.print()

        # 5. Combined File Table (Suspicious Files Detected)
        self.console.print(Align.center("[bold orange3]SUSPICIOUS FILES DETECTED[/bold orange3]"))
        self.console.print(Rule(characters="-", style="bold orange3"))
        self._print_unified_file_table(scan_result)

        # 6. Final Verdict Panel
        self._print_verdict(scan_result, verdict_data, color)

    def _create_risk_gauge(self, score: float, color: str) -> Text:
        """Create a visual gauge bar like: [==========..........] 78/100."""
        total_blocks = 20
        filled_blocks = int((score / 100.0) * total_blocks)
        empty_blocks = total_blocks - filled_blocks
        
        # Use simple ASCII characters that work in all terminals (e.g., Windows cmd)
        bar_filled = "=" * filled_blocks
        bar_empty = "." * empty_blocks
        
        # Colorize parts of the bar
        result = Text()
        if score < 20:
            result.append(bar_filled, style="green")
            result.append(bar_empty, style="dim green")
        elif score < 50:
            result.append(bar_filled[:total_blocks//2], style="green")
            result.append(bar_filled[total_blocks//2:], style="yellow")
            result.append(bar_empty, style="dim yellow")
        elif score < 80:
            result.append(bar_filled[:total_blocks//3], style="green")
            result.append(bar_filled[total_blocks//3:total_blocks*2//3], style="yellow")
            result.append(bar_filled[total_blocks*2//3:], style="orange3")
            result.append(bar_empty, style="dim orange3")
        else:
            result.append(bar_filled[:total_blocks//4], style="green")
            result.append(bar_filled[total_blocks//4:total_blocks//2], style="yellow")
            result.append(bar_filled[total_blocks//2:total_blocks*3//4], style="orange3")
            result.append(bar_filled[total_blocks*3//4:], style="red")
            result.append(bar_empty, style="dim red")
            
        return result

    def _print_unified_file_table(self, scan_result: ScanResult):
        """Print a unified table of suspicious files and their specific indicators."""
        table = Table(box=box.ASCII, show_lines=True, padding=(0, 1))
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Severity")
        table.add_column("Suspicious Indicators Found")

        # Sort files by risk score
        risky_files = sorted(
            [f for f in scan_result.file_results if f.risk_score > 0],
            key=lambda x: x.risk_score,
            reverse=True
        )
        
        # Display top 15 files to avoid terminal spam
        display_files = risky_files[:15]

        for file in display_files:
            # Format severity label
            score_color = SEVERITY_CONFIG.get(file.severity_label.lower(), SEVERITY_CONFIG["info"])["color"]
            sev_label = f"[{score_color}]{file.severity_label.upper()}[/{score_color}]"

            # Truncate filename if too long
            filename = file.relative_path
            if len(filename) > 40:
                filename = "..." + filename[-37:]

            # Aggregate findings for this file
            file.findings.sort(key=lambda x: x.effective_weight, reverse=True)
            
            # Show up to 4 top findings for this file
            finding_strs = []
            for finding in file.findings[:4]:
                f_sev = SEVERITY_CONFIG.get(finding.severity, SEVERITY_CONFIG["info"])
                f_color = f_sev["color"]
                f_emoji = f_sev["emoji"]
                
                finding_name = finding.name
                if finding.severity == "critical":
                    finding_name = f"[bold red]{finding_name}[/bold red]"
                
                finding_strs.append(f"{f_emoji} [{f_color}]{finding_name}[/{f_color}]")
                
            if len(file.findings) > 4:
                finding_strs.append(f"[dim]... and {len(file.findings) - 4} more[/dim]")
                
            indicators_col = "\n".join(finding_strs)
            table.add_row(filename, sev_label, indicators_col)

        if len(risky_files) > 15:
            table.add_row(
                f"... and {len(risky_files) - 15} more files", 
                "", 
                "[dim]Run with JSON export to see all files.[/dim]"
            )

        self.console.print(table)

    def _print_verdict(self, scan_result: ScanResult, verdict_data: dict, color: str):
        """Print final verdict in a styled panel."""
        self.console.print()
        
        title = f"{verdict_data['emoji']} Final Verdict: {verdict_data['label']} {verdict_data['emoji']}"
        
        # Format the summary message to bold the recommendation
        msg = scan_result.summary_message
        if "Recommendation:" in msg:
            parts = msg.split("Recommendation:")
            msg = f"{parts[0]}\n\n[bold]Recommendation:[/bold]{parts[1]}"
            
        panel = Panel(
            msg,
            title=f"[{color} bold]{title}[/]",
            border_style=color,
            box=box.ASCII,
            padding=(1, 2)
        )
        self.console.print(panel)
        self.console.print()
