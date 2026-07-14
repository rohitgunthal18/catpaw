"""Command Line Interface for Cat Paw.

Provides the entry points for scanning repositories and local directories.
"""

import os
import sys
from collections import deque

import click
from rich.console import Console, Group
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt
from rich.panel import Panel

from reposentinel.core.scanner import RepoScanner
from reposentinel.reporters.json_report import JSONReporter
from reposentinel.reporters.terminal_report import TerminalReporter
from reposentinel.utils.git_utils import validate_github_url

# Standardize output for Click
console = Console()


@click.group(invoke_without_command=True, context_settings=dict(help_option_names=[]))
@click.pass_context
def cli_group(ctx):
    """Cat Paw - GitHub Repository Security Scanner"""
    pass


@cli_group.command()
@click.argument('url')
@click.option('--deep', is_flag=True, help='Enable deep AST analysis (slower but more thorough)')
@click.option('--export', type=click.Path(), help='Export report to JSON file')
@click.option('--no-banner', is_flag=True, help='Hide the ASCII art banner')
def scan(url: str, deep: bool, export: str, no_banner: bool):
    """Scan a GitHub repository for malicious code."""
    _run_scan(url, deep, export, no_banner)


@cli_group.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--deep', is_flag=True, help='Enable deep AST analysis (slower but more thorough)')
@click.option('--export', type=click.Path(), help='Export report to JSON file')
@click.option('--no-banner', is_flag=True, help='Hide the ASCII art banner')
def local(directory: str, deep: bool, export: str, no_banner: bool):
    """Scan a local directory for malicious code."""
    _run_local(directory, deep, export, no_banner)


def _run_scan(url: str, deep: bool = False, export: str = None, no_banner: bool = False):
    reporter = TerminalReporter()
    if not no_banner:
        reporter.print_banner()
        
    is_valid, error_msg = validate_github_url(url)
    if not is_valid:
        console.print(f"[bold red]Error:[/bold red] {error_msg}")
        sys.exit(1)
        
    try:
        reporter.print_scan_start(url)
        scanner = RepoScanner(deep_scan=deep)
        
        progress = reporter.create_progress()
        recent_files = deque(maxlen=5)
        
        def render_ui():
            log_text = Text()
            for f in recent_files:
                log_text.append(f"  🐾 Scanning {f} ...\n", style="dim")
            return Group(progress, log_text)

        with Live(render_ui(), console=console, refresh_per_second=10, transient=True) as live:
            task = progress.add_task("[orange3]Fetching repository...", total=None)
            
            def progress_callback(completed: int, total: int, current_file: str):
                recent_files.append(current_file)
                progress.update(
                    task, 
                    completed=completed, 
                    total=total,
                    description="[orange3]Scanning...[/orange3]"
                )
                live.update(render_ui())
                
            scan_result = scanner.scan_repo(url, progress_callback)
            
        if scan_result.total_files_scanned == 0 and "Scan failed" in scan_result.summary_message:
            console.print(f"\n[bold red]Error:[/bold red] {scan_result.summary_message}")
            sys.exit(1)
            
        reporter.print_results(scan_result)
        
        if export:
            json_reporter = JSONReporter()
            if json_reporter.export(scan_result, export):
                console.print(f"\n[bold green]✓[/bold green] Report exported successfully to [cyan]{export}[/cyan]")
            else:
                console.print(f"\n[bold red]✗[/bold red] Failed to export report to {export}")
                
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user. Cleaning up...[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {str(e)}")
        sys.exit(1)


def _run_local(directory: str, deep: bool = False, export: str = None, no_banner: bool = False):
    reporter = TerminalReporter()
    if not no_banner:
        reporter.print_banner()
        
    abs_path = os.path.abspath(directory)
    reporter.print_scan_start(abs_path)
    
    try:
        scanner = RepoScanner(deep_scan=deep)
        
        progress = reporter.create_progress()
        recent_files = deque(maxlen=5)
        
        def render_ui():
            log_text = Text()
            for f in recent_files:
                log_text.append(f"  🐾 Scanning {f} ...\n", style="dim")
            return Group(progress, log_text)

        with Live(render_ui(), console=console, refresh_per_second=10, transient=True) as live:
            task = progress.add_task("[orange3]Scanning...", total=None)
            
            def progress_callback(completed: int, total: int, current_file: str):
                recent_files.append(current_file)
                progress.update(task, completed=completed, total=total)
                live.update(render_ui())
                
            scan_result = scanner.scan_local_dir(abs_path, progress_callback)
            
        reporter.print_results(scan_result)
        
        if export:
            json_reporter = JSONReporter()
            if json_reporter.export(scan_result, export):
                console.print(f"\n[bold green]✓[/bold green] Report exported successfully to [cyan]{export}[/cyan]")
            else:
                console.print(f"\n[bold red]✗[/bold red] Failed to export report to {export}")
                
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred:[/bold red] {str(e)}")
        sys.exit(1)


def interactive_mode():
    reporter = TerminalReporter()
    reporter.print_banner()
    
    console.print("[bold]Welcome to Cat Paw! What would you like to do?[/bold]")
    console.print("1. Scan a GitHub Repository")
    console.print("2. Scan a Local File or Directory")
    console.print("3. Exit")
    
    choice = Prompt.ask("Selection", choices=["1", "2", "3"], default="1")
    
    if choice == "1":
        url = Prompt.ask("Enter the GitHub repository URL")
        _run_scan(url, no_banner=True)
    elif choice == "2":
        path = Prompt.ask("Enter the local directory path")
        _run_local(path, no_banner=True)
    else:
        console.print("Goodbye!")
        sys.exit(0)


def custom_help():
    reporter = TerminalReporter()
    reporter.print_banner()
    
    about_text = (
        "Cat Paw is an advanced terminal-based security scanner designed to "
        "protect developers by identifying malicious code, dangerous permissions, "
        "and backdoors in GitHub repositories before they are executed."
    )
    console.print(Panel(about_text, title="About Cat Paw", border_style="orange3"))
    console.print()
    
    console.print("[bold]Available Commands:[/bold]")
    console.print("1. [cyan]catpaw scan [githuburl][/cyan]  - Download and scan a remote repository")
    console.print("2. [cyan]catpaw local [path][/cyan]      - Scan a local directory or file")
    console.print()
    
    choice = Prompt.ask("Which command would you like to use?", choices=["1", "2", "q"], default="q")
    
    if choice == "1":
        url = Prompt.ask("Please enter the [cyan]githuburl[/cyan]")
        _run_scan(url, no_banner=True)
    elif choice == "2":
        path = Prompt.ask("Please enter the local [cyan]path[/cyan]")
        _run_local(path, no_banner=True)
    else:
        sys.exit(0)


def main():
    args = sys.argv[1:]
    
    if not args:
        interactive_mode()
        return
        
    if '--help' in args or '-h' in args:
        custom_help()
        return
        
    cli_group(args)


if __name__ == '__main__':
    main()
