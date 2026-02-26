# sentinel/reporters/console_reporter.py

"""
Console report generator for Script Sentinel analysis results.

Provides rich, color-coded console output with tables, panels, and visual
hierarchy for quick analysis result scanning. Uses the Rich library for
cross-platform terminal formatting.
"""

import logging
from typing import Optional, List, Dict, Any
from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from sentinel.models import AnalysisResult, Finding, Verdict

logger = logging.getLogger(__name__)

# Severity color mapping (Rich color names)
SEVERITY_COLORS = {
    'Critical': 'bright_red',
    'High': 'red',
    'Medium': 'yellow',
    'Low': 'cyan',
    'Informational': 'blue'
}

# Verdict color and emoji mapping
VERDICT_STYLES = {
    Verdict.MALICIOUS: {'color': 'bright_red', 'emoji': '🚨', 'label': 'MALICIOUS'},
    Verdict.SUSPICIOUS: {'color': 'yellow', 'emoji': '⚠️', 'label': 'SUSPICIOUS'},
    Verdict.BENIGN: {'color': 'green', 'emoji': '✅', 'label': 'BENIGN'},
    Verdict.UNKNOWN: {'color': 'white', 'emoji': '❓', 'label': 'UNKNOWN'}
}


class ConsoleReporter:
    """
    Generates rich console reports from analysis results.
    
    Uses the Rich library to create color-coded, visually hierarchical
    console output with panels, tables, and proper formatting. Supports
    cross-platform terminals (Windows, macOS, Linux) with automatic
    fallback for non-color terminals.
    
    Examples:
        >>> from sentinel.models import AnalysisResult, Verdict
        >>> result = AnalysisResult(verdict=Verdict.SUSPICIOUS, confidence_score=0.75)
        >>> reporter = ConsoleReporter()
        >>> output = reporter.generate(result)
        >>> print(output)  # Rich formatted console output
    """
    
    def __init__(self, max_findings: int = 20, max_snippet_length: int = 80):
        """
        Initialize the console reporter.
        
        Args:
            max_findings: Maximum number of findings to display (default: 20).
                         Prevents overwhelming output for large reports.
            max_snippet_length: Maximum length for code snippets (default: 80).
                               Longer snippets are truncated with ellipsis.
        """
        self.max_findings = max_findings
        self.max_snippet_length = max_snippet_length
    
    def generate(self, result: AnalysisResult, verbose: bool = False) -> str:
        """
        Generate console report string from analysis result.
        
        Creates a rich, unified console report with verdict, findings (with code snippets),
        IOCs, and metadata in a single cohesive view. Output is optimized for
        quick scanning (< 5 seconds) with clear visual hierarchy.
        
        Args:
            result: AnalysisResult object from analyzer.
            verbose: If True, show all findings. If False, limit to max_findings.
        
        Returns:
            Formatted console output string with ANSI color codes.
        
        Raises:
            TypeError: If result is not an AnalysisResult instance.
        
        Examples:
            >>> reporter = ConsoleReporter()
            >>> output = reporter.generate(result, verbose=False)
            >>> print(output)  # Display in terminal
        """
        if not isinstance(result, AnalysisResult):
            raise TypeError(f"Expected AnalysisResult, got {type(result).__name__}")
        
        # Create string buffer for output
        output_buffer = StringIO()
        console = Console(file=output_buffer, force_terminal=True, width=120)
        
        try:
            # Render unified report
            self._render_unified_report(console, result, verbose)
            
            # Get output string
            output = output_buffer.getvalue()
            logger.debug(f"Generated console report ({len(output)} bytes, verbose={verbose})")
            return output
            
        except Exception as e:
            logger.error(f"Failed to generate console report: {e}")
            raise
        finally:
            output_buffer.close()
    
    def _render_unified_report(self, console: Console, result: AnalysisResult, verbose: bool) -> None:
        """
        Render a unified, single-panel report with all analysis information.
        
        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
            verbose: If True, show all findings.
        """
        # Build the unified report content
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.columns import Columns
        
        # Header: Verdict and Metadata
        self._render_verdict_panel(console, result)
        console.print()
        
        # Main content: Findings with code snippets
        if result.findings:
            self._render_findings_with_snippets(console, result, verbose)
        else:
            self._render_no_findings(console)
        
        console.print()

        # Footer: IOCs, YARA, and Metadata
        if result.iocs and any(result.iocs.values()):
            self._render_iocs_compact(console, result)
            console.print()

        # YARA contribution summary (if matches exist)
        if result.yara_contribution and result.yara_contribution.matches > 0:
            self._render_yara_summary(console, result)
            console.print()

        # ML contribution summary (if score > 0)
        score_breakdown = result.metadata.get('score_breakdown')
        if score_breakdown:
            ml_score = score_breakdown.get('scorer_scores', {}).get('ml', 0)
            if ml_score > 0:
                self._render_ml_summary(console, result, score_breakdown)
                console.print()

        self._render_metadata_compact(console, result)
    
    def _render_verdict_panel(self, console: Console, result: AnalysisResult) -> None:
        """
        Render the verdict panel with emoji, verdict, and confidence score.
        
        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        style = VERDICT_STYLES.get(result.verdict, VERDICT_STYLES[Verdict.UNKNOWN])
        
        # Create verdict text with emoji
        verdict_text = Text()
        verdict_text.append(f"{style['emoji']} ", style=style['color'])
        verdict_text.append(style['label'], style=f"bold {style['color']}")
        
        # Add confidence score
        confidence_pct = result.confidence_score * 100
        verdict_text.append(f"\nConfidence: {confidence_pct:.1f}%", style="white")
        
        # Create panel
        panel = Panel(
            verdict_text,
            title="[bold]Analysis Verdict[/bold]",
            border_style=style['color'],
            box=box.DOUBLE,
            padding=(1, 2)
        )
        
        console.print(panel)
    
    def _render_findings_table(
        self,
        console: Console,
        result: AnalysisResult,
        verbose: bool
    ) -> None:
        """
        Render findings table with severity-based color coding.
        
        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
            verbose: If True, show all findings. If False, show only High/Critical (max 5).
        """
        # Filter by severity if not verbose (only High and Critical)
        findings_to_display = result.findings
        if not verbose:
            findings_to_display = [f for f in result.findings if f.severity in {'High', 'Critical'}]
        
        # Sort findings by priority (severity + confidence)
        sorted_findings = sorted(
            findings_to_display,
            key=lambda f: f.get_priority_score(),
            reverse=True
        )
        
        # Limit findings count based on verbose mode
        display_findings = sorted_findings
        truncated = False
        max_display = self.max_findings if verbose else 5
        if len(sorted_findings) > max_display:
            display_findings = sorted_findings[:max_display]
            truncated = True
        
        # Create table
        table = Table(
            title=f"[bold]Security Findings[/bold] ({len(display_findings)} shown)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )
        
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Line", justify="right", width=6)
        table.add_column("Description", width=50)
        table.add_column("Pattern", width=12)
        
        # Add findings rows
        for finding in display_findings:
            severity_color = SEVERITY_COLORS.get(finding.severity, 'white')
            
            # Format line number
            line_str = str(finding.line_number) if finding.line_number else "—"
            
            # Truncate description if needed
            description = finding.description
            if len(description) > 60:
                description = description[:57] + "..."
            
            table.add_row(
                f"[{severity_color}]{finding.severity}[/{severity_color}]",
                line_str,
                description,
                finding.pattern_id
            )
        
        console.print(table)
        
        # Show truncation message if applicable
        if truncated:
            max_display = self.max_findings if verbose else 5
            remaining = len(sorted_findings) - max_display
            console.print(
                f"[dim]... and {remaining} more findings (use --verbose to see all)[/dim]"
            )
        elif not verbose and len(result.findings) > len(findings_to_display):
            # Show message about filtered findings
            filtered_count = len(result.findings) - len(findings_to_display)
            console.print(
                f"[dim]{filtered_count} Low/Medium/Informational findings hidden (use --verbose to see all)[/dim]"
            )
    
    def _render_findings_with_snippets(
        self,
        console: Console,
        result: AnalysisResult,
        verbose: bool
    ) -> None:
        """
        Render findings with code snippets in an expanded format.
        
        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
            verbose: If True, show all findings.
        """
        # Filter by severity if not verbose
        findings_to_display = result.findings
        if not verbose:
            findings_to_display = [f for f in result.findings if f.severity in {'High', 'Critical'}]
        
        # Sort findings by priority
        sorted_findings = sorted(
            findings_to_display,
            key=lambda f: f.get_priority_score(),
            reverse=True
        )
        
        # Limit findings count
        max_display = self.max_findings if verbose else 5
        display_findings = sorted_findings[:max_display]
        truncated = len(sorted_findings) > max_display
        
        # Create main findings panel
        console.print(f"[bold cyan]━━━ Security Findings ({len(display_findings)} shown) ━━━[/bold cyan]")
        console.print()
        
        # Render each finding with its code snippet
        for idx, finding in enumerate(display_findings, 1):
            self._render_single_finding(console, finding, idx)
            if idx < len(display_findings):
                console.print()  # Spacing between findings
        
        # Show truncation message
        if truncated:
            remaining = len(sorted_findings) - max_display
            console.print()
            console.print(
                f"[dim]... and {remaining} more findings (use --verbose to see all)[/dim]"
            )
        elif not verbose and len(result.findings) > len(findings_to_display):
            filtered_count = len(result.findings) - len(findings_to_display)
            console.print()
            console.print(
                f"[dim]{filtered_count} Low/Medium/Informational findings hidden (use --verbose to see all)[/dim]"
            )
    
    def _render_single_finding(self, console: Console, finding: Finding, index: int) -> None:
        """
        Render a single finding with its code snippet.

        Args:
            console: Rich Console instance.
            finding: Finding object.
            index: Finding number for display.
        """
        severity_color = SEVERITY_COLORS.get(finding.severity, 'white')

        # Create finding header
        header = Text()
        header.append(f"[{index}] ", style="bold white")

        # Add source indicator prefix
        if finding.source == 'yara':
            header.append("[YARA] ", style="bold magenta")
        elif finding.source == 'obfuscation':
            # Check for AMSI bypass technique in pattern_id (e.g., OBF-AMSI_BYPASS-PO)
            if 'AMSI' in finding.pattern_id.upper():
                header.append("[AMSI] ", style="bold bright_red")
            elif 'ANSI_C' in finding.pattern_id.upper() or 'BRACE_EXPANSION' in finding.pattern_id.upper():
                header.append("[BASH] ", style="bold green")
            else:
                header.append("[OBFS] ", style="bold yellow")
        elif finding.source == 'ast':
            header.append("[AST] ", style="bold blue")

        header.append(f"{finding.severity}", style=f"bold {severity_color}")
        header.append(f" • ", style="dim")
        header.append(f"{finding.pattern_id}", style="cyan")
        if finding.line_number:
            header.append(f" • Line {finding.line_number}", style="dim")
        
        console.print(header)
        
        # Description
        console.print(f"    {finding.description}", style="white")
        
        # Code snippet if available - show full snippet with wrapping
        if finding.code_snippet:
            snippet = finding.code_snippet.strip()
            
            # Replace newlines with spaces for single-line display, but preserve readability
            snippet = ' '.join(snippet.split())
            
            # Show full snippet with text wrapping (Rich will handle wrapping automatically)
            console.print(f"    [dim]Code:[/dim]", end=" ")
            console.print(f"[yellow]{snippet}[/yellow]")
        
        # MITRE technique
        if finding.mitre_technique:
            console.print(f"    [dim]MITRE:[/dim] [blue]{finding.mitre_technique}[/blue]")
    
    def _render_no_findings(self, console: Console) -> None:
        """
        Render message when no findings are present.
        
        Args:
            console: Rich Console instance.
        """
        panel = Panel(
            "[green]✓ No security findings detected[/green]",
            title="[bold]Security Findings[/bold]",
            border_style="green",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        console.print(panel)
    
    def _render_yara_summary(self, console: Console, result: AnalysisResult) -> None:
        """
        Render YARA contribution summary.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        yara = result.yara_contribution
        if not yara or yara.matches == 0:
            return

        console.print(f"[bold magenta]━━━ YARA Rule Matches ({yara.matches} rules) ━━━[/bold magenta]")
        console.print()

        # Score contribution summary
        console.print(f"  [cyan]Score Contribution:[/cyan] {yara.score_contribution}")
        console.print(f"  [cyan]Weighted Score:[/cyan] {yara.weighted_score:.2f}")
        console.print()

        # List matched rules (limit to 10)
        if yara.rules_matched:
            rules_to_show = yara.rules_matched[:10]
            for rule in rules_to_show:
                console.print(f"  • [magenta]{rule}[/magenta]")

            if len(yara.rules_matched) > 10:
                remaining = len(yara.rules_matched) - 10
                console.print(f"  [dim]... and {remaining} more rules[/dim]")

    def _render_ml_summary(self, console: Console, result: AnalysisResult, score_breakdown: Dict[str, Any]) -> None:
        """
        Render ML (Machine Learning) contribution summary.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
            score_breakdown: Score breakdown dictionary from verdict calculation.
        """
        ml_score = score_breakdown.get('scorer_scores', {}).get('ml', 0)
        if ml_score == 0:
            return

        console.print(f"[bold blue]━━━ Machine Learning Detection ━━━[/bold blue]")
        console.print()

        # Get ML explanations
        ml_explanations = score_breakdown.get('explanations', {}).get('ml', [])
        
        # Extract prediction and threshold from explanations
        prediction = None
        threshold = None
        for exp in ml_explanations:
            if 'ML prediction:' in exp:
                # Parse: "ML prediction: 0.028 (threshold: 0.85)"
                parts = exp.split('(threshold:')
                if len(parts) == 2:
                    try:
                        prediction = float(parts[0].split(':')[1].strip())
                        threshold = float(parts[1].strip().rstrip(')'))
                    except (ValueError, IndexError):
                        pass
        
        # Determine ML verdict based on threshold
        ml_verdict = "BENIGN"
        ml_verdict_color = "green"
        if prediction is not None and threshold is not None:
            if prediction >= threshold:
                ml_verdict = "MALICIOUS"
                ml_verdict_color = "red"
            elif prediction >= threshold * 0.7:  # Within 70% of threshold
                ml_verdict = "SUSPICIOUS"
                ml_verdict_color = "yellow"
        
        # Display ML verdict
        console.print(f"  [cyan]ML Verdict:[/cyan] [{ml_verdict_color}]{ml_verdict}[/{ml_verdict_color}]")
        
        # Score contribution summary
        ml_weight = score_breakdown.get('scorer_weights', {}).get('ml', 0.10)
        console.print(f"  [cyan]Score Contribution:[/cyan] {ml_score:.2f} (weight: {ml_weight:.0%})")
        
        # Get language from metadata
        language = result.metadata.get('script_language', 'unknown')
        console.print(f"  [cyan]Model:[/cyan] {language.capitalize()}")
        console.print()

        # Display explanations
        if ml_explanations:
            console.print(f"  [bold]Detection Details:[/bold]")
            for exp in ml_explanations:
                # Color code based on content
                if '⚠️' in exp or 'malicious' in exp.lower():
                    console.print(f"  • [yellow]{exp}[/yellow]")
                else:
                    console.print(f"  • [white]{exp}[/white]")

    def _render_iocs_compact(self, console: Console, result: AnalysisResult) -> None:
        """
        Render IOCs in a compact format.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        total_iocs = sum(len(ioc_list) for ioc_list in result.iocs.values())
        
        console.print(f"[bold magenta]━━━ Indicators of Compromise ({total_iocs} found) ━━━[/bold magenta]")
        console.print()
        
        # IOC type color mapping
        ioc_colors = {
            'ipv4': 'red',
            'ipv6': 'red',
            'domain': 'yellow',
            'url': 'yellow',
            'email': 'cyan',
            'md5': 'magenta',
            'sha1': 'magenta',
            'sha256': 'magenta',
            'file_path': 'blue',
            'registry_key': 'blue'
        }
        
        # Group and display IOCs
        for ioc_type in sorted(result.iocs.keys()):
            ioc_list = result.iocs[ioc_type]
            if not ioc_list:
                continue
            
            color = ioc_colors.get(ioc_type, 'white')
            
            for ioc in ioc_list[:10]:  # Limit to 10 per type
                value = ioc.value
                if len(value) > 60:
                    value = value[:57] + "..."
                
                line_str = f"Line {ioc.line_number}" if ioc.line_number else "—"
                confidence_str = f"{ioc.confidence * 100:.0f}%"
                
                console.print(
                    f"  [{color}]{ioc_type:12}[/{color}] {value:60} {line_str:10} {confidence_str:>6}"
                )
            
            if len(ioc_list) > 10:
                console.print(f"  [dim]... and {len(ioc_list) - 10} more {ioc_type} IOCs[/dim]")
    
    def _render_metadata_compact(self, console: Console, result: AnalysisResult) -> None:
        """
        Render metadata in a compact single-line format.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        metadata = result.metadata

        # Build metadata line
        meta_parts = []

        # Analysis time
        analysis_time = metadata.get('analysis_time_seconds', 0)
        meta_parts.append(f"[cyan]Analysis Time:[/cyan] {analysis_time:.3f}s")

        # Patterns matched - sum up severity distribution or use heuristic findings count
        pattern_matches = metadata.get('pattern_matches', {})
        if isinstance(pattern_matches, dict):
            # Sum up all severity levels from the distribution
            patterns_matched = sum(pattern_matches.values())
        else:
            # Fallback to heuristic findings count
            patterns_matched = metadata.get('heuristic_findings_count', 0)
        meta_parts.append(f"[cyan]Patterns Matched:[/cyan] {patterns_matched}")

        # Obfuscation with technique count
        obfuscation = metadata.get('obfuscation_detected', False)
        obfuscation_count = metadata.get('obfuscation_findings_count', 0)
        if obfuscation:
            obfuscation_str = f"[yellow]Yes ({obfuscation_count})[/yellow]"
        else:
            obfuscation_str = "[green]No[/green]"
        meta_parts.append(f"[cyan]Obfuscation:[/cyan] {obfuscation_str}")

        # YARA matches (if available)
        if result.yara_contribution and result.yara_contribution.matches > 0:
            yara_matches = result.yara_contribution.matches
            meta_parts.append(f"[cyan]YARA Rules:[/cyan] [magenta]{yara_matches}[/magenta]")

        # ML contribution (if available) - check in metadata
        score_breakdown = metadata.get('score_breakdown')
        if score_breakdown:
            ml_score = score_breakdown.get('scorer_scores', {}).get('ml', 0)
            if ml_score > 0:
                meta_parts.append(f"[cyan]ML Score:[/cyan] [magenta]{ml_score:.1f}[/magenta]")

        # IOCs
        total_iocs = metadata.get('total_iocs', 0)
        if total_iocs > 0:
            meta_parts.append(f"[cyan]IOCs:[/cyan] {total_iocs}")

        # Create panel
        meta_text = " • ".join(meta_parts)
        panel = Panel(
            meta_text,
            title="[bold]Analysis Metadata[/bold]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 2)
        )

        console.print(panel)
    
    def _render_iocs_section(self, console: Console, result: AnalysisResult) -> None:
        """
        Render IOCs section with type-based grouping.
        
        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        # Count total IOCs
        total_iocs = sum(len(ioc_list) for ioc_list in result.iocs.values())
        
        # Create table
        table = Table(
            title=f"[bold]Indicators of Compromise (IOCs)[/bold] ({total_iocs} found)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        
        table.add_column("Type", style="bold", width=15)
        table.add_column("Value", width=40)
        table.add_column("Line", justify="right", width=6)
        table.add_column("Confidence", justify="right", width=10)
        
        # IOC type color mapping
        ioc_colors = {
            'ipv4': 'red',
            'ipv6': 'red',
            'domain': 'yellow',
            'url': 'yellow',
            'email': 'cyan',
            'md5': 'magenta',
            'sha1': 'magenta',
            'sha256': 'magenta',
            'file_path': 'blue',
            'registry_key': 'blue'
        }
        
        # Add IOCs grouped by type
        for ioc_type in sorted(result.iocs.keys()):
            ioc_list = result.iocs[ioc_type]
            if not ioc_list:
                continue
            
            color = ioc_colors.get(ioc_type, 'white')
            
            for ioc in ioc_list:
                # Truncate long values
                value = ioc.value
                if len(value) > 50:
                    value = value[:47] + "..."
                
                line_str = str(ioc.line_number) if ioc.line_number else "—"
                confidence_str = f"{ioc.confidence * 100:.0f}%"
                
                table.add_row(
                    f"[{color}]{ioc_type}[/{color}]",
                    value,
                    line_str,
                    confidence_str
                )
        
        console.print(table)
    
    def _render_metadata_panel(self, console: Console, result: AnalysisResult) -> None:
        """
        Render metadata panel with analysis statistics.
        
        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        metadata = result.metadata
        
        # Build metadata text
        meta_text = Text()
        
        # Analysis time
        analysis_time = metadata.get('analysis_time_seconds', 0)
        meta_text.append(f"Analysis Time: {analysis_time:.3f}s\n", style="cyan")
        
        # Patterns matched - sum up severity distribution or use heuristic findings count
        pattern_matches = metadata.get('pattern_matches', {})
        if isinstance(pattern_matches, dict):
            # Sum up all severity levels from the distribution
            patterns_matched = sum(pattern_matches.values())
        else:
            # Fallback to heuristic findings count
            patterns_matched = metadata.get('heuristic_findings_count', 0)
        meta_text.append(f"Patterns Matched: {patterns_matched}\n", style="cyan")
        
        # Obfuscation detected
        obfuscation = metadata.get('obfuscation_detected', False)
        obfuscation_str = "Yes" if obfuscation else "No"
        obfuscation_color = "yellow" if obfuscation else "green"
        meta_text.append(f"Obfuscation Detected: ", style="cyan")
        meta_text.append(obfuscation_str, style=obfuscation_color)
        
        # IOCs found
        total_iocs = metadata.get('total_iocs', 0)
        if total_iocs > 0:
            meta_text.append(f"\nIOCs Found: {total_iocs}", style="cyan")
        
        # Language
        language = metadata.get('language', 'unknown')
        if language != 'unknown':
            meta_text.append(f"\nLanguage: {language}", style="cyan")
        
        # Create panel
        panel = Panel(
            meta_text,
            title="[bold]Analysis Metadata[/bold]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(1, 2)
        )
        
        console.print(panel)