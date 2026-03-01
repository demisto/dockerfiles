# sentinel/reporters/explain_reporter.py

"""
Explain report generator for Script Sentinel analysis results.

Provides detailed score breakdown and explanation output for the --explain
CLI flag, showing how the final verdict was calculated including all scorer
contributions, weights, and Yara rule matches.
"""

import logging
from typing import Optional, List
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


class ExplainReporter:
    """
    Generates detailed explanation reports from analysis results.

    Provides a comprehensive breakdown of how the analysis verdict was
    calculated, including:
    1. Verdict header with score and confidence
    2. Score breakdown table showing each scorer's contribution
    3. Top contributors (findings sorted by priority)
    4. Yara summary (when Yara matches exist)

    Examples:
        >>> from sentinel.models import AnalysisResult, Verdict
        >>> result = AnalysisResult(verdict=Verdict.SUSPICIOUS, confidence_score=0.75)
        >>> reporter = ExplainReporter()
        >>> output = reporter.generate(result)
        >>> print(output)  # Rich formatted explanation output
    """

    def __init__(self, max_contributors: int = 10):
        """
        Initialize the explain reporter.

        Args:
            max_contributors: Maximum number of top contributors to display (default: 10).
        """
        self.max_contributors = max_contributors

    def generate(self, result: AnalysisResult) -> str:
        """
        Generate explanation report string from analysis result.

        Creates a detailed breakdown report with 4 sections:
        1. Verdict header - verdict, score, confidence
        2. Score breakdown - table with Scorer|Raw|Weight|Weighted|Contrib columns
        3. Top contributors - top findings sorted by priority
        4. Yara summary - only if yara_contribution.matches > 0

        Args:
            result: AnalysisResult object from analyzer.

        Returns:
            Formatted explanation output string with ANSI color codes.

        Raises:
            TypeError: If result is not an AnalysisResult instance.
        """
        if not isinstance(result, AnalysisResult):
            raise TypeError(f"Expected AnalysisResult, got {type(result).__name__}")

        # Create string buffer for output
        output_buffer = StringIO()
        console = Console(file=output_buffer, force_terminal=True, width=120)

        try:
            # Section 1: Verdict header
            self._render_verdict_header(console, result)
            console.print()

            # Section 2: Score breakdown table
            self._render_score_breakdown(console, result)
            console.print()

            # Section 2b: Context-aware explanations (if available)
            score_breakdown = result.metadata.get('score_breakdown', {})
            explanations = score_breakdown.get('explanations', {})
            if explanations:
                self._render_context_explanations(console, explanations)
                console.print()

            # Section 3: Top contributors
            if result.findings:
                self._render_top_contributors(console, result)
                console.print()

            # Section 4: Obfuscation summary (if detected)
            if result.metadata.get('obfuscation_detected', False):
                self._render_obfuscation_summary(console, result)
                console.print()

            # Section 5: Yara summary (only if matches > 0)
            if result.yara_contribution and result.yara_contribution.matches > 0:
                self._render_yara_summary(console, result)
                console.print()

            # Get output string
            output = output_buffer.getvalue()
            logger.debug(f"Generated explain report ({len(output)} bytes)")
            return output

        except Exception as e:
            logger.error(f"Failed to generate explain report: {e}")
            raise
        finally:
            output_buffer.close()

    def _render_verdict_header(self, console: Console, result: AnalysisResult) -> None:
        """
        Render the verdict header with emoji, verdict, score, and confidence.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        style = VERDICT_STYLES.get(result.verdict, VERDICT_STYLES[Verdict.UNKNOWN])

        # Create verdict text with emoji
        verdict_text = Text()
        verdict_text.append(f"{style['emoji']} ", style=style['color'])
        verdict_text.append("VERDICT: ", style="bold white")
        verdict_text.append(style['label'], style=f"bold {style['color']}")

        # Add confidence score
        confidence_pct = result.confidence_score * 100
        verdict_text.append(f"\nConfidence: {confidence_pct:.1f}%", style="white")

        # Add final score if available
        score_breakdown = result.metadata.get('score_breakdown', {})
        final_score = score_breakdown.get('final_score', 0)
        if final_score > 0:
            verdict_text.append(f"\nFinal Score: {final_score:.1f}", style="cyan")

        # Create panel
        panel = Panel(
            verdict_text,
            title="[bold]Analysis Verdict[/bold]",
            border_style=style['color'],
            box=box.DOUBLE,
            padding=(1, 2)
        )

        console.print(panel)

    def _render_score_breakdown(self, console: Console, result: AnalysisResult) -> None:
        """
        Render the score breakdown table showing each scorer's contribution.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        score_breakdown = result.metadata.get('score_breakdown', {})
        scorer_scores = score_breakdown.get('scorer_scores', {})
        weights = score_breakdown.get('weights', {})
        final_score = score_breakdown.get('final_score', 0)

        console.print("[bold cyan]━━━ Score Breakdown ━━━[/bold cyan]")
        console.print()

        if not scorer_scores:
            console.print("[dim]No score breakdown available[/dim]")
            return

        # Create table
        table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )

        table.add_column("Scorer", style="bold", width=20)
        table.add_column("Raw Score", justify="right", width=12)
        table.add_column("Weight", justify="right", width=10)
        table.add_column("Weighted", justify="right", width=12)
        table.add_column("Contrib %", justify="right", width=10)

        # Calculate total weighted score for contribution percentages
        total_weighted = 0
        rows_data = []

        for scorer_name, raw_score in sorted(scorer_scores.items()):
            weight = weights.get(scorer_name, 0.0)
            weighted_score = raw_score * weight
            total_weighted += weighted_score
            rows_data.append((scorer_name, raw_score, weight, weighted_score))

        # Add rows with contribution percentages
        for scorer_name, raw_score, weight, weighted_score in rows_data:
            contrib_pct = (weighted_score / total_weighted * 100) if total_weighted > 0 else 0

            # Highlight Yara row in magenta
            if scorer_name.lower() == 'yara':
                table.add_row(
                    f"[magenta]{scorer_name}[/magenta]",
                    f"{raw_score:.1f}",
                    f"{weight:.2f}",
                    f"{weighted_score:.2f}",
                    f"{contrib_pct:.1f}%"
                )
            else:
                table.add_row(
                    scorer_name,
                    f"{raw_score:.1f}",
                    f"{weight:.2f}",
                    f"{weighted_score:.2f}",
                    f"{contrib_pct:.1f}%"
                )

        console.print(table)

        # Show final score
        if final_score > 0:
            console.print(f"\n[bold]Final Score:[/bold] {final_score:.1f}")

    def _render_context_explanations(self, console: Console, explanations: dict) -> None:
        """
        Render context-aware scoring explanations.

        Args:
            console: Rich Console instance.
            explanations: Dictionary of scorer explanations from aggregator.
        """
        # Only show context-aware explanation if present in severity explanations
        severity_explanations = explanations.get('severity', [])
        context_lines = [e for e in severity_explanations if 'Context-aware' in e or 'context' in e.lower()]

        if not context_lines:
            return

        console.print("[bold cyan]━━━ Context-Aware Scoring ━━━[/bold cyan]")
        console.print()

        for line in context_lines:
            if 'Context-aware score' in line:
                # Parse and highlight the context-aware score line
                console.print(f"  [green]•[/green] {line}")
            elif 'legitimate' in line.lower() or 'documentation' in line.lower() or 'logging' in line.lower():
                # Legitimate indicators
                console.print(f"  [green]✓[/green] {line}")
            elif 'malicious' in line.lower() or 'download-execute' in line.lower():
                # Malicious indicators
                console.print(f"  [red]✗[/red] {line}")
            else:
                console.print(f"  [dim]•[/dim] {line}")

    def _render_top_contributors(self, console: Console, result: AnalysisResult) -> None:
        """
        Render the top contributors section with findings sorted by priority.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        console.print("[bold cyan]━━━ Top Contributors ━━━[/bold cyan]")
        console.print()

        # Sort findings by priority score
        sorted_findings = sorted(
            result.findings,
            key=lambda f: f.get_priority_score(),
            reverse=True
        )

        # Limit to max_contributors
        display_findings = sorted_findings[:self.max_contributors]

        for idx, finding in enumerate(display_findings, 1):
            self._render_contributor(console, finding, idx)

        if len(sorted_findings) > self.max_contributors:
            remaining = len(sorted_findings) - self.max_contributors
            console.print(f"\n[dim]... and {remaining} more findings[/dim]")

    def _render_contributor(self, console: Console, finding: Finding, index: int) -> None:
        """
        Render a single contributor (finding) with details.

        Args:
            console: Rich Console instance.
            finding: Finding object.
            index: Finding number for display.
        """
        severity_color = SEVERITY_COLORS.get(finding.severity, 'white')

        # Create finding header with source indicator
        header = Text()
        header.append(f"[{index}] ", style="bold white")

        # Add source indicator
        if finding.source == 'yara':
            header.append("[YARA] ", style="bold magenta")
        elif finding.source == 'obfuscation':
            # Check for AMSI bypass technique in pattern_id
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
        header.append(f"Confidence: {finding.confidence:.0%}", style="dim")

        console.print(header)

        # Description
        console.print(f"    {finding.description}", style="white")

        # Pattern ID and MITRE
        details = Text()
        details.append("    ", style="dim")
        details.append(f"Pattern: {finding.pattern_id}", style="cyan")
        if finding.mitre_technique:
            details.append(f" • MITRE: {finding.mitre_technique}", style="blue")
        console.print(details)

        # Code snippet if available
        if finding.code_snippet:
            snippet = ' '.join(finding.code_snippet.strip().split())
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            console.print(f"    [dim]Code:[/dim] [yellow]{snippet}[/yellow]")

        console.print()

    def _render_obfuscation_summary(self, console: Console, result: AnalysisResult) -> None:
        """
        Render the Obfuscation summary section.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        console.print("[bold yellow]━━━ Obfuscation Analysis ━━━[/bold yellow]")
        console.print()

        # Count obfuscation findings by technique
        technique_counts: dict = {}
        obfuscation_findings = [f for f in result.findings if f.source == 'obfuscation']

        for finding in obfuscation_findings:
            # Extract technique from pattern_id (e.g., OBF-AMSI_BYPASS-PO)
            parts = finding.pattern_id.split('-')
            if len(parts) >= 2:
                technique = parts[1].replace('_', ' ').title()
                technique_counts[technique] = technique_counts.get(technique, 0) + 1

        obfuscation_count = result.metadata.get('obfuscation_findings_count', len(obfuscation_findings))

        # Summary text
        summary = Text()
        summary.append("Indicators Found: ", style="white")
        summary.append(f"{obfuscation_count}", style="bold yellow")
        console.print(summary)

        # List techniques with counts
        if technique_counts:
            console.print()
            console.print("[bold]Techniques Detected:[/bold]")
            for technique, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
                # Special styling for AMSI bypass
                if 'AMSI' in technique.upper():
                    console.print(f"  • [bright_red]{technique}[/bright_red]: {count} [dim](Security Bypass)[/dim]")
                elif 'ANSI' in technique.upper() or 'BRACE' in technique.upper():
                    console.print(f"  • [green]{technique}[/green]: {count} [dim](Bash Evasion)[/dim]")
                else:
                    console.print(f"  • [yellow]{technique}[/yellow]: {count}")

    def _render_yara_summary(self, console: Console, result: AnalysisResult) -> None:
        """
        Render the Yara summary section.

        Only rendered if result.yara_contribution.matches > 0.

        Args:
            console: Rich Console instance.
            result: AnalysisResult object.
        """
        yara = result.yara_contribution
        if not yara or yara.matches == 0:
            return

        console.print("[bold magenta]━━━ Yara Summary ━━━[/bold magenta]")
        console.print()

        # Create summary text
        summary = Text()
        summary.append(f"Rules Matched: ", style="white")
        summary.append(f"{yara.matches}", style="bold magenta")
        summary.append(f"\nScore Contribution: ", style="white")
        summary.append(f"{yara.score_contribution}", style="cyan")
        summary.append(f"\nRaw Score: ", style="white")
        summary.append(f"{yara.raw_score:.2f}", style="white")
        summary.append(f"\nWeighted Score: ", style="white")
        summary.append(f"{yara.weighted_score:.2f}", style="cyan")

        console.print(summary)

        # List matched rules
        if yara.rules_matched:
            console.print()
            console.print("[bold]Matched Rules:[/bold]")
            for rule in yara.rules_matched:
                console.print(f"  • [magenta]{rule}[/magenta]")
