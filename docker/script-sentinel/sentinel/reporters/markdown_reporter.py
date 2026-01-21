# sentinel/reporters/markdown_reporter.py

"""
Markdown report generator for Script Sentinel analysis results.

Provides clean, human-readable Markdown output suitable for documentation,
team sharing, and rendering in common Markdown viewers (GitHub, GitLab, VS Code).
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, List
from collections import defaultdict

from sentinel.models import AnalysisResult, Finding, Verdict

# Tool version for report metadata
TOOL_VERSION = "0.1.0"

logger = logging.getLogger(__name__)

# Verdict emoji mapping for visual clarity
VERDICT_EMOJI = {
    Verdict.MALICIOUS: '🚨',
    Verdict.SUSPICIOUS: '⚠️',
    Verdict.BENIGN: '✅',
    Verdict.UNKNOWN: '❓'
}


class MarkdownReporter:
    """
    Generates Markdown reports from analysis results.
    
    Creates well-formatted Markdown documents with proper headers, tables,
    code blocks, and visual hierarchy. Compatible with GitHub, GitLab,
    VS Code, and other common Markdown viewers.
    
    Examples:
        >>> from sentinel.models import AnalysisResult, Verdict
        >>> result = AnalysisResult(verdict=Verdict.SUSPICIOUS, confidence_score=0.75)
        >>> reporter = MarkdownReporter()
        >>> markdown = reporter.generate(result)
        >>> success, error = reporter.write_to_file(result, "report.md")
    """
    
    def __init__(self, max_snippet_length: int = 100):
        """
        Initialize the Markdown reporter.
        
        Args:
            max_snippet_length: Maximum length for code snippets (default: 100).
                               Longer snippets are truncated with ellipsis.
        """
        self.max_snippet_length = max_snippet_length
        self.tool_version = TOOL_VERSION
    
    def generate(self, result: AnalysisResult, verbose: bool = False) -> str:
        """
        Generate Markdown string from analysis result.
        
        Creates a well-formatted Markdown document with:
        - Title and verdict summary
        - Findings grouped by severity in tables
        - Code snippets in code blocks
        - Metadata section with analysis details
        - Table of contents for large reports (100+ findings)
        
        Args:
            result: AnalysisResult object from analyzer.
            verbose: If True, show all findings. If False, show only High/Critical (max 10).
        
        Returns:
            Formatted Markdown string.
        
        Raises:
            TypeError: If result is not an AnalysisResult instance.
        
        Examples:
            >>> reporter = MarkdownReporter()
            >>> markdown = reporter.generate(result, verbose=False)
            >>> print(markdown)  # Display Markdown content
        """
        if not isinstance(result, AnalysisResult):
            raise TypeError(f"Expected AnalysisResult, got {type(result).__name__}")
        
        try:
            # Build Markdown sections using list for performance
            sections = []
            
            # Header section
            sections.append(self._build_header(result))
            sections.append("")  # Blank line
            
            # Table of contents for large reports
            if len(result.findings) > 100:
                sections.append(self._build_toc())
                sections.append("")
            
            # Summary section
            sections.append(self._build_summary(result))
            sections.append("")
            
            # Findings section
            if result.findings:
                sections.append(self._build_findings_section(result, verbose))
            else:
                sections.append(self._build_no_findings())
            sections.append("")
            
            # IOCs section
            if result.iocs and any(result.iocs.values()):
                sections.append(self._build_iocs_section(result))
                sections.append("")

            # Obfuscation details section (if detected)
            if result.metadata.get('obfuscation_detected', False):
                sections.append(self._build_obfuscation_section(result))
                sections.append("")

            # Yara Contribution section (only if matches > 0)
            if result.yara_contribution and result.yara_contribution.matches > 0:
                sections.append(self._build_yara_contribution_section(result))
                sections.append("")

            # Metadata section
            sections.append(self._build_metadata_section(result))
            
            # Join all sections
            markdown = "\n".join(sections)
            
            logger.debug(f"Generated Markdown report ({len(markdown)} bytes)")
            return markdown
            
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")
            raise
    
    def write_to_file(
        self,
        result: AnalysisResult,
        file_path: str,
        verbose: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Write Markdown report to file.
        
        Writes the analysis result to a Markdown file with proper error handling,
        directory creation, and UTF-8 encoding. Supports both relative and
        absolute file paths with cross-platform compatibility via pathlib.
        
        Args:
            result: AnalysisResult object from analyzer.
            file_path: Output file path (relative or absolute).
            verbose: If True, show all findings. If False, show only High/Critical (max 10).
        
        Returns:
            Tuple of (success: bool, error_message: str | None).
            - (True, None) on success
            - (False, error_message) on failure
        
        Examples:
            >>> reporter = MarkdownReporter()
            >>> success, error = reporter.write_to_file(result, "./report.md", verbose=False)
            >>> if success:
            ...     print("Report written successfully")
            ... else:
            ...     print(f"Error: {error}")
        """
        try:
            # Convert to Path object for cross-platform compatibility
            output_path = Path(file_path)
            
            # Validate path is not a directory
            if output_path.exists() and output_path.is_dir():
                error_msg = f"Path is a directory, not a file: {file_path}"
                logger.error(error_msg)
                return False, error_msg
            
            # Create parent directories if they don't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured parent directory exists: {output_path.parent}")
            
            # Generate Markdown content
            markdown_content = self.generate(result, verbose=verbose)
            
            # Write to file with UTF-8 encoding
            output_path.write_text(markdown_content, encoding='utf-8')
            logger.info(f"Successfully wrote Markdown report to: {output_path}")
            
            return True, None
            
        except PermissionError as e:
            error_msg = f"Permission denied writing to {file_path}: {e}"
            logger.error(error_msg)
            return False, error_msg
            
        except OSError as e:
            error_msg = f"OS error writing to {file_path}: {e}"
            logger.error(error_msg)
            return False, error_msg
            
        except Exception as e:
            error_msg = f"Unexpected error writing to {file_path}: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def _build_header(self, result: AnalysisResult) -> str:
        """
        Build the Markdown header with title and verdict.
        
        Args:
            result: AnalysisResult object.
        
        Returns:
            Markdown header string.
        """
        emoji = VERDICT_EMOJI.get(result.verdict, '❓')
        verdict_label = result.verdict.value.upper()
        
        return f"# {emoji} Script Analysis Report: {verdict_label}"
    
    def _build_toc(self) -> str:
        """
        Build table of contents for large reports.
        
        Returns:
            Markdown table of contents string.
        """
        toc = [
            "## Table of Contents",
            "",
            "- [Summary](#summary)",
            "- [Security Findings](#security-findings)",
            "- [Analysis Metadata](#analysis-metadata)"
        ]
        return "\n".join(toc)
    
    def _build_summary(self, result: AnalysisResult) -> str:
        """
        Build the summary section with verdict and confidence.
        
        Args:
            result: AnalysisResult object.
        
        Returns:
            Markdown summary string.
        """
        confidence_pct = result.confidence_score * 100
        verdict_label = result.verdict.value.capitalize()
        
        summary = [
            "## Summary",
            "",
            f"**Verdict:** {verdict_label}  ",
            f"**Confidence:** {confidence_pct:.1f}%  ",
            f"**Total Findings:** {len(result.findings)}"
        ]
        
        # Add severity breakdown if findings exist
        if result.findings:
            severity_counts = self._count_by_severity(result.findings)
            summary.append("")
            summary.append("**Findings by Severity:**")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    summary.append(f"- {severity}: {count}")
        
        return "\n".join(summary)
    
    def _build_findings_section(self, result: AnalysisResult, verbose: bool) -> str:
        """
        Build the findings section with severity-grouped tables.
        
        Args:
            result: AnalysisResult object.
            verbose: If True, show all findings. If False, show only High/Critical (max 10).
        
        Returns:
            Markdown findings section string.
        """
        sections = ["## Security Findings", ""]
        
        # Filter by severity if not verbose (only High and Critical)
        findings_to_display = result.findings
        if not verbose:
            findings_to_display = [f for f in result.findings if f.severity in {'High', 'Critical'}]
            # Limit to top 10 findings
            findings_to_display = sorted(
                findings_to_display,
                key=lambda f: f.get_priority_score(),
                reverse=True
            )[:10]
        
        # Group findings by severity
        grouped_findings = self._group_by_severity(findings_to_display)
        
        # Add note about filtered findings if not verbose
        if not verbose and len(result.findings) > len(findings_to_display):
            filtered_count = len(result.findings) - len(findings_to_display)
            sections.append(f"*Showing High/Critical severity findings only. {filtered_count} Low/Medium/Informational findings hidden. Use `--verbose` flag to see all findings.*")
            sections.append("")
        
        # Process each severity level in priority order
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
            findings = grouped_findings.get(severity, [])
            if not findings:
                continue
            
            # Severity subsection header
            sections.append(f"### {severity} Severity ({len(findings)} findings)")
            sections.append("")
            
            # Create table with Source column
            sections.append("| Source | Line | Description | Pattern | MITRE ATT&CK |")
            sections.append("|--------|------|-------------|---------|--------------|")

            # Add findings rows
            for finding in findings:
                line_str = str(finding.line_number) if finding.line_number else "—"

                # Source indicator
                if finding.source == 'yara':
                    source_str = "[YARA]"
                elif finding.source == 'obfuscation':
                    # Check for AMSI bypass technique
                    if 'AMSI' in finding.pattern_id.upper():
                        source_str = "[AMSI]"
                    elif 'ANSI_C' in finding.pattern_id.upper() or 'BRACE_EXPANSION' in finding.pattern_id.upper():
                        source_str = "[BASH]"
                    else:
                        source_str = "[OBFS]"
                elif finding.source == 'ast':
                    source_str = "[AST]"
                else:
                    source_str = "—"

                # Escape pipe characters and truncate description
                description = self._escape_markdown(finding.description)
                if len(description) > 80:
                    description = description[:77] + "..."

                # Format MITRE technique as link if present
                mitre = finding.mitre_technique
                if mitre and mitre != "N/A":
                    mitre_link = f"[{mitre}](https://attack.mitre.org/techniques/{mitre.replace('.', '/')})"
                else:
                    mitre_link = "—"

                sections.append(f"| {source_str} | {line_str} | {description} | `{finding.pattern_id}` | {mitre_link} |")
            
            # Add code snippets if present
            snippets_added = False
            for finding in findings:
                if finding.code_snippet:
                    if not snippets_added:
                        sections.append("")
                        sections.append("**Code Snippets:**")
                        sections.append("")
                        snippets_added = True
                    
                    # Determine language for syntax highlighting
                    language = self._detect_language(result.metadata)
                    
                    # Truncate long snippets
                    snippet = finding.code_snippet
                    if len(snippet) > self.max_snippet_length:
                        snippet = snippet[:self.max_snippet_length] + "..."
                    
                    line_ref = f"Line {finding.line_number}" if finding.line_number else "Unknown line"
                    sections.append(f"**{line_ref}** ({finding.pattern_id}):")
                    sections.append(f"```{language}")
                    sections.append(snippet)
                    sections.append("```")
                    sections.append("")
            
            sections.append("")
        
        return "\n".join(sections)
    
    def _build_no_findings(self) -> str:
        """
        Build message for when no findings are present.
        
        Returns:
            Markdown no findings message.
        """
        return "\n".join([
            "## Security Findings",
            "",
            "✅ **No security findings detected.**",
            "",
            "The script appears to be benign based on the analysis patterns."
        ])
    
    def _build_iocs_section(self, result: AnalysisResult) -> str:
        """
        Build the IOCs section with type-grouped tables.
        
        Args:
            result: AnalysisResult object.
        
        Returns:
            Markdown IOCs section string.
        """
        sections = ["## Indicators of Compromise (IOCs)", ""]
        
        # Count total IOCs
        total_iocs = sum(len(ioc_list) for ioc_list in result.iocs.values())
        sections.append(f"**Total IOCs Found:** {total_iocs}")
        sections.append("")
        
        # Group IOCs by type
        for ioc_type in sorted(result.iocs.keys()):
            ioc_list = result.iocs[ioc_type]
            if not ioc_list:
                continue
            
            # Type subsection header
            sections.append(f"### {ioc_type.upper()} ({len(ioc_list)} found)")
            sections.append("")
            
            # Create table
            sections.append("| Value | Line | Confidence | Context |")
            sections.append("|-------|------|------------|---------|")
            
            # Add IOC rows
            for ioc in ioc_list:
                # Escape markdown characters
                value = self._escape_markdown(ioc.value)
                
                # Truncate long values
                if len(value) > 60:
                    value = value[:57] + "..."
                
                line_str = str(ioc.line_number) if ioc.line_number else "—"
                confidence_str = f"{ioc.confidence * 100:.0f}%"
                
                # Truncate context
                context = ""
                if ioc.context:
                    context = self._escape_markdown(ioc.context)
                    if len(context) > 40:
                        context = context[:37] + "..."
                else:
                    context = "—"
                
                sections.append(f"| `{value}` | {line_str} | {confidence_str} | {context} |")
            
            sections.append("")
        
        return "\n".join(sections)
    
    def _build_metadata_section(self, result: AnalysisResult) -> str:
        """
        Build the metadata section with analysis details.
        
        Args:
            result: AnalysisResult object.
        
        Returns:
            Markdown metadata section string.
        """
        metadata = result.metadata
        sections = ["## Analysis Metadata", ""]
        
        # Analysis timestamp
        timestamp = datetime.utcnow().isoformat() + 'Z'
        sections.append(f"**Report Generated:** {timestamp}  ")
        sections.append(f"**Tool Version:** {self.tool_version}  ")
        
        # Analysis time
        analysis_time = metadata.get('analysis_time_seconds', 0)
        sections.append(f"**Analysis Time:** {analysis_time:.3f} seconds  ")
        
        # Language
        language = metadata.get('language', 'unknown')
        if language != 'unknown':
            sections.append(f"**Script Language:** {language}  ")
        
        # Patterns matched - sum up severity distribution or use heuristic findings count
        pattern_matches = metadata.get('pattern_matches', {})
        if isinstance(pattern_matches, dict):
            # Sum up all severity levels from the distribution
            patterns_matched = sum(pattern_matches.values())
        else:
            # Fallback to heuristic findings count
            patterns_matched = metadata.get('heuristic_findings_count', 0)
        sections.append(f"**Patterns Matched:** {patterns_matched}  ")
        
        # Obfuscation detection
        obfuscation = metadata.get('obfuscation_detected', False)
        obfuscation_str = "Yes ⚠️" if obfuscation else "No"
        sections.append(f"**Obfuscation Detected:** {obfuscation_str}  ")
        
        # IOCs found
        total_iocs = metadata.get('total_iocs', 0)
        if total_iocs > 0:
            sections.append(f"**IOCs Found:** {total_iocs}  ")
        
        # File info if present
        file_path = metadata.get('file_path')
        if file_path:
            sections.append(f"**File Path:** `{file_path}`  ")
        
        file_size = metadata.get('file_size_bytes')
        if file_size:
            sections.append(f"**File Size:** {file_size} bytes  ")
        
        return "\n".join(sections)
    
    def _group_by_severity(self, findings: List[Finding]) -> dict:
        """
        Group findings by severity level.
        
        Args:
            findings: List of Finding objects.
        
        Returns:
            Dictionary mapping severity to list of findings, sorted by priority.
        """
        grouped = defaultdict(list)
        
        for finding in findings:
            grouped[finding.severity].append(finding)
        
        # Sort findings within each severity group by priority score
        for severity in grouped:
            grouped[severity].sort(key=lambda f: f.get_priority_score(), reverse=True)
        
        return dict(grouped)
    
    def _count_by_severity(self, findings: List[Finding]) -> dict:
        """
        Count findings by severity level.
        
        Args:
            findings: List of Finding objects.
        
        Returns:
            Dictionary mapping severity to count.
        """
        counts = defaultdict(int)
        for finding in findings:
            counts[finding.severity] += 1
        return dict(counts)
    
    def _escape_markdown(self, text: str) -> str:
        """
        Escape special Markdown characters in user content.
        
        Args:
            text: Text to escape.
        
        Returns:
            Escaped text safe for Markdown.
        """
        # Escape pipe characters for table compatibility
        text = text.replace('|', '\\|')
        # Escape backticks
        text = text.replace('`', '\\`')
        return text
    
    def _detect_language(self, metadata: dict) -> str:
        """
        Detect script language for syntax highlighting.

        Args:
            metadata: Analysis metadata dictionary.

        Returns:
            Language identifier for code blocks (e.g., 'powershell', 'bash').
        """
        language = metadata.get('language', '').lower()

        # Map to common syntax highlighting identifiers
        language_map = {
            'powershell': 'powershell',
            'bash': 'bash',
            'python': 'python',
            'javascript': 'javascript',
            'vbscript': 'vbscript',
            'batch': 'batch'
        }

        return language_map.get(language, '')

    def _build_obfuscation_section(self, result: AnalysisResult) -> str:
        """
        Build the Obfuscation Details section.

        Args:
            result: AnalysisResult object.

        Returns:
            Markdown obfuscation section string.
        """
        sections = ["## Obfuscation Analysis", ""]

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
        sections.append(f"**Obfuscation Indicators Found:** {obfuscation_count}")
        sections.append("")

        if technique_counts:
            sections.append("**Techniques Detected:**")
            for technique, count in sorted(technique_counts.items(), key=lambda x: -x[1]):
                # Special handling for AMSI bypass
                if 'AMSI' in technique.upper():
                    sections.append(f"- 🛡️ **{technique}**: {count} (Security Bypass)")
                else:
                    sections.append(f"- {technique}: {count}")
            sections.append("")

        # List top 5 obfuscation findings with details
        if obfuscation_findings:
            top_findings = sorted(
                obfuscation_findings,
                key=lambda f: f.get_priority_score(),
                reverse=True
            )[:5]

            sections.append("**Top Obfuscation Findings:**")
            sections.append("")
            sections.append("| Technique | Severity | Description |")
            sections.append("|-----------|----------|-------------|")

            for finding in top_findings:
                technique = finding.pattern_id.split('-')[1] if '-' in finding.pattern_id else 'Unknown'
                description = self._escape_markdown(finding.description)
                if len(description) > 60:
                    description = description[:57] + "..."
                sections.append(f"| `{technique}` | {finding.severity} | {description} |")

        return "\n".join(sections)

    def _build_yara_contribution_section(self, result: AnalysisResult) -> str:
        """
        Build the Yara Contribution section.

        Only called when result.yara_contribution.matches > 0.

        Args:
            result: AnalysisResult object.

        Returns:
            Markdown Yara contribution section string.
        """
        yara = result.yara_contribution
        sections = ["## Yara Contribution", ""]

        # Summary stats
        sections.append(f"**Rules Matched:** {yara.matches}  ")
        sections.append(f"**Score Contribution:** {yara.score_contribution}  ")
        sections.append(f"**Raw Score:** {yara.raw_score:.2f}  ")
        sections.append(f"**Weighted Score:** {yara.weighted_score:.2f}  ")
        sections.append("")

        # List matched rules
        if yara.rules_matched:
            sections.append("**Matched Rules:**")
            for rule in yara.rules_matched:
                sections.append(f"- `{rule}`")

        return "\n".join(sections)