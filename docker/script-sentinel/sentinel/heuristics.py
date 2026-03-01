# sentinel/heuristics.py

"""
Heuristic pattern matching engine for Script Sentinel.

This module provides the core pattern matching functionality that identifies
suspicious patterns in parsed scripts using both AST-based and regex-based
detection methods.
"""

import logging
import re
from typing import List, Optional, Dict, Any
from pathlib import Path

from .models import Finding
from .patterns.models import Pattern, PatternMatch
from .patterns.registry import PatternRegistry
from .patterns.loader import PatternLoader

logger = logging.getLogger(__name__)


class HeuristicEngine:
    """
    Heuristic pattern matching engine.
    
    The engine loads patterns from the pattern registry and matches them
    against parsed AST structures and raw script content. It supports both
    AST-based structural matching and regex-based text matching.
    
    Attributes:
        registry: PatternRegistry instance containing loaded patterns.
        _regex_cache: Cache of compiled regex patterns for performance.
        
    Examples:
        >>> engine = HeuristicEngine()
        >>> engine.load_patterns('sentinel/patterns')
        >>> findings = engine.match_patterns(ast, 'powershell', script_content)
    """
    
    def __init__(self):
        """Initializes the heuristic engine with an empty pattern registry."""
        self.registry = PatternRegistry()
        self._regex_cache: Dict[str, re.Pattern] = {}
        logger.info("Heuristic engine initialized")
    
    def load_patterns(self, patterns_dir: str | Path) -> tuple[int, List[str]]:
        """
        Loads patterns from a directory into the registry.
        
        Args:
            patterns_dir: Path to directory containing pattern YAML files.
            
        Returns:
            Tuple of (number_of_patterns_loaded, list_of_errors).
            
        Examples:
            >>> engine = HeuristicEngine()
            >>> count, errors = engine.load_patterns('sentinel/patterns')
            >>> print(f"Loaded {count} patterns")
        """
        loader = PatternLoader()
        patterns, errors = loader.load_directory(patterns_dir, recursive=True)
        
        # Register all loaded patterns
        for pattern in patterns:
            success, error = self.registry.register_pattern(pattern)
            if not success:
                errors.append(f"Failed to register pattern {pattern.id}: {error}")
        
        loaded_count = self.registry.get_pattern_count()
        logger.info(f"Loaded {loaded_count} patterns into registry")
        
        if errors:
            logger.warning(f"Encountered {len(errors)} errors while loading patterns")
            for error in errors[:5]:  # Log first 5 errors
                logger.warning(f"  {error}")
        
        return loaded_count, errors
    
    def match_patterns(
        self,
        ast: dict,
        language: str,
        script_content: Optional[str] = None,
        paranoia_level: int = 1
    ) -> List[Finding]:
        """
        Matches AST and script content against known suspicious patterns.
        
        This is the main entry point for heuristic pattern matching. It retrieves
        patterns for the specified language and applies both AST-based and regex-based
        matching to identify suspicious code.
        
        Args:
            ast: Abstract Syntax Tree from parser.parse().
            language: Script language ('powershell', 'bash', 'javascript').
            script_content: Raw script content for regex matching (optional).
            paranoia_level: Analysis sensitivity level (1=Balanced, 2=Aggressive, 3=Maximum).
            
        Returns:
            List of Finding objects for matched patterns, sorted by priority
            (severity × confidence, descending).
            
        Examples:
            >>> ast, _ = parse(script_content, 'powershell')
            >>> findings = engine.match_patterns(ast, 'powershell', script_content)
            >>> for finding in findings:
            ...     print(f"{finding.severity}: {finding.description}")
        """
        if not ast:
            logger.warning("Empty AST provided to match_patterns")
            return []
        
        # Normalize language
        language = language.lower()
        
        # Get patterns for this language
        patterns = self.registry.get_patterns(language=language, enabled_only=True)
        
        # Filter patterns based on paranoia level confidence thresholds
        patterns = self._filter_patterns_by_paranoia(patterns, paranoia_level)
        
        if not patterns:
            logger.warning(f"No patterns found for language: {language}")
            return []
        
        logger.info(f"Matching {len(patterns)} patterns for {language}")
        
        findings: List[Finding] = []
        
        # Match each pattern
        for pattern in patterns:
            try:
                if pattern.detection_type == 'ast':
                    # AST-based matching
                    matches = self._match_ast_pattern(pattern, ast, script_content)
                    findings.extend(matches)
                elif pattern.detection_type == 'regex':
                    # Regex-based matching
                    if script_content:
                        matches = self._match_regex_pattern(pattern, script_content)
                        findings.extend(matches)
                    else:
                        logger.debug(f"Skipping regex pattern {pattern.id} - no script content provided")
            except Exception as e:
                logger.error(f"Error matching pattern {pattern.id}: {str(e)}")
                continue
        
        # Sort findings by priority (highest first)
        findings.sort(key=lambda f: f.get_priority_score(), reverse=True)
        
        logger.info(f"Found {len(findings)} matches (paranoia level: {paranoia_level})")
        return findings
    
    def _filter_patterns_by_paranoia(
        self,
        patterns: List,
        paranoia_level: int
    ) -> List:
        """
        Filters patterns based on paranoia level confidence thresholds.
        
        Paranoia levels:
        - Level 1 (Balanced): confidence >= 0.8
        - Level 2 (Aggressive): confidence >= 0.5
        - Level 3 (Maximum): all patterns (confidence >= 0.0)
        
        Args:
            patterns: List of patterns to filter.
            paranoia_level: Analysis sensitivity level (1-3).
            
        Returns:
            Filtered list of patterns.
        """
        # Define confidence thresholds for each paranoia level
        thresholds = {
            1: 0.6,   # Balanced - medium confidence and above (includes Low severity patterns)
            2: 0.5,   # Aggressive - medium-low confidence and above
            3: 0.0    # Maximum - all patterns
        }
        
        threshold = thresholds.get(paranoia_level, 0.8)
        
        # Filter patterns by confidence threshold
        filtered = [p for p in patterns if p.confidence >= threshold]
        
        if len(filtered) < len(patterns):
            logger.info(f"Paranoia level {paranoia_level}: filtered {len(patterns)} patterns to {len(filtered)} "
                       f"(threshold: {threshold})")
        
        return filtered
    
    def _match_ast_pattern(
        self,
        pattern: Pattern,
        ast: dict,
        script_content: Optional[str] = None
    ) -> List[Finding]:
        """
        Matches an AST-based pattern against the syntax tree.
        
        Args:
            pattern: Pattern to match.
            ast: Abstract Syntax Tree.
            script_content: Raw script content for snippet extraction.
            
        Returns:
            List of Finding objects for matches.
        """
        findings: List[Finding] = []
        
        # For now, we'll implement a simple node type matching
        # More sophisticated AST query support can be added later
        detection_logic = pattern.detection_logic.lower()
        
        # Traverse AST and look for matching node types
        matches = self._traverse_ast(ast, detection_logic)
        
        for match in matches:
            # Extract line number and code snippet
            line_number = self._extract_line_number(match)
            code_snippet = self._extract_code_snippet(match, script_content)
            
            finding = Finding(
                description=pattern.description,
                severity=pattern.severity,
                confidence=pattern.confidence,
                pattern_id=pattern.id,
                mitre_technique=pattern.mitre_technique,
                category=pattern.category,
                line_number=line_number,
                code_snippet=code_snippet,
                metadata={
                    'pattern_name': pattern.name,
                    'detection_type': 'ast'
                }
            )
            findings.append(finding)
        
        return findings
    
    def _match_regex_pattern(
        self,
        pattern: Pattern,
        script_content: str
    ) -> List[Finding]:
        """
        Matches a regex-based pattern against script content.
        
        Args:
            pattern: Pattern to match.
            script_content: Raw script content.
            
        Returns:
            List of Finding objects for matches.
        """
        findings: List[Finding] = []
        
        # Get or compile regex pattern
        regex = self._get_compiled_regex(pattern.id, pattern.detection_logic)
        if not regex:
            return findings
        
        # Find all matches
        try:
            matches = regex.finditer(script_content)
            
            for match in matches:
                # Extract line number from match position
                line_number = script_content[:match.start()].count('\n') + 1
                
                # Extract code snippet (match + surrounding context)
                code_snippet = self._extract_snippet_from_match(
                    script_content,
                    match.start(),
                    match.end()
                )
                
                finding = Finding(
                    description=pattern.description,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    pattern_id=pattern.id,
                    mitre_technique=pattern.mitre_technique,
                    category=pattern.category,
                    line_number=line_number,
                    code_snippet=code_snippet,
                    metadata={
                        'pattern_name': pattern.name,
                        'detection_type': 'regex',
                        'matched_text': match.group(0)
                    }
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error applying regex pattern {pattern.id}: {str(e)}")
        
        return findings
    
    def _get_compiled_regex(self, pattern_id: str, regex_str: str) -> Optional[re.Pattern]:
        """
        Gets a compiled regex pattern from cache or compiles it.
        
        Args:
            pattern_id: Pattern ID for cache key.
            regex_str: Regex pattern string.
            
        Returns:
            Compiled regex pattern or None if compilation fails.
        """
        if pattern_id in self._regex_cache:
            return self._regex_cache[pattern_id]
        
        try:
            compiled = re.compile(regex_str, re.MULTILINE | re.IGNORECASE | re.DOTALL)
            self._regex_cache[pattern_id] = compiled
            return compiled
        except re.error as e:
            logger.error(f"Failed to compile regex for pattern {pattern_id}: {str(e)}")
            return None
    
    def _traverse_ast(self, node: dict, pattern: str) -> List[dict]:
        """
        Traverses AST to find nodes matching the pattern.
        
        This is a simplified implementation that matches node types.
        More sophisticated query support can be added later.
        
        Args:
            node: AST node to traverse.
            pattern: Pattern to match (simplified - just node type for now).
            
        Returns:
            List of matching AST nodes.
        """
        matches = []
        
        if not isinstance(node, dict):
            return matches
        
        # Check if current node matches
        node_type = node.get('type', '').lower()
        if pattern in node_type:
            matches.append(node)
        
        # Recursively check children
        children = node.get('children', [])
        for child in children:
            matches.extend(self._traverse_ast(child, pattern))
        
        return matches
    
    def _extract_line_number(self, ast_node: dict) -> Optional[int]:
        """
        Extracts line number from AST node.
        
        Args:
            ast_node: AST node.
            
        Returns:
            Line number (1-based) or None if not available.
        """
        start_pos = ast_node.get('start_position')
        if start_pos and isinstance(start_pos, (list, tuple)) and len(start_pos) >= 1:
            return start_pos[0] + 1  # Convert to 1-based line number
        return None
    
    def _extract_code_snippet(
        self,
        ast_node: dict,
        script_content: Optional[str]
    ) -> Optional[str]:
        """
        Extracts code snippet from AST node position.
        
        Args:
            ast_node: AST node.
            script_content: Raw script content.
            
        Returns:
            Code snippet or None if not available.
        """
        if not script_content:
            return None
        
        start_pos = ast_node.get('start_position')
        end_pos = ast_node.get('end_position')
        
        if not start_pos or not end_pos:
            return None
        
        try:
            # Convert positions to character offsets
            lines = script_content.split('\n')
            start_line, start_col = start_pos[0], start_pos[1]
            end_line, end_col = end_pos[0], end_pos[1]
            
            if start_line == end_line:
                # Single line
                return lines[start_line][start_col:end_col]
            else:
                # Multi-line - return first line with ellipsis
                snippet = lines[start_line][start_col:]
                if len(snippet) > 80:
                    snippet = snippet[:77] + '...'
                return snippet
        except (IndexError, TypeError):
            return None
    
    def _extract_snippet_from_match(
        self,
        script_content: str,
        start: int,
        end: int,
        context_lines: int = 2
    ) -> str:
        """
        Extracts code snippet from regex match with surrounding context lines.
        
        Args:
            script_content: Full script content.
            start: Match start position.
            end: Match end position.
            context_lines: Number of context lines before/after match (default: 2).
            
        Returns:
            Code snippet showing the match with context lines before and after.
        """
        # Find the line boundaries containing the match
        lines = script_content.split('\n')
        total_lines = len(lines)
        
        # Calculate which line the match starts on
        chars_before = script_content[:start]
        match_line = chars_before.count('\n')
        
        # Calculate context range (2 lines before and after)
        context_start = max(0, match_line - context_lines)
        context_end = min(total_lines, match_line + context_lines + 1)
        
        # Extract context lines
        context_lines_list = []
        for i in range(context_start, context_end):
            line = lines[i].strip()
            if line:  # Only include non-empty lines
                # Mark the line containing the match with >>>
                if i == match_line:
                    context_lines_list.append(f">>> {line}")
                else:
                    context_lines_list.append(f"    {line}")
        
        # Join with newlines for multi-line display, or spaces if too long
        snippet = '\n'.join(context_lines_list) if len(context_lines_list) <= 5 else ' '.join(context_lines_list)
        
        return snippet
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Returns statistics about the heuristic engine.
        
        Returns:
            Dictionary with engine statistics.
        """
        return {
            'patterns_loaded': self.registry.get_pattern_count(),
            'patterns_enabled': self.registry.get_enabled_count(),
            'regex_cache_size': len(self._regex_cache),
            'pattern_stats': self.registry.get_statistics()
        }


# Convenience function for direct use
def match_patterns(
    ast: dict,
    language: str,
    script_content: Optional[str] = None,
    patterns_dir: Optional[str | Path] = None
) -> List[Finding]:
    """
    Convenience function to match patterns without managing engine instance.
    
    Creates a HeuristicEngine, loads patterns, and performs matching.
    For repeated use, create an engine instance and reuse it.
    
    Args:
        ast: Abstract Syntax Tree from parser.parse().
        language: Script language ('powershell', 'bash', 'javascript').
        script_content: Raw script content for regex matching (optional).
        patterns_dir: Directory containing patterns (default: auto-detect).
        
    Returns:
        List of Finding objects for matched patterns, sorted by priority.
        
    Examples:
        >>> from sentinel.parser import parse
        >>> ast, _ = parse(script_content, 'powershell')
        >>> findings = match_patterns(ast, 'powershell', script_content)
    """
    engine = HeuristicEngine()
    
    # Auto-detect patterns directory if not provided
    if patterns_dir is None:
        # Assume patterns are in sentinel/patterns relative to this file
        current_file = Path(__file__)
        patterns_dir = current_file.parent / 'patterns'
    
    # Load patterns
    count, errors = engine.load_patterns(patterns_dir)
    if count == 0:
        logger.error("No patterns loaded - cannot perform matching")
        return []
    
    # Perform matching
    return engine.match_patterns(ast, language, script_content)