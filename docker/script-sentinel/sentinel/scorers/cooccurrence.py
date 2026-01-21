"""Pattern co-occurrence scorer for verdict calculation.

This module implements the PatternCooccurrenceScorer which detects dangerous
pattern combinations and scores based on their severity.
"""

from typing import List, Tuple, Dict, Any, Set
from sentinel.scorers.base import BaseScorer
from sentinel.models import Finding


class PatternCooccurrenceScorer(BaseScorer):
    """
    Scores based on dangerous pattern combinations.

    This scorer analyzes patterns that frequently co-occur in malicious scripts,
    such as download + execute + policy bypass. When multiple patterns from a
    configured combination are detected together, it adds the combination's score
    to the total.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        pattern_combinations: Dictionary of pattern combinations by severity
        critical_combos: List of critical severity combinations
        high_combos: List of high severity combinations
        medium_combos: List of medium severity combinations

    Examples:
        >>> config = {
        ...     'pattern_combinations': {
        ...         'critical': [
        ...             {
        ...                 'patterns': ['download_execute', 'bypass_execution_policy'],
        ...                 'score': 40,
        ...                 'description': 'Download-Execute with policy bypass'
        ...             }
        ...         ]
        ...     }
        ... }
        >>> scorer = PatternCooccurrenceScorer(config)
        >>> findings = [
        ...     Finding(
        ...         description='Download and execute',
        ...         severity='High',
        ...         confidence=0.9,
        ...         pattern_id='download_execute',
        ...         mitre_technique='T1059',
        ...         category='execution'
        ...     ),
        ...     Finding(
        ...         description='Bypass execution policy',
        ...         severity='High',
        ...         confidence=0.8,
        ...         pattern_id='bypass_execution_policy',
        ...         mitre_technique='T1562',
        ...         category='defense_evasion'
        ...     )
        ... ]
        >>> score, explanations = scorer.score(findings)
        >>> score
        40.0
        >>> len(explanations)
        2
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the pattern co-occurrence scorer.

        Args:
            config: Configuration dictionary containing pattern_combinations section
                   with critical, high, and medium severity categories
        """
        super().__init__(config)

        # Extract pattern combinations configuration
        pattern_combos = config.get('pattern_combinations', {})

        # Load combinations by severity category with defaults
        self.critical_combos = pattern_combos.get('critical', [])
        self.high_combos = pattern_combos.get('high', [])
        self.medium_combos = pattern_combos.get('medium', [])

        # Validate combinations on initialization
        self._validate_combinations()

    def _validate_combinations(self) -> None:
        """
        Validate pattern combination structure.

        Logs warnings for invalid combinations but doesn't fail initialization.
        Invalid combinations are skipped during scoring.
        """
        for category, combos in [
            ('critical', self.critical_combos),
            ('high', self.high_combos),
            ('medium', self.medium_combos)
        ]:
            for i, combo in enumerate(combos):
                # Check required fields
                if not isinstance(combo, dict):
                    continue

                if 'patterns' not in combo or not isinstance(combo['patterns'], list):
                    # Invalid combo - will be skipped during scoring
                    continue

                if 'score' not in combo or not isinstance(combo['score'], (int, float)):
                    # Invalid combo - will be skipped during scoring
                    continue

                # Description is optional but recommended
                if 'description' not in combo:
                    combo['description'] = f"{category.capitalize()} pattern combination"

    def score(self, findings: List[Finding]) -> Tuple[float, List[str]]:
        """
        Calculate score based on pattern co-occurrence (multi-tactic AND single-tactic).
        
        Algorithm:
        1. Calculate multi-tactic combination score (existing logic)
        2. Calculate single-tactic combination score (NEW - Story 3.6)
        3. Use max(multi_score, single_score) to avoid double-counting
        4. Generate combined explanations
        
        Args:
            findings: List of Finding objects to analyze
            
        Returns:
            Tuple of (score: 0-100, explanations: list of strings)
            
        Examples:
            >>> scorer = PatternCooccurrenceScorer({})
            >>> score, explanations = scorer.score([])
            >>> score
            0.0
            >>> explanations
            ['No findings to analyze for pattern combinations']
        """
        # Handle empty findings list
        if not findings:
            return 0.0, ["No findings to analyze for pattern combinations"]
        
        # Calculate multi-tactic combination score (EXISTING LOGIC)
        multi_score, multi_explanations = self._score_multi_tactic_combinations(findings)
        
        # Calculate single-tactic combination score (NEW - Story 3.6)
        single_score, single_explanations = self._score_single_tactic_combinations(findings)
        
        # Use max to avoid double-counting
        final_score = max(multi_score, single_score)
        
        # Combine explanations
        explanations = []
        if multi_score > 0:
            explanations.extend(multi_explanations)
        if single_score > 0:
            explanations.extend(single_explanations)
        
        if not explanations:
            return 0.0, ["No dangerous pattern combinations detected"]
        
        # Add summary
        summary = (
            f"Pattern co-occurrence score: {final_score:.1f}/100 "
            f"(Multi-tactic: {multi_score:.0f}, Single-tactic: {single_score:.0f})"
        )
        explanations.insert(0, summary)
        
        return self.validate_score(final_score), explanations
    
    def _score_multi_tactic_combinations(self, findings: List[Finding]) -> Tuple[float, List[str]]:
        """
        Score based on multi-tactic pattern combinations (existing logic).

        This is the original scoring logic extracted into a separate method
        to support the new max() integration pattern from Story 3.6.

        Updated in Story 1.3 to include Yara findings in category extraction
        for cross-source combo detection.

        Args:
            findings: List of Finding objects to analyze

        Returns:
            Tuple of (score: 0-100, explanations: list of strings)
        """
        # Extract pattern IDs from findings (use set for O(1) lookup)
        pattern_ids = self._extract_pattern_ids(findings)

        # Extract categories from ALL findings regardless of source (Story 1.3)
        # This enables cross-source combo detection (e.g., Yara 'download' + pattern 'execute')
        categories = self._extract_categories(findings)

        # No valid pattern IDs or categories found
        if not pattern_ids and not categories:
            return 0.0, []

        # Detect matching combinations
        total_score = 0.0
        explanations = []

        # Check critical combinations first (highest severity)
        for combo in self.critical_combos:
            if self._is_valid_combo(combo):
                if self._combo_matches(combo, pattern_ids, categories):
                    total_score += combo['score']
                    explanations.append(f"[CRITICAL] {combo['description']}")

        # Check high severity combinations
        for combo in self.high_combos:
            if self._is_valid_combo(combo):
                if self._combo_matches(combo, pattern_ids, categories):
                    total_score += combo['score']
                    explanations.append(f"[HIGH] {combo['description']}")

        # Check medium severity combinations
        for combo in self.medium_combos:
            if self._is_valid_combo(combo):
                if self._combo_matches(combo, pattern_ids, categories):
                    total_score += combo['score']
                    explanations.append(f"[MEDIUM] {combo['description']}")

        return total_score, explanations
    
    def _score_single_tactic_combinations(self, findings: List[Finding]) -> Tuple[float, List[str]]:
        """
        Score based on dangerous single-tactic pattern combinations.
        
        Detects combinations of patterns within the same MITRE tactic that
        indicate sophisticated malware behavior (e.g., layered obfuscation,
        download-execute chains).
        
        Args:
            findings: List of Finding objects to analyze
            
        Returns:
            Tuple of (score: 0-100, explanations: list of strings)
            
        Examples:
            >>> findings = [
            ...     Finding(pattern_id='PS-032', category='obfuscation', ...),
            ...     Finding(pattern_id='PS-039', category='obfuscation', ...)
            ... ]
            >>> score, explanations = scorer._score_single_tactic_combinations(findings)
            >>> score
            15.0  # "Obfuscation + Embedded Payload" combination
        """
        # Load single-tactic combinations from config
        single_tactic_config = self.config.get('pattern_combinations', {}).get('single_tactic', {})
        
        if not single_tactic_config:
            return 0.0, []
        
        max_score = 0.0
        explanations = []

        # Deduplicate findings by MITRE technique to prevent double-counting
        # when both YARA and pattern detect the same technique
        deduplicated = self._deduplicate_by_mitre(findings)

        # Extract pattern IDs and categories from deduplicated findings
        pattern_ids = {f.pattern_id for f in deduplicated if f.pattern_id}

        # Count findings per category (from deduplicated list)
        pattern_categories = {}
        for f in deduplicated:
            if f.category:
                pattern_categories[f.category] = pattern_categories.get(f.category, 0) + 1
        
        # Check each tactic's combinations
        for tactic_name, combinations in single_tactic_config.items():
            for combination in combinations:
                if self._match_combination(combination, pattern_ids, pattern_categories):
                    score = combination.get('score', 0)
                    if score > max_score:
                        max_score = score
                    
                    explanation = (
                        f"[SINGLE-TACTIC] {combination['name']}: "
                        f"{combination.get('description', 'Matched')} "
                        f"(Score: {score})"
                    )
                    explanations.append(explanation)
        
        return max_score, explanations
    
    def _match_combination(
        self,
        combination: Dict[str, Any],
        pattern_ids: Set[str],
        pattern_categories: Dict[str, int]
    ) -> bool:
        """
        Check if a combination matches the detected patterns.
        
        Supports matching by pattern IDs or categories. Applies min_matches
        threshold to determine if combination is present.
        
        Args:
            combination: Combination definition from config
            pattern_ids: Set of pattern IDs from findings
            pattern_categories: Dict mapping category to count of findings with that category
            
        Returns:
            True if combination matches, False otherwise
            
        Examples:
            >>> combination = {
            ...     'patterns': ['PS-032', 'PS-039'],
            ...     'min_matches': 2
            ... }
            >>> pattern_ids = {'PS-032', 'PS-039', 'PS-001'}
            >>> scorer._match_combination(combination, pattern_ids, {})
            True
        """
        min_matches = combination.get('min_matches', 2)
        
        # Match by pattern IDs
        if 'patterns' in combination:
            required_patterns = set(combination['patterns'])
            matched = len(required_patterns & pattern_ids)
            if matched >= min_matches:
                return True
        
        # Match by categories (count findings with matching categories)
        if 'categories' in combination:
            required_categories = set(combination['categories'])
            # Sum up counts for all required categories
            total_matches = sum(
                pattern_categories.get(cat, 0)
                for cat in required_categories
            )
            if total_matches >= min_matches:
                return True
        
        return False

    def _extract_pattern_ids(self, findings: List[Finding]) -> Set[str]:
        """
        Extract pattern IDs from findings into a set.

        Filters out findings with null or empty pattern IDs.
        Includes findings from all sources (pattern, yara, obfuscation, ast).

        Args:
            findings: List of Finding objects

        Returns:
            Set of pattern ID strings
        """
        pattern_ids = set()
        for finding in findings:
            if finding.pattern_id and isinstance(finding.pattern_id, str):
                pattern_ids.add(finding.pattern_id)
        return pattern_ids

    def _deduplicate_by_mitre(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate findings by MITRE technique to prevent double-counting.

        When both a YARA rule and a pattern detect the same MITRE technique,
        we keep only the finding with the highest confidence. This prevents
        inflated scores when the same attack technique is detected by multiple
        sources.

        Findings without a MITRE technique are always kept (no deduplication).

        Args:
            findings: List of Finding objects from any source

        Returns:
            Deduplicated list of findings (one per MITRE technique)
        """
        # Group findings by MITRE technique
        by_mitre: Dict[str, List[Finding]] = {}
        no_mitre: List[Finding] = []

        for finding in findings:
            if finding.mitre_technique and isinstance(finding.mitre_technique, str):
                technique = finding.mitre_technique
                if technique not in by_mitre:
                    by_mitre[technique] = []
                by_mitre[technique].append(finding)
            else:
                no_mitre.append(finding)

        # Keep the highest confidence finding for each technique
        deduplicated = []
        for technique, technique_findings in by_mitre.items():
            # Sort by confidence (descending), then prefer pattern over yara for ties
            best = max(
                technique_findings,
                key=lambda f: (f.confidence, f.source == 'pattern')
            )
            deduplicated.append(best)

        # Add findings without MITRE technique
        deduplicated.extend(no_mitre)

        return deduplicated

    def _extract_categories(self, findings: List[Finding]) -> Set[str]:
        """
        Extract categories from deduplicated findings.

        This method enables cross-source combo detection per Story 1.3 AC#3.
        For example, a Yara finding with category 'execution' and a pattern
        finding with category 'network' can together trigger a combo.

        IMPORTANT: Findings are deduplicated by MITRE technique before
        extracting categories to prevent double-counting when both YARA
        and pattern detections fire for the same technique.

        Yara findings have categories derived from their namespace:
        - powershell/bash/javascript -> execution
        - malware -> malware
        - webshell -> webshell
        - other -> signature

        Args:
            findings: List of Finding objects from any source

        Returns:
            Set of category strings from deduplicated findings
        """
        # Deduplicate by MITRE technique first
        deduplicated = self._deduplicate_by_mitre(findings)

        categories = set()
        for finding in deduplicated:
            if finding.category and isinstance(finding.category, str):
                categories.add(finding.category)
        return categories

    def _is_valid_combo(self, combo: Dict[str, Any]) -> bool:
        """
        Check if a combination has valid structure.

        Args:
            combo: Combination dictionary

        Returns:
            True if combination has required fields, False otherwise
        """
        if not isinstance(combo, dict):
            return False

        # Must have patterns list
        if 'patterns' not in combo or not isinstance(combo['patterns'], list):
            return False

        # Must have score
        if 'score' not in combo or not isinstance(combo['score'], (int, float)):
            return False

        # Patterns list must not be empty
        if not combo['patterns']:
            return False

        return True

    def _combo_matches(
        self,
        combo: Dict[str, Any],
        pattern_ids: Set[str],
        categories: Set[str]
    ) -> bool:
        """
        Check if all patterns in a combination are present in findings.

        Updated in Story 1.3 to support cross-source combo detection.
        Patterns can match either by pattern_id OR by category, enabling
        combos like (Yara 'execution' category + pattern 'network' category).

        Args:
            combo: Combination dictionary with 'patterns' list
            pattern_ids: Set of pattern IDs from all findings
            categories: Set of categories from all findings (for cross-source matching)

        Returns:
            True if ALL patterns in combo are present (by pattern_id or category)
        """
        combo_patterns = combo['patterns']
        # Combine pattern_ids and categories for matching
        # This allows cross-source detection where a Yara finding's category
        # can match a combo pattern alongside a pattern finding's pattern_id
        all_identifiers = pattern_ids | categories
        return all(pattern in all_identifiers for pattern in combo_patterns)
