# sentinel/aggregator.py

"""
Finding aggregator for Script Sentinel.

This module provides deduplication and merging of findings from multiple detection
engines (heuristics, obfuscation, YARA). It ensures that duplicate detections of the
same pattern don't inflate risk scores while preserving the best metadata from each source.

Engine Responsibilities (to avoid overlap):
- Obfuscation Engine: Detects HOW code is hidden (encoding, entropy, evasion techniques)
- Heuristic Engine: Detects WHAT code does (behaviors, API abuse, suspicious combinations)
- YARA Engine: Detects KNOWN threats (malware signatures, tool fingerprints)

References:
- Architecture decision to separate detection responsibilities
- Reduces false positive amplification from duplicate detections
"""

import logging
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict

from .models import Finding

logger = logging.getLogger(__name__)


class FindingAggregator:
    """
    Aggregates and deduplicates findings from multiple detection engines.

    The aggregator groups findings by their detection location and pattern similarity,
    then merges duplicates while keeping the highest confidence detection.

    Deduplication Strategy:
    1. Group findings by line_number (or 0 if no line)
    2. Within each line, check for similar matched_text or pattern overlap
    3. Keep the finding with highest confidence when duplicates found
    4. Merge metadata from all sources into the kept finding

    Attributes:
        similarity_threshold: Minimum text overlap ratio to consider duplicates (0.0-1.0).

    Examples:
        >>> aggregator = FindingAggregator()
        >>> deduplicated = aggregator.aggregate(heuristic_findings + obfuscation_findings)
        >>> print(f"Reduced {len(all_findings)} to {len(deduplicated)} findings")
    """

    def __init__(self, similarity_threshold: float = 0.7):
        """
        Initialize the finding aggregator.

        Args:
            similarity_threshold: Minimum text overlap to consider findings as duplicates.
                                  Default 0.7 means 70% of characters must match.
        """
        self.similarity_threshold = similarity_threshold

    def aggregate(self, findings: List[Finding]) -> List[Finding]:
        """
        Aggregates findings from multiple sources, deduplicating similar detections.

        Args:
            findings: List of findings from all detection engines.

        Returns:
            Deduplicated list of findings, sorted by priority score.
        """
        if not findings:
            return []

        original_count = len(findings)

        # Group findings by line number
        findings_by_line: Dict[int, List[Finding]] = defaultdict(list)
        for finding in findings:
            line_key = finding.line_number or 0
            findings_by_line[line_key].append(finding)

        # Process each line group for duplicates
        deduplicated: List[Finding] = []

        for line_num, line_findings in findings_by_line.items():
            if len(line_findings) == 1:
                deduplicated.append(line_findings[0])
            else:
                # Check for duplicates within this line
                merged = self._merge_line_findings(line_findings)
                deduplicated.extend(merged)

        # Sort by priority score (highest first)
        deduplicated.sort(key=lambda f: f.get_priority_score(), reverse=True)

        removed_count = original_count - len(deduplicated)
        if removed_count > 0:
            logger.info(f"FindingAggregator: deduplicated {original_count} -> {len(deduplicated)} "
                       f"({removed_count} duplicates removed)")

        return deduplicated

    def _merge_line_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Merges findings on the same line, keeping best detection for duplicates.

        Two findings are considered duplicates if:
        1. Same MITRE technique AND same category, OR
        2. Similar matched_text (code_snippet overlap), OR
        3. Same pattern_id prefix (e.g., both start with "OBF-" or "PS-")

        Args:
            findings: List of findings all from the same line.

        Returns:
            Merged list with duplicates combined.
        """
        if len(findings) <= 1:
            return findings

        # Track which findings have been merged
        merged_indices = set()
        result = []

        for i, finding_a in enumerate(findings):
            if i in merged_indices:
                continue

            # Find all findings that are duplicates of finding_a
            duplicates = [finding_a]

            for j, finding_b in enumerate(findings[i+1:], start=i+1):
                if j in merged_indices:
                    continue

                if self._are_duplicates(finding_a, finding_b):
                    duplicates.append(finding_b)
                    merged_indices.add(j)

            # Merge duplicates into single finding
            if len(duplicates) > 1:
                merged = self._merge_duplicate_group(duplicates)
                result.append(merged)
            else:
                result.append(finding_a)

        return result

    def _are_duplicates(self, finding_a: Finding, finding_b: Finding) -> bool:
        """
        Determines if two findings are duplicates that should be merged.

        Args:
            finding_a: First finding to compare.
            finding_b: Second finding to compare.

        Returns:
            True if findings are duplicates, False otherwise.
        """
        # Same MITRE technique and category is a strong duplicate signal
        if (finding_a.mitre_technique == finding_b.mitre_technique and
            finding_a.category == finding_b.category and
            finding_a.mitre_technique):  # Must have a technique
            return True

        # Same category with similar code snippet
        if finding_a.category == finding_b.category:
            if self._snippets_similar(finding_a.code_snippet, finding_b.code_snippet):
                return True

        # Check for pattern ID overlap (e.g., PS-002 and OBF-BASE64_ENCODING-PO)
        # Both detecting base64 should be merged
        if self._pattern_ids_overlap(finding_a.pattern_id, finding_b.pattern_id):
            return True

        return False

    def _snippets_similar(self, snippet_a: Optional[str], snippet_b: Optional[str]) -> bool:
        """
        Checks if two code snippets are similar enough to be duplicates.

        Uses simple character overlap ratio for efficiency.

        Args:
            snippet_a: First code snippet.
            snippet_b: Second code snippet.

        Returns:
            True if snippets are similar above threshold.
        """
        if not snippet_a or not snippet_b:
            return False

        # Normalize snippets
        a = snippet_a.lower().strip()
        b = snippet_b.lower().strip()

        if not a or not b:
            return False

        # Calculate overlap ratio (Jaccard-like)
        set_a = set(a)
        set_b = set(b)

        intersection = len(set_a & set_b)
        union = len(set_a | set_b)

        if union == 0:
            return False

        ratio = intersection / union
        return ratio >= self.similarity_threshold

    def _pattern_ids_overlap(self, id_a: str, id_b: str) -> bool:
        """
        Checks if two pattern IDs indicate the same type of detection.

        Maps known pattern ID prefixes to detection categories to identify
        when different engines detected the same thing.

        Args:
            id_a: First pattern ID.
            id_b: Second pattern ID.

        Returns:
            True if pattern IDs indicate duplicate detection.
        """
        # Define pattern ID to category mappings
        category_map = {
            # Base64 detection
            'PS-002': 'base64',
            'OBF-BASE64': 'base64',

            # AMSI bypass
            'PS-010': 'amsi',
            'OBF-AMSI': 'amsi',

            # String concatenation
            'PS-036': 'string_concat',
            'OBF-STRING_CONCATENATION': 'string_concat',

            # Character substitution
            'PS-038': 'char_sub',
            'PS-040': 'char_sub',
            'OBF-CHARACTER_SUBSTITUTION': 'char_sub',
            'OBF-STRING_REVERSAL': 'char_sub',

            # Bash encoding
            'BASH-026': 'bash_encoding',
            'OBF-ANSI_C_OCTAL': 'bash_encoding',
            'OBF-ANSI_C_HEX': 'bash_encoding',
        }

        # Get categories for each ID (check prefix matches)
        cat_a = None
        cat_b = None

        for pattern_prefix, category in category_map.items():
            if id_a.startswith(pattern_prefix):
                cat_a = category
            if id_b.startswith(pattern_prefix):
                cat_b = category

        # If both have categories and they match, it's a duplicate
        if cat_a and cat_b and cat_a == cat_b:
            return True

        return False

    def _merge_duplicate_group(self, duplicates: List[Finding]) -> Finding:
        """
        Merges a group of duplicate findings into a single finding.

        Keeps the finding with highest confidence and merges metadata from all sources.

        Args:
            duplicates: List of findings that are duplicates of each other.

        Returns:
            Single merged finding with best confidence and combined metadata.
        """
        # Sort by confidence (descending) to get best detection first
        duplicates.sort(key=lambda f: f.confidence, reverse=True)

        # Start with the highest confidence finding
        best = duplicates[0]

        # Collect sources and merge metadata
        sources = set()
        merged_metadata = {}

        for dup in duplicates:
            sources.add(dup.source)
            # Merge metadata (later findings override earlier for same keys)
            if dup.metadata:
                merged_metadata.update(dup.metadata)

        # Add deduplication info to metadata
        merged_metadata['deduplicated_from'] = [d.pattern_id for d in duplicates]
        merged_metadata['original_sources'] = list(sources)
        merged_metadata['duplicate_count'] = len(duplicates)

        # Create merged finding (copy best and update metadata)
        # Note: We can't modify the dataclass directly, so we create a new one
        merged = Finding(
            description=best.description,
            severity=best.severity,
            confidence=best.confidence,
            pattern_id=best.pattern_id,
            mitre_technique=best.mitre_technique,
            category=best.category,
            line_number=best.line_number,
            code_snippet=best.code_snippet,
            metadata=merged_metadata,
            source=best.source
        )

        logger.debug(f"Merged {len(duplicates)} findings into {best.pattern_id} "
                    f"(sources: {sources})")

        return merged


def aggregate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Convenience function to aggregate findings without managing aggregator instance.

    Args:
        findings: List of findings from all detection engines.

    Returns:
        Deduplicated list of findings.

    Examples:
        >>> all_findings = heuristic_findings + obfuscation_findings + yara_findings
        >>> deduplicated = aggregate_findings(all_findings)
    """
    aggregator = FindingAggregator()
    return aggregator.aggregate(findings)
