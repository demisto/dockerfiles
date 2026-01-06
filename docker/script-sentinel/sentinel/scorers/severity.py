"""Enhanced severity scorer for verdict calculation.

This module implements the EnhancedSeverityScorer which calculates a weighted
score based on finding severity levels and confidence scores.
"""

from typing import List, Tuple, Dict, Any
from sentinel.scorers.base import BaseScorer
from sentinel.models import Finding


class EnhancedSeverityScorer(BaseScorer):
    """
    Calculates weighted severity score based on findings.

    The scorer uses a weighted average algorithm that considers both the
    severity level of each finding and its confidence score. Severity levels
    are mapped to numeric weights, and each finding's contribution is
    multiplied by its confidence before averaging.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        severity_weights: Mapping of severity levels to numeric weights
        use_confidence_multiplier: Whether to weight by confidence scores

    Examples:
        >>> config = {
        ...     'severity_scorer': {
        ...         'weights': {
        ...             'Critical': 100,
        ...             'High': 70,
        ...             'Medium': 40,
        ...             'Low': 20,
        ...             'Informational': 5
        ...         },
        ...         'confidence_multiplier': True
        ...     }
        ... }
        >>> scorer = EnhancedSeverityScorer(config)
        >>> findings = [
        ...     Finding(
        ...         description='Test',
        ...         severity='High',
        ...         confidence=0.9,
        ...         pattern_id='P1',
        ...         mitre_technique='T1059',
        ...         category='test'
        ...     )
        ... ]
        >>> score, explanations = scorer.score(findings)
        >>> 60 < score < 80  # High severity with high confidence
        True
    """

    # Default severity weights if not provided in config
    DEFAULT_WEIGHTS = {
        'Critical': 100,
        'High': 70,
        'Medium': 40,
        'Low': 20,
        'Informational': 5
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the enhanced severity scorer.

        Args:
            config: Configuration dictionary containing severity_scorer section
                   with weights and confidence_multiplier settings
        """
        super().__init__(config)

        # Extract severity scorer configuration
        severity_config = config.get('severity_scorer', {})

        # Load severity weights with defaults
        config_weights = severity_config.get('weights', {})
        self.severity_weights = {**self.DEFAULT_WEIGHTS, **config_weights}

        # Load confidence multiplier setting (default: True)
        self.use_confidence_multiplier = severity_config.get(
            'confidence_multiplier', True
        )

    def score(self, findings: List[Finding]) -> Tuple[float, List[str]]:
        """
        Calculate weighted severity score from findings.

        The algorithm:
        1. For each finding, get base score from severity weight
        2. Multiply by confidence if confidence_multiplier is enabled
        3. Calculate weighted average (sum of weighted scores / sum of weights)
        4. Normalize to 0-100 range
        5. Generate explanation of calculation

        Args:
            findings: List of Finding objects to score

        Returns:
            Tuple of (score: 0-100, explanations: list of strings)

        Examples:
            >>> scorer = EnhancedSeverityScorer({})
            >>> score, _ = scorer.score([])
            >>> score
            0.0
        """
        # Handle empty findings list
        if not findings:
            return 0.0, ["No findings to score"]

        weighted_scores = []
        severity_counts = {}

        for finding in findings:
            # Get base score from severity weight
            # Handle case-insensitive matching and unknown severities
            severity = finding.severity
            base_score = self._get_severity_weight(severity)

            # Get confidence, capping at 1.0 and treating missing as 1.0
            confidence = min(1.0, max(0.0, finding.confidence))

            # Calculate weighted contribution
            if self.use_confidence_multiplier:
                weighted_score = base_score * confidence
            else:
                weighted_score = base_score

            weighted_scores.append(weighted_score)

            # Track severity distribution for explanation
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate score using maximum + diminishing returns for additional findings
        # This ensures multiple findings amplify the score rather than averaging it down
        if weighted_scores:
            # Take the highest severity finding as base
            base_score = max(weighted_scores)
            
            # Add bonus for additional findings with diminishing returns
            if len(weighted_scores) > 1:
                # Each additional finding adds value, but with exponential decay
                # This prevents score inflation while rewarding multiple detections
                additional_findings = len(weighted_scores) - 1
                bonus_per_finding = 3.0  # Each additional finding worth up to 3 points
                decay_rate = 0.85  # Exponential decay factor
                
                bonus = sum(
                    bonus_per_finding * (decay_rate ** i)
                    for i in range(additional_findings)
                )
                average_score = base_score + bonus
            else:
                average_score = base_score
        else:
            # All findings have zero confidence
            average_score = 0.0

        # Normalize to 0-100 range (should already be in range, but ensure)
        final_score = self.validate_score(average_score)

        # Generate explanation
        explanations = self._generate_explanation(
            final_score, findings, severity_counts
        )

        return final_score, explanations

    def _get_severity_weight(self, severity: str) -> float:
        """
        Get numeric weight for a severity level.

        Handles case-insensitive matching and defaults to Informational
        weight for unknown severity levels.

        Args:
            severity: Severity level string

        Returns:
            Numeric weight for the severity level
        """
        # Try exact match first
        if severity in self.severity_weights:
            return self.severity_weights[severity]

        # Try case-insensitive match
        for key, value in self.severity_weights.items():
            if key.lower() == severity.lower():
                return value

        # Default to Informational weight for unknown severities
        return self.severity_weights.get('Informational', 5)

    def _generate_explanation(
        self,
        score: float,
        findings: List[Finding],
        severity_counts: Dict[str, int]
    ) -> List[str]:
        """
        Generate human-readable explanation of score calculation.

        Args:
            score: Calculated score
            findings: List of findings that were scored
            severity_counts: Count of findings by severity level

        Returns:
            List of explanation strings
        """
        explanations = []

        # Overall score summary
        explanations.append(
            f"Severity score: {score:.1f}/100 from {len(findings)} finding(s)"
        )

        # Severity distribution
        if severity_counts:
            severity_parts = []
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    severity_parts.append(f"{count} {severity}")

            if severity_parts:
                explanations.append(
                    f"Severity distribution: {', '.join(severity_parts)}"
                )

        # Confidence impact note
        if self.use_confidence_multiplier:
            avg_confidence = sum(f.confidence for f in findings) / len(findings)
            explanations.append(
                f"Average confidence: {avg_confidence:.2f} "
                f"(findings weighted by confidence)"
            )

        return explanations
