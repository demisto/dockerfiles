"""Yara scorer for verdict calculation.

This module implements the YaraScorer which calculates weighted scores
based on Yara rule matches, considering severity and confidence levels.
"""

from typing import List, Tuple, Dict, Any
from sentinel.scorers.base import BaseScorer
from sentinel.models import Finding


class YaraScorer(BaseScorer):
    """
    Scores based on Yara rule matches with severity and confidence weighting.

    The scorer filters findings by source='yara', then calculates a weighted
    score using the formula:
      - match_score = severity_weight * confidence per finding
      - normalized_score = min(total_score * normalization_factor, max_score)

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        severity_weights: Mapping of severity levels to numeric weights
        normalization_factor: Multiplier for score scaling
        max_score: Maximum score cap

    Examples:
        >>> config = {
        ...     'yara_scorer': {
        ...         'severity_weights': {'high': 3.0, 'critical': 4.0},
        ...         'normalization_factor': 3.0,
        ...         'max_score': 100
        ...     }
        ... }
        >>> scorer = YaraScorer(config)
        >>> findings = [
        ...     Finding(
        ...         description='Yara match',
        ...         severity='High',
        ...         confidence=0.9,
        ...         pattern_id='YARA_001',
        ...         mitre_technique='T1059',
        ...         category='execution',
        ...         source='yara'
        ...     )
        ... ]
        >>> score, explanations = scorer.score(findings)
    """

    # Default severity weights if not provided in config
    DEFAULT_SEVERITY_WEIGHTS = {
        'critical': 4.0,
        'high': 3.0,
        'medium': 2.0,
        'low': 1.0,
        'informational': 0.5
    }

    DEFAULT_NORMALIZATION_FACTOR = 3.0
    DEFAULT_MAX_SCORE = 100

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Yara scorer.

        Args:
            config: Configuration dictionary containing yara_scorer section
                   with severity_weights, normalization_factor, and max_score
        """
        super().__init__(config)

        # Extract yara scorer configuration
        yara_config = config.get('yara_scorer', {})

        # Load severity weights with defaults
        config_weights = yara_config.get('severity_weights', {})
        self.severity_weights = {**self.DEFAULT_SEVERITY_WEIGHTS, **config_weights}

        # Load normalization factor (default: 3.0)
        self.normalization_factor = yara_config.get(
            'normalization_factor', self.DEFAULT_NORMALIZATION_FACTOR
        )

        # Load max score cap (default: 100)
        self.max_score = yara_config.get('max_score', self.DEFAULT_MAX_SCORE)

    def score(self, findings: List[Finding]) -> Tuple[float, List[str]]:
        """
        Calculate weighted score from Yara findings.

        The algorithm:
        1. Filter findings to only Yara source
        2. For each finding, calculate match_score = severity_weight * confidence
        3. Sum all match scores
        4. Apply normalization: min(total * normalization_factor, max_score)
        5. Generate explanation for each finding

        Args:
            findings: List of Finding objects to score

        Returns:
            Tuple of (score: 0-max_score, explanations: list of strings)

        Examples:
            >>> scorer = YaraScorer({})
            >>> score, _ = scorer.score([])
            >>> score
            0.0
        """
        # Filter to Yara findings only
        yara_findings = [f for f in findings if f.source == 'yara']

        # Handle empty Yara findings
        if not yara_findings:
            return 0.0, []

        total_score = 0.0
        explanations = []

        for finding in yara_findings:
            # Get severity weight (case-insensitive)
            severity = finding.severity.lower()
            severity_weight = self.severity_weights.get(severity, 2.0)

            # Get confidence
            confidence = finding.confidence

            # Calculate match score
            match_score = severity_weight * confidence
            total_score += match_score

            # Generate explanation
            explanations.append(
                f"YARA {finding.pattern_id}: {severity} x {confidence:.2f} = {match_score:.2f}"
            )

        # Apply normalization with max score cap
        normalized_score = min(total_score * self.normalization_factor, self.max_score)

        return normalized_score, explanations
