"""Weighted aggregator for verdict calculation.

This module implements the WeightedAggregator which combines scores from multiple
scorers using configurable weights and maps them to final verdicts with confidence scores.
"""

from typing import Dict, List, Tuple, Any
from sentinel.models import Verdict


class WeightedAggregator:
    """
    Aggregates scores from multiple scorers using configurable weights.

    This aggregator combines outputs from severity, co-occurrence, kill chain,
    content, and yara scorers to produce a final verdict with confidence score.
    It supports paranoia levels for adjustable threat detection sensitivity.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        weights: Dictionary of scorer weights (severity, cooccurrence, killchain, content, yara)
        verdict_thresholds: Thresholds for verdict mapping
        confidence_caps: Maximum confidence values per verdict type
        paranoia_levels: Paranoia-specific threshold configurations

    Examples:
        >>> config = ConfigLoader().load_config('config/patterns_config.yaml')
        >>> aggregator = WeightedAggregator(config)
        >>> scorer_outputs = {
        ...     'severity': (70.0, ['High severity patterns detected']),
        ...     'cooccurrence': (25.0, ['Download-Execute chain detected'])
        ... }
        >>> verdict, confidence, breakdown = aggregator.aggregate(scorer_outputs)
        >>> verdict
        <Verdict.MALICIOUS: 'malicious'>
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the weighted aggregator.

        Args:
            config: Configuration dictionary containing aggregator, verdict_thresholds,
                   confidence_caps, and paranoia_levels sections
        """
        self.config = config

        # Load aggregator weights
        # Updated to include ML scorer (0.10)
        # Default weights: severity 0.30, cooccurrence 0.20, killchain 0.15, content 0.10, yara 0.15, ml 0.10
        aggregator_config = config.get("aggregator", {})
        self.weights = aggregator_config.get(
            "weights",
            {
                "severity": 0.30,
                "cooccurrence": 0.20,
                "killchain": 0.15,
                "content": 0.10,
                "yara": 0.15,
                "ml": 0.10,
            },
        )

        # Load verdict thresholds (default paranoia level 1)
        thresholds_config = config.get("verdict_thresholds", {})
        self.verdict_thresholds = {
            "malicious": thresholds_config.get("malicious", 70),
            "suspicious": thresholds_config.get("suspicious", 40),
        }

        # Load confidence caps
        caps_config = config.get("confidence_caps", {})
        self.confidence_caps = {
            "malicious": caps_config.get("malicious", 0.95),
            "suspicious": caps_config.get("suspicious", 0.85),
            "benign": caps_config.get("benign", 0.75),
        }

        # Load paranoia levels configuration
        self.paranoia_levels = config.get(
            "paranoia_levels",
            {
                1: {"malicious_threshold": 70, "suspicious_threshold": 40},
                2: {"malicious_threshold": 55, "suspicious_threshold": 30},
                3: {"malicious_threshold": 40, "suspicious_threshold": 20},
            },
        )

        # Validate configuration
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """
        Validate configuration structure and values.

        Ensures weights are numeric, thresholds are valid, and paranoia levels
        are properly configured. Logs warnings for invalid values but doesn't fail.
        """
        # Validate weights are numeric
        for scorer, weight in self.weights.items():
            if not isinstance(weight, (int, float)):
                # Use default weight of 0.0 for invalid values
                self.weights[scorer] = 0.0

        # Validate thresholds are numeric and in valid range
        for threshold_type in ["malicious", "suspicious"]:
            threshold = self.verdict_thresholds.get(threshold_type, 0)
            if not isinstance(threshold, (int, float)) or threshold < 0 or threshold > 100:
                # Use defaults
                self.verdict_thresholds[threshold_type] = 70 if threshold_type == "malicious" else 40

        # Validate confidence caps
        for verdict_type in ["malicious", "suspicious", "benign"]:
            cap = self.confidence_caps.get(verdict_type, 1.0)
            if not isinstance(cap, (int, float)) or cap < 0 or cap > 1.0:
                self.confidence_caps[verdict_type] = 0.95 if verdict_type == "malicious" else 0.85

        # Validate paranoia levels
        for level in [1, 2, 3]:
            if level not in self.paranoia_levels:
                # Provide default thresholds
                self.paranoia_levels[level] = {"malicious_threshold": 70, "suspicious_threshold": 40}

    def aggregate(
        self, scorer_outputs: Dict[str, Tuple[float, List[str]]], paranoia_level: int = 1
    ) -> Tuple[Verdict, float, Dict[str, Any]]:
        """
        Aggregate scores from multiple scorers into a final verdict.

        The algorithm:
        1. Apply weights to each scorer's score
        2. Sum weighted scores to get final aggregated score
        3. Map final score to verdict using paranoia-adjusted thresholds
        4. Calculate confidence based on verdict and score
        5. Generate comprehensive breakdown of scoring

        Args:
            scorer_outputs: Dictionary mapping scorer names to (score, explanations) tuples
                          Score should be 0-100, explanations is list of strings
            paranoia_level: Paranoia level (1-3) for threshold adjustment
                          1 = Balanced (default), 2 = Aggressive, 3 = Very Aggressive

        Returns:
            Tuple of (verdict, confidence, breakdown) where:
            - verdict: Verdict enum (MALICIOUS, SUSPICIOUS, or BENIGN)
            - confidence: Confidence score (0.0-1.0)
            - breakdown: Dictionary with detailed scoring information

        Examples:
            >>> aggregator = WeightedAggregator({})
            >>> outputs = {'severity': (80.0, ['High severity'])}
            >>> verdict, confidence, breakdown = aggregator.aggregate(outputs)
            >>> verdict
            <Verdict.SUSPICIOUS: 'suspicious'>
        """
        # Validate paranoia level
        if paranoia_level not in [1, 2, 3]:
            paranoia_level = 1

        # Handle empty scorer outputs
        if not scorer_outputs:
            return (
                Verdict.BENIGN,
                0.0,
                {
                    "final_score": 0.0,
                    "scorer_scores": {},
                    "scorer_weights": self.weights,
                    "explanations": {},
                    "verdict_thresholds": self.verdict_thresholds,
                    "paranoia_level": paranoia_level,
                },
            )

        # Apply weights to each scorer's score
        weighted_scores = {}
        all_explanations = {}

        for scorer_name, (score, explanations) in scorer_outputs.items():
            # Validate and clamp score to [0, 100]
            validated_score = max(0.0, min(100.0, score))

            # Get weight for this scorer (default to 0.0 if not configured)
            weight = self.weights.get(scorer_name, 0.0)

            # Calculate weighted score
            weighted_scores[scorer_name] = validated_score * weight
            all_explanations[scorer_name] = explanations

        # Calculate final aggregated score
        final_score = sum(weighted_scores.values())

        # Cap final score at 100
        final_score = min(100.0, final_score)

        # Get paranoia-adjusted thresholds
        paranoia_config = self.paranoia_levels.get(paranoia_level, self.paranoia_levels[1])
        malicious_threshold = paranoia_config.get("malicious_threshold", 70)
        suspicious_threshold = paranoia_config.get("suspicious_threshold", 40)

        # Map final score to verdict and calculate enhanced confidence
        verdict, confidence = self._map_to_verdict(
            final_score, malicious_threshold, suspicious_threshold, scorer_outputs
        )

        # Generate comprehensive breakdown
        breakdown = {
            "final_score": final_score,
            "scorer_scores": weighted_scores,
            "scorer_weights": self.weights,
            "explanations": all_explanations,
            "verdict_thresholds": {"malicious": malicious_threshold, "suspicious": suspicious_threshold},
            "paranoia_level": paranoia_level,
            "confidence_cap_applied": self.confidence_caps.get(verdict.value, 1.0),
        }

        return verdict, confidence, breakdown

    def _map_to_verdict(
        self, score: float, malicious_threshold: float, suspicious_threshold: float,
        scorer_outputs: Dict[str, Tuple[float, List[str]]] = None
    ) -> Tuple[Verdict, float]:
        """
        Map aggregated score to verdict with enhanced confidence calculation.

        Uses threshold-based mapping with confidence calculation that considers:
        - Base confidence from score
        - Evidence quality (scorer confidence levels)
        - Scorer agreement (multiple scorers detecting threats)

        Args:
            score: Final aggregated score (0-100)
            malicious_threshold: Threshold for MALICIOUS verdict
            suspicious_threshold: Threshold for SUSPICIOUS verdict
            scorer_outputs: Optional scorer outputs for enhanced confidence calculation

        Returns:
            Tuple of (verdict, confidence)

        Examples:
            >>> aggregator = WeightedAggregator({})
            >>> verdict, confidence = aggregator._map_to_verdict(75.0, 70, 40)
            >>> verdict
            <Verdict.MALICIOUS: 'malicious'>
        """
        # Determine verdict based on thresholds
        if score >= malicious_threshold:
            verdict = Verdict.MALICIOUS
        elif score >= suspicious_threshold:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

        # Calculate confidence using enhanced algorithm if scorer outputs available
        if scorer_outputs:
            confidence = self._calculate_enhanced_confidence(
                score, verdict, scorer_outputs
            )
        else:
            # Fallback to simple confidence calculation
            if verdict == Verdict.BENIGN:
                raw_confidence = (100.0 - score) / 100.0
            else:
                raw_confidence = score / 100.0
            confidence = min(raw_confidence, self.confidence_caps[verdict.value])

        return verdict, confidence

    def _calculate_enhanced_confidence(
        self,
        score: float,
        verdict: Verdict,
        scorer_outputs: Dict[str, Tuple[float, List[str]]]
    ) -> float:
        """
        Calculate enhanced confidence based on evidence quality and scorer agreement.

        Confidence factors:
        1. Base confidence from score (0.0-1.0)
        2. Evidence quality: High-scoring scorers indicate strong evidence
        3. Scorer agreement: Multiple scorers agreeing increases confidence

        Args:
            score: Final aggregated score (0-100)
            verdict: Determined verdict
            scorer_outputs: Dictionary of scorer outputs

        Returns:
            Confidence score (0.0-1.0)
        """
        # Factor 1: Base confidence from score
        if verdict == Verdict.BENIGN:
            base_confidence = (100.0 - score) / 100.0
        else:
            base_confidence = score / 100.0

        # Factor 2: Evidence quality boost
        # Check how many scorers have high confidence (score > 70)
        quality_boost = 0.0
        high_confidence_scorers = 0
        medium_confidence_scorers = 0

        for scorer_name, (scorer_score, _) in scorer_outputs.items():
            if scorer_score > 70:  # High-confidence scorer
                high_confidence_scorers += 1
                quality_boost += 0.08
            elif scorer_score > 40:  # Medium-confidence scorer
                medium_confidence_scorers += 1
                quality_boost += 0.04

        # Cap quality boost at +25%
        quality_boost = min(0.25, quality_boost)

        # Factor 3: Scorer agreement boost
        # Multiple scorers detecting threats increases confidence
        active_scorers = sum(1 for score, _ in scorer_outputs.values() if score > 20)
        agreement_boost = 0.0

        if active_scorers >= 4:
            agreement_boost = 0.15  # Strong agreement (4+ scorers)
        elif active_scorers >= 3:
            agreement_boost = 0.10  # Moderate agreement (3 scorers)
        elif active_scorers >= 2:
            agreement_boost = 0.05  # Weak agreement (2 scorers)

        # Calculate final confidence
        confidence = base_confidence + quality_boost + agreement_boost

        # Apply verdict-specific caps
        confidence = min(confidence, self.confidence_caps[verdict.value])

        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))

    def get_contributing_factors(self, breakdown: Dict[str, Any]) -> List[str]:
        """
        Extract contributing factors from breakdown for reporting.

        Generates a human-readable list of factors that contributed to the verdict,
        including scorer contributions and key explanations.

        Args:
            breakdown: Breakdown dictionary from aggregate() method

        Returns:
            List of contributing factor strings

        Examples:
            >>> aggregator = WeightedAggregator({})
            >>> breakdown = {
            ...     'final_score': 75.0,
            ...     'scorer_scores': {'severity': 28.0, 'cooccurrence': 20.0},
            ...     'scorer_weights': {'severity': 0.4, 'cooccurrence': 0.25},
            ...     'explanations': {
            ...         'severity': ['High severity patterns'],
            ...         'cooccurrence': ['Download-Execute chain']
            ...     }
            ... }
            >>> factors = aggregator.get_contributing_factors(breakdown)
            >>> len(factors) > 0
            True
        """
        factors = []

        # Add final score
        final_score = breakdown.get("final_score", 0.0)
        factors.append(f"Final aggregated score: {final_score:.1f}/100")

        # Add scorer contributions
        scorer_scores = breakdown.get("scorer_scores", {})
        scorer_weights = breakdown.get("scorer_weights", {})

        for scorer_name, weighted_score in sorted(scorer_scores.items(), key=lambda x: x[1], reverse=True):
            if weighted_score > 0:
                weight = scorer_weights.get(scorer_name, 0.0)
                factors.append(f"{scorer_name.capitalize()} scorer: {weighted_score:.1f} " f"(weight: {weight:.2f})")

        # Add key explanations from each scorer
        explanations = breakdown.get("explanations", {})
        for scorer_name, explanation_list in explanations.items():
            if explanation_list and scorer_scores.get(scorer_name, 0) > 0:
                # Add first explanation from each contributing scorer
                factors.append(f"  └─ {explanation_list[0]}")

        return factors
