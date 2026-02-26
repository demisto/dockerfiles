# sentinel/verdict.py

"""
Verdict and confidence score calculation for Script Sentinel.

This module implements the final verdict determination and confidence scoring
by combining findings from heuristic pattern matching, obfuscation detection,
and LLM semantic analysis.

Supports both legacy and enhanced scoring modes via feature flag.
"""

import logging
from typing import List, Tuple, Optional, Dict, Any

from .models import Finding, Verdict

logger = logging.getLogger(__name__)


def calculate_verdict(
    findings: List[Finding],
    llm_available: bool,
    obfuscation_detected: bool,
    paranoia_level: int = 1,
    script_content: Optional[str] = None,
    ast: Optional[Dict[str, Any]] = None,
    use_enhanced_scoring: bool = False,
    language: Optional[str] = None,
    script_path: Optional[str] = None,
) -> Tuple[Verdict, float, Optional[Dict[str, Any]]]:
    """
    Calculate final verdict and confidence score from all findings.

    This function supports both legacy and enhanced scoring modes:
    - Legacy mode (default): Uses existing severity-based algorithm
    - Enhanced mode: Uses multi-scorer architecture with weighted aggregation

    Algorithm (Legacy Mode):
    1. Categorize findings by severity (Critical, High, Medium, Low, Informational)
    2. Determine verdict based on severity distribution (adjusted by paranoia level):
       - Level 1 (Balanced): Malicious if Critical OR 2+ High; Suspicious if High OR 2+ Medium
       - Level 2 (Aggressive): Malicious if High OR 2+ Medium; Suspicious if Medium OR 2+ Low
       - Level 3 (Maximum): Malicious if Medium OR 2+ Low; Suspicious if any findings
    3. Calculate confidence based on:
       - Number of findings (more = higher confidence)
       - Severity distribution (higher severity = higher confidence)
       - Individual finding confidence levels
       - LLM availability (LLM + heuristic agreement = higher confidence)
       - Obfuscation detection (increases suspicion)
    4. Normalize confidence to 0.0-1.0 range

    Args:
        findings: List of all findings (heuristic + obfuscation + LLM).
        llm_available: Whether LLM analysis was available and successful.
        obfuscation_detected: Whether obfuscation was detected in the script.
        paranoia_level: Analysis sensitivity level (1=Balanced, 2=Aggressive, 3=Maximum).
        script_content: Script content for content intelligence scoring (optional).
        ast: Abstract syntax tree for complexity analysis (optional).
        use_enhanced_scoring: Enable enhanced multi-scorer mode (default: False).
        language: Script language for ML scoring ('powershell', 'javascript', 'vbscript') (optional).
        script_path: Path to script file for ML scoring (optional).

    Returns:
        Tuple of (Verdict, confidence_score, score_breakdown).
        score_breakdown is None for legacy mode, dict for enhanced mode containing:
        - final_score: The aggregated final score
        - scorer_scores: Individual scorer contributions
        - explanations: Context-aware explanations for each scorer
        - verdict_thresholds: Thresholds used for verdict determination

    Examples:
        >>> findings = [
        ...     Finding(description="Test", severity="High", confidence=0.9,
        ...             pattern_id="test", mitre_technique="T1059", category="test")
        ... ]
        >>> verdict, confidence, breakdown = calculate_verdict(findings, True, False)
        >>> print(f"{verdict.value}: {confidence:.2f}")
        suspicious: 0.85
    """
    if use_enhanced_scoring:
        return _calculate_verdict_enhanced(
            findings, llm_available, obfuscation_detected, paranoia_level,
            script_content, ast, language, script_path
        )
    else:
        verdict, confidence = _calculate_verdict_legacy(
            findings, llm_available, obfuscation_detected, paranoia_level
        )
        return verdict, confidence, None  # Legacy mode has no breakdown


def _calculate_verdict_legacy(
    findings: List[Finding], llm_available: bool, obfuscation_detected: bool, paranoia_level: int
) -> Tuple[Verdict, float]:
    """
    Legacy verdict calculation - preserves existing behavior.

    This is the EXISTING implementation, renamed for clarity.
    Maintains 100% backward compatibility with previous behavior.

    Args:
        findings: List of all findings (heuristic + obfuscation + LLM).
        llm_available: Whether LLM analysis was available and successful.
        obfuscation_detected: Whether obfuscation was detected in the script.
        paranoia_level: Analysis sensitivity level (1=Balanced, 2=Aggressive, 3=Maximum).

    Returns:
        Tuple of (Verdict, confidence_score).
    """
    # Handle empty findings - benign with high confidence
    if not findings:
        logger.info("No findings detected - verdict: BENIGN")
        return Verdict.BENIGN, 1.0

    # Categorize findings by severity
    critical_findings = [f for f in findings if f.severity == "Critical"]
    high_findings = [f for f in findings if f.severity == "High"]
    medium_findings = [f for f in findings if f.severity == "Medium"]
    low_findings = [f for f in findings if f.severity == "Low"]
    info_findings = [f for f in findings if f.severity == "Informational"]

    logger.info(
        f"Severity distribution: Critical={len(critical_findings)}, "
        f"High={len(high_findings)}, Medium={len(medium_findings)}, "
        f"Low={len(low_findings)}, Info={len(info_findings)}"
    )

    # Calculate base confidence from finding confidence scores
    avg_confidence = sum(f.confidence for f in findings) / len(findings)

    # Determine verdict based on severity distribution and paranoia level
    verdict = _determine_verdict_from_severity(
        critical_findings,
        high_findings,
        medium_findings,
        low_findings,
        info_findings,
        paranoia_level,
    )

    # Calculate confidence score
    confidence = _calculate_confidence_score(
        findings=findings,
        verdict=verdict,
        avg_confidence=avg_confidence,
        llm_available=llm_available,
        obfuscation_detected=obfuscation_detected,
        critical_count=len(critical_findings),
        high_count=len(high_findings),
        medium_count=len(medium_findings),
    )

    logger.info(f"Final verdict: {verdict.value} (confidence: {confidence:.2f})")
    return verdict, confidence


def _calculate_verdict_enhanced(
    findings: List[Finding],
    llm_available: bool,
    obfuscation_detected: bool,
    paranoia_level: int,
    script_content: Optional[str],
    ast: Optional[Dict[str, Any]],
    language: Optional[str],
    script_path: Optional[str],
) -> Tuple[Verdict, float, Dict[str, Any]]:
    """
    Enhanced verdict calculation using multi-scorer architecture.

    Implements the complete multi-scorer verdict engine with all six scorers:
    - EnhancedSeverityScorer: Weighted severity analysis (Story 1.3)
    - PatternCooccurrenceScorer: Dangerous pattern combinations (Story 1.4)
    - MitreKillChainScorer: Attack progression detection (Story 1.5)
    - ContentIntelligenceScorer: Content characteristics analysis (Story 2.6)
    - YaraScorer: YARA rule matching (Story 1.3)
    - MLScorer: Machine learning detection using Hornet LightGBM models

    Scorer Weights (configured in patterns_config.yaml):
    - Severity: 0.30 (30% contribution)
    - Co-occurrence: 0.20 (20% contribution)
    - Kill Chain: 0.15 (15% contribution)
    - Content: 0.10 (10% contribution)
    - YARA: 0.15 (15% contribution)
    - ML: 0.10 (10% contribution)

    Uses WeightedAggregator to combine scores with configurable weights and
    paranoia-level adjusted thresholds. Includes performance monitoring and
    error handling with fallback to legacy scoring.

    Args:
        findings: List of all findings.
        llm_available: Whether LLM analysis was available.
        obfuscation_detected: Whether obfuscation was detected.
        paranoia_level: Analysis sensitivity level (1=Balanced, 2=Aggressive, 3=Maximum).
        script_content: Script content for content intelligence scoring (optional).
                       If None, content scorer returns 0 (graceful degradation).
        ast: Abstract syntax tree for complexity analysis (optional).
            If None, complexity component of content scorer returns 0.
        language: Script language for ML scoring (optional).
                 If None, ML scorer returns 0 (graceful degradation).
        script_path: Path to script file for ML scoring (optional).

    Returns:
        Tuple of (Verdict, confidence_score).
    """
    import time
    from .scorers.severity import EnhancedSeverityScorer
    from .scorers.cooccurrence import PatternCooccurrenceScorer
    from .scorers.killchain import MitreKillChainScorer
    from .scorers.content import ContentIntelligenceScorer
    from .scorers.context_aware import ContextAwareScorer
    from .scorers.yara import YaraScorer
    from .scorers.ml import MLScorer
    from .scorers.aggregator import WeightedAggregator
    from .utils.config_loader import load_config

    start_time = time.time()

    try:
        # Load configuration from YAML file with caching (Story 1.2)
        # Falls back to defaults if file missing or invalid
        config = load_config("config/patterns_config.yaml")
        logger.debug("Configuration loaded for enhanced scoring")

        # Initialize all six scorers with configuration
        severity_scorer = EnhancedSeverityScorer(config)
        cooccurrence_scorer = PatternCooccurrenceScorer(config)
        killchain_scorer = MitreKillChainScorer(config)
        content_scorer = ContentIntelligenceScorer(config)
        yara_scorer = YaraScorer(config)
        ml_scorer = MLScorer(config)

        # Call each scorer with appropriate inputs
        scorer_start = time.time()
        severity_score, severity_explanations = severity_scorer.score(findings)
        severity_time = time.time() - scorer_start
        logger.debug(f"Severity scorer: {severity_score:.1f} ({severity_time:.3f}s)")

        scorer_start = time.time()
        cooccurrence_score, cooccurrence_explanations = cooccurrence_scorer.score(findings)
        cooccurrence_time = time.time() - scorer_start
        logger.debug(f"Co-occurrence scorer: {cooccurrence_score:.1f} ({cooccurrence_time:.3f}s)")

        scorer_start = time.time()
        killchain_score, killchain_explanations = killchain_scorer.score(findings)
        killchain_time = time.time() - scorer_start
        logger.debug(f"Kill chain scorer: {killchain_score:.1f} ({killchain_time:.3f}s)")

        # Content intelligence scorer (Story 2.6)
        # Analyzes script_content and ast for suspicious characteristics
        scorer_start = time.time()
        if script_content or ast:
            content_score, content_explanations = content_scorer.score(script_content, ast)
        else:
            # Graceful degradation: return 0 if inputs missing
            content_score = 0.0
            content_explanations = [
                "Content intelligence scorer: No script content or AST provided"
            ]
        content_time = time.time() - scorer_start
        logger.debug(f"Content scorer: {content_score:.1f} ({content_time:.3f}s)")

        # Yara scorer (Story 1.3)
        # Scores based on Yara rule matches with severity and confidence weighting
        scorer_start = time.time()
        yara_score, yara_explanations = yara_scorer.score(findings)
        yara_time = time.time() - scorer_start
        logger.debug(f"Yara scorer: {yara_score:.1f} ({yara_time:.3f}s)")

        # ML scorer - Machine learning detection using Hornet LightGBM models
        # Analyzes script using pre-trained models for PowerShell, JavaScript, VBScript
        scorer_start = time.time()
        if language and (script_content or script_path):
            ml_score, ml_explanations = ml_scorer.score(language, script_content, script_path)
        else:
            # Graceful degradation: return 0 if inputs missing
            ml_score = 0.0
            ml_explanations = [
                "ML scorer: No language or script content/path provided"
            ]
        ml_time = time.time() - scorer_start
        logger.debug(f"ML scorer: {ml_score:.1f} ({ml_time:.3f}s)")

        # Build scorer outputs dictionary for aggregator
        scorer_outputs = {
            "severity": (severity_score, severity_explanations),
            "cooccurrence": (cooccurrence_score, cooccurrence_explanations),
            "killchain": (killchain_score, killchain_explanations),
            "content": (content_score, content_explanations),
            "yara": (yara_score, yara_explanations),
            "ml": (ml_score, ml_explanations),
        }

        # Aggregate scores using WeightedAggregator
        aggregator = WeightedAggregator(config)
        aggregator_start = time.time()
        verdict, confidence, breakdown = aggregator.aggregate(scorer_outputs, paranoia_level)
        aggregator_time = time.time() - aggregator_start
        logger.debug(f"Aggregation: {aggregator_time:.3f}s")

        # Context-aware scoring (Story 3.7.1) - Post-aggregation adjustment
        # Analyzes script_content for contextual indicators to reduce false positives
        # Applied AFTER aggregation to preserve multi-scorer architecture
        context_aware_config = config.get('context_aware_scoring', {})
        context_aware_enabled = context_aware_config.get('enabled', False)
        
        if context_aware_enabled and script_content:
            context_start = time.time()
            context_scorer = ContextAwareScorer(config)
            
            # Calculate context adjustment based on final aggregated score
            base_final_score = breakdown['final_score']
            context_adjusted_score, context_explanations = context_scorer.score(
                script_content=script_content,
                base_score=base_final_score,
                language=language
            )
            
            context_adjustment = context_adjusted_score - base_final_score
            context_time = time.time() - context_start
            
            logger.debug(
                f"Context-aware adjustment: {context_adjustment:+.1f} "
                f"(base: {base_final_score:.1f} → adjusted: {context_adjusted_score:.1f}, "
                f"time: {context_time:.3f}s)"
            )
            
            # Re-map to verdict with adjusted score and enhanced confidence
            malicious_threshold = breakdown['verdict_thresholds']['malicious']
            suspicious_threshold = breakdown['verdict_thresholds']['suspicious']
            verdict, confidence = aggregator._map_to_verdict(
                context_adjusted_score,
                malicious_threshold,
                suspicious_threshold,
                scorer_outputs  # Pass scorer outputs for enhanced confidence
            )
            
            # Update breakdown with context-aware information
            breakdown['context_aware'] = {
                'enabled': True,
                'base_score': base_final_score,
                'adjusted_score': context_adjusted_score,
                'adjustment': context_adjustment,
                'explanations': context_explanations
            }
            breakdown['final_score'] = context_adjusted_score
            
            logger.info(
                f"Context-aware scoring applied: adjustment={context_adjustment:+.1f}, "
                f"new_verdict={verdict.value}, new_confidence={confidence:.2f}"
            )
        elif context_aware_enabled and not script_content:
            logger.debug("Context-aware scoring enabled but no script content provided")
            breakdown['context_aware'] = {
                'enabled': False,
                'reason': 'No script content provided'
            }
        else:
            breakdown['context_aware'] = {
                'enabled': False,
                'reason': 'Context-aware scoring disabled in config'
            }

        # Calculate total execution time
        total_time = time.time() - start_time

        # Log performance metrics
        logger.info(
            f"Enhanced verdict: {verdict.value} (confidence: {confidence:.2f}, "
            f"final_score: {breakdown['final_score']:.1f}, "
            f"execution_time: {total_time:.3f}s)"
        )

        # Log detailed breakdown
        logger.debug(
            f"Score breakdown - Severity: {severity_score:.1f}, "
            f"Co-occurrence: {cooccurrence_score:.1f}, "
            f"Kill chain: {killchain_score:.1f}, "
            f"Content: {content_score:.1f}, "
            f"Yara: {yara_score:.1f}, "
            f"ML: {ml_score:.1f}"
        )

        # Warn if execution time exceeds target
        if total_time > 5.0:
            logger.warning(
                f"Enhanced scoring exceeded 5s target: {total_time:.3f}s "
                f"(findings: {len(findings)})"
            )

        return verdict, confidence, breakdown

    except Exception as e:
        # Error handling: Fall back to legacy scoring on any error
        logger.error(
            f"Enhanced scoring failed: {str(e)}. Falling back to legacy scoring. "
            f"Findings count: {len(findings)}, Paranoia level: {paranoia_level}",
            exc_info=True,
        )

        # Fall back to legacy logic
        verdict, confidence = _calculate_verdict_legacy(
            findings, llm_available, obfuscation_detected, paranoia_level
        )
        return verdict, confidence, None  # No breakdown in fallback mode


def _determine_verdict_from_severity(
    critical_findings: List[Finding],
    high_findings: List[Finding],
    medium_findings: List[Finding],
    low_findings: List[Finding],
    info_findings: List[Finding],
    paranoia_level: int = 1,
) -> Verdict:
    """
    Determine verdict based on severity distribution of findings and paranoia level.

    Verdict rules (adjusted by paranoia level):

    Level 1 (Balanced - default) - UPDATED:
    - MALICIOUS: Any Critical OR High findings OR 2+ Medium severity findings
    - SUSPICIOUS: Any Medium OR Low severity findings
    - BENIGN: Only Informational findings OR no findings

    Level 2 (Aggressive) - UPDATED:
    - MALICIOUS: Any Critical OR High findings OR 2+ Medium severity findings
    - SUSPICIOUS: Any Medium OR Low severity findings
    - BENIGN: Only Informational findings OR no findings

    Level 3 (Maximum):
    - MALICIOUS: Any Medium findings OR 2+ Low severity findings
    - SUSPICIOUS: Any Low findings OR any Informational findings
    - BENIGN: No findings

    Args:
        critical_findings: List of Critical severity findings.
        high_findings: List of High severity findings.
        medium_findings: List of Medium severity findings.
        low_findings: List of Low severity findings.
        info_findings: List of Informational severity findings.
        paranoia_level: Analysis sensitivity level (1-3).

    Returns:
        Verdict enum value.
    """
    if paranoia_level == 3:
        # Level 3: Maximum sensitivity
        # Malicious: Medium+ OR 2+ Low
        if medium_findings or critical_findings or high_findings:
            logger.info(
                f"Verdict: MALICIOUS (Level 3 - Medium+ findings: "
                f"{len(critical_findings) + len(high_findings) + len(medium_findings)})"
            )
            return Verdict.MALICIOUS

        if len(low_findings) >= 2:
            logger.info(
                f"Verdict: MALICIOUS (Level 3 - Multiple Low findings: {len(low_findings)})"
            )
            return Verdict.MALICIOUS

        # Suspicious: Any Low or Info
        if low_findings or info_findings:
            logger.info(
                f"Verdict: SUSPICIOUS (Level 3 - Low/Info findings: "
                f"{len(low_findings) + len(info_findings)})"
            )
            return Verdict.SUSPICIOUS

    elif paranoia_level == 2:
        # Level 2: Aggressive sensitivity - UPDATED
        # Malicious: Critical OR High OR 2+ Medium
        if critical_findings or high_findings:
            logger.info(
                f"Verdict: MALICIOUS (Level 2 - Critical/High findings: "
                f"{len(critical_findings) + len(high_findings)})"
            )
            return Verdict.MALICIOUS

        if len(medium_findings) >= 2:
            logger.info(
                f"Verdict: MALICIOUS (Level 2 - Multiple Medium findings: {len(medium_findings)})"
            )
            return Verdict.MALICIOUS

        # Suspicious: Any Medium OR Low
        if medium_findings or low_findings:
            logger.info(
                f"Verdict: SUSPICIOUS (Level 2 - Medium/Low findings: "
                f"{len(medium_findings) + len(low_findings)})"
            )
            return Verdict.SUSPICIOUS

    else:
        # Level 1: Balanced (default) - UPDATED FOR SUSPICIOUS VERDICT
        # Malicious: Critical OR High OR 2+ Medium
        if critical_findings:
            logger.info(
                f"Verdict: MALICIOUS (Level 1 - Critical findings: {len(critical_findings)})"
            )
            return Verdict.MALICIOUS

        if high_findings:
            logger.info(f"Verdict: MALICIOUS (Level 1 - High findings: {len(high_findings)})")
            return Verdict.MALICIOUS

        if len(medium_findings) >= 2:
            logger.info(
                f"Verdict: MALICIOUS (Level 1 - Multiple Medium findings: {len(medium_findings)})"
            )
            return Verdict.MALICIOUS

        # Suspicious: Medium OR any Low findings
        if medium_findings:
            logger.info(f"Verdict: SUSPICIOUS (Level 1 - Medium findings: {len(medium_findings)})")
            return Verdict.SUSPICIOUS

        if low_findings:
            logger.info(f"Verdict: SUSPICIOUS (Level 1 - Low findings: {len(low_findings)})")
            return Verdict.SUSPICIOUS

    # Only informational findings are benign
    if info_findings:
        logger.info(f"Verdict: BENIGN (Info findings: {len(info_findings)})")
        return Verdict.BENIGN

    # Shouldn't reach here, but default to unknown
    logger.warning("Unable to determine verdict - defaulting to UNKNOWN")
    return Verdict.UNKNOWN


def _calculate_confidence_score(
    findings: List[Finding],
    verdict: Verdict,
    avg_confidence: float,
    llm_available: bool,
    obfuscation_detected: bool,
    critical_count: int,
    high_count: int,
    medium_count: int,
) -> float:
    """
    Calculate confidence score based on multiple factors.

    Confidence factors:
    - Base confidence from finding confidence scores
    - Number of findings (more findings = higher confidence)
    - Severity distribution (higher severity = higher confidence)
    - LLM availability (LLM + heuristic agreement = boost)
    - Obfuscation detection (increases confidence in suspicious/malicious verdicts)

    Args:
        findings: All findings.
        verdict: Determined verdict.
        avg_confidence: Average confidence of all findings.
        llm_available: Whether LLM analysis was available.
        obfuscation_detected: Whether obfuscation was detected.
        critical_count: Number of Critical findings.
        high_count: Number of High findings.
        medium_count: Number of Medium findings.

    Returns:
        Confidence score (0.0 to 1.0).
    """
    # Start with average finding confidence as base
    confidence = avg_confidence

    # Adjust based on number of findings (more findings = higher confidence)
    finding_count = len(findings)
    if finding_count >= 5:
        confidence = min(1.0, confidence + 0.10)  # Boost for many findings
    elif finding_count >= 3:
        confidence = min(1.0, confidence + 0.05)  # Small boost for multiple findings

    # Adjust based on severity distribution
    if critical_count > 0:
        # Critical findings increase confidence significantly
        confidence = min(1.0, confidence + 0.15)
    elif high_count >= 2:
        # Multiple high findings increase confidence
        confidence = min(1.0, confidence + 0.10)
    elif high_count == 1:
        # Single high finding increases confidence slightly
        confidence = min(1.0, confidence + 0.05)

    # LLM availability affects confidence
    if llm_available:
        # Check for LLM-heuristic agreement
        llm_findings = [
            f for f in findings if "llm" in f.pattern_id.lower() or "adk" in f.pattern_id.lower()
        ]
        heuristic_findings = [f for f in findings if f not in llm_findings]

        if llm_findings and heuristic_findings:
            # Both LLM and heuristics found issues - high confidence
            confidence = min(1.0, confidence + 0.10)
            logger.debug("LLM-heuristic agreement detected - confidence boost")
    else:
        # LLM unavailable - reduce confidence slightly
        confidence = max(0.0, confidence - 0.10)
        logger.debug("LLM unavailable - confidence reduction")

    # Obfuscation detection affects confidence
    if obfuscation_detected:
        if verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            # Obfuscation + suspicious patterns = higher confidence
            confidence = min(1.0, confidence + 0.10)
            logger.debug("Obfuscation + suspicious patterns - confidence boost")
        else:
            # Obfuscation alone is suspicious
            confidence = min(1.0, confidence + 0.05)

    # Apply verdict-specific confidence caps
    if verdict == Verdict.MALICIOUS:
        # Malicious verdicts can have very high confidence
        confidence = min(0.95, confidence)
    elif verdict == Verdict.SUSPICIOUS:
        # Suspicious verdicts have moderate confidence
        confidence = min(0.85, confidence)
    elif verdict == Verdict.BENIGN:
        # Benign verdicts with findings have lower confidence
        if findings:
            confidence = min(0.75, confidence)

    # Ensure confidence is in valid range
    confidence = max(0.0, min(1.0, confidence))

    return confidence


def get_severity_distribution(findings: List[Finding]) -> dict:
    """
    Get distribution of findings by severity level.

    Args:
        findings: List of findings to analyze.

    Returns:
        Dictionary mapping severity levels to counts.

    Examples:
        >>> findings = [Finding(..., severity="High", ...), Finding(..., severity="Low", ...)]
        >>> dist = get_severity_distribution(findings)
        >>> print(dist)
        {'Critical': 0, 'High': 1, 'Medium': 0, 'Low': 1, 'Informational': 0}
    """
    severity_levels = ["Critical", "High", "Medium", "Low", "Informational"]
    distribution = {level: 0 for level in severity_levels}

    for finding in findings:
        if finding.severity in distribution:
            distribution[finding.severity] += 1

    return distribution
