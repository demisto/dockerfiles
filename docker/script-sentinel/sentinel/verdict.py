# sentinel/verdict.py

"""
Verdict and confidence score calculation for Script Sentinel.

This module implements the final verdict determination and confidence scoring
by combining findings from heuristic pattern matching, obfuscation detection,
and LLM semantic analysis.
"""

import logging
from typing import List, Tuple
from collections import Counter

from .models import Finding, Verdict

logger = logging.getLogger(__name__)


def calculate_verdict(
    findings: List[Finding],
    llm_available: bool,
    obfuscation_detected: bool,
    paranoia_level: int = 1
) -> Tuple[Verdict, float]:
    """
    Calculate final verdict and confidence score from all findings.
    
    This function implements a severity-based verdict determination algorithm
    that combines heuristic, obfuscation, and LLM findings with appropriate
    weighting to produce a final security assessment.
    
    Algorithm:
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
        
    Returns:
        Tuple of (Verdict, confidence_score).
        
    Examples:
        >>> findings = [
        ...     Finding(description="Test", severity="High", confidence=0.9,
        ...             pattern_id="test", mitre_technique="T1059", category="test")
        ... ]
        >>> verdict, confidence = calculate_verdict(findings, True, False)
        >>> print(f"{verdict.value}: {confidence:.2f}")
        suspicious: 0.85
    """
    # Handle empty findings - benign with high confidence
    if not findings:
        logger.info("No findings detected - verdict: BENIGN")
        return Verdict.BENIGN, 1.0
    
    # Categorize findings by severity
    severity_counts = Counter(f.severity for f in findings)
    
    critical_findings = [f for f in findings if f.severity == 'Critical']
    high_findings = [f for f in findings if f.severity == 'High']
    medium_findings = [f for f in findings if f.severity == 'Medium']
    low_findings = [f for f in findings if f.severity == 'Low']
    info_findings = [f for f in findings if f.severity == 'Informational']
    
    logger.info(f"Severity distribution: Critical={len(critical_findings)}, "
                f"High={len(high_findings)}, Medium={len(medium_findings)}, "
                f"Low={len(low_findings)}, Info={len(info_findings)}")
    
    # Calculate base confidence from finding confidence scores
    avg_confidence = sum(f.confidence for f in findings) / len(findings)
    
    # Determine verdict based on severity distribution and paranoia level
    verdict = _determine_verdict_from_severity(
        critical_findings,
        high_findings,
        medium_findings,
        low_findings,
        info_findings,
        paranoia_level
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
        medium_count=len(medium_findings)
    )
    
    logger.info(f"Final verdict: {verdict.value} (confidence: {confidence:.2f})")
    return verdict, confidence


def _determine_verdict_from_severity(
    critical_findings: List[Finding],
    high_findings: List[Finding],
    medium_findings: List[Finding],
    low_findings: List[Finding],
    info_findings: List[Finding],
    paranoia_level: int = 1
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
            logger.info(f"Verdict: MALICIOUS (Level 3 - Medium+ findings: "
                       f"{len(critical_findings) + len(high_findings) + len(medium_findings)})")
            return Verdict.MALICIOUS
        
        if len(low_findings) >= 2:
            logger.info(f"Verdict: MALICIOUS (Level 3 - Multiple Low findings: {len(low_findings)})")
            return Verdict.MALICIOUS
        
        # Suspicious: Any Low or Info
        if low_findings or info_findings:
            logger.info(f"Verdict: SUSPICIOUS (Level 3 - Low/Info findings: "
                       f"{len(low_findings) + len(info_findings)})")
            return Verdict.SUSPICIOUS
        
    elif paranoia_level == 2:
        # Level 2: Aggressive sensitivity - UPDATED
        # Malicious: Critical OR High OR 2+ Medium
        if critical_findings or high_findings:
            logger.info(f"Verdict: MALICIOUS (Level 2 - Critical/High findings: "
                       f"{len(critical_findings) + len(high_findings)})")
            return Verdict.MALICIOUS
        
        if len(medium_findings) >= 2:
            logger.info(f"Verdict: MALICIOUS (Level 2 - Multiple Medium findings: {len(medium_findings)})")
            return Verdict.MALICIOUS
        
        # Suspicious: Any Medium OR Low
        if medium_findings or low_findings:
            logger.info(f"Verdict: SUSPICIOUS (Level 2 - Medium/Low findings: "
                       f"{len(medium_findings) + len(low_findings)})")
            return Verdict.SUSPICIOUS
        
    else:
        # Level 1: Balanced (default) - UPDATED FOR SUSPICIOUS VERDICT
        # Malicious: Critical OR High OR 2+ Medium
        if critical_findings:
            logger.info(f"Verdict: MALICIOUS (Level 1 - Critical findings: {len(critical_findings)})")
            return Verdict.MALICIOUS
        
        if high_findings:
            logger.info(f"Verdict: MALICIOUS (Level 1 - High findings: {len(high_findings)})")
            return Verdict.MALICIOUS
        
        if len(medium_findings) >= 2:
            logger.info(f"Verdict: MALICIOUS (Level 1 - Multiple Medium findings: {len(medium_findings)})")
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
    medium_count: int
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
        llm_findings = [f for f in findings if 'llm' in f.pattern_id.lower() or 'adk' in f.pattern_id.lower()]
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
    severity_levels = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    distribution = {level: 0 for level in severity_levels}
    
    for finding in findings:
        if finding.severity in distribution:
            distribution[finding.severity] += 1
    
    return distribution