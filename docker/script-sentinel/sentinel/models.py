# sentinel/models.py

"""
Data models for Script Sentinel analysis results.

Defines the core data structures used throughout the analysis pipeline,
including Finding and AnalysisResult classes.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from enum import Enum


class Verdict(Enum):
    """Analysis verdict enumeration."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


@dataclass
class YaraContribution:
    """
    Yara contribution details for analysis output.

    Captures the Yara engine's contribution to the overall analysis,
    including match counts, score breakdowns, and matched rule names.

    Attributes:
        enabled: Whether Yara scanning was enabled.
        matches: Number of Yara rule matches.
        score_contribution: Percentage contribution to total score (e.g., "15.5%").
        raw_score: Unweighted Yara score.
        weighted_score: Yara score after weight applied.
        rules_matched: List of matched rule names.

    Examples:
        >>> contrib = YaraContribution(
        ...     enabled=True,
        ...     matches=3,
        ...     score_contribution="15.5%",
        ...     raw_score=45.0,
        ...     weighted_score=6.75,
        ...     rules_matched=["YARA-emotet", "YARA-base64"]
        ... )
    """
    enabled: bool = True
    matches: int = 0
    score_contribution: str = "0.0%"
    raw_score: float = 0.0
    weighted_score: float = 0.0
    rules_matched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """
        Converts YaraContribution to dictionary format.

        Returns:
            Dictionary representation with rounded float scores.
        """
        return {
            'enabled': self.enabled,
            'matches': self.matches,
            'score_contribution': self.score_contribution,
            'raw_score': round(self.raw_score, 2),
            'weighted_score': round(self.weighted_score, 2),
            'rules_matched': self.rules_matched
        }


@dataclass
class Finding:
    """
    Represents a single security finding from pattern matching or analysis.
    
    A Finding captures details about a detected suspicious pattern or behavior,
    including its severity, confidence, location in the code, and associated
    threat intelligence (MITRE ATT&CK technique).
    
    Attributes:
        description: Human-readable description of what was detected.
        severity: Severity level ('High', 'Medium', 'Low').
        confidence: Confidence score (0.0 to 1.0).
        pattern_id: ID of the pattern that triggered this finding.
        line_number: Line number where the finding was detected (optional).
        code_snippet: Code snippet showing the detected pattern (optional).
        mitre_technique: MITRE ATT&CK technique ID (e.g., 'T1059.001').
        category: Finding category (e.g., 'command_injection', 'obfuscation').
        metadata: Additional finding metadata (optional).
        
    Examples:
        >>> finding = Finding(
        ...     description='Detected Invoke-Expression cmdlet',
        ...     severity='High',
        ...     confidence=0.9,
        ...     pattern_id='PS-001',
        ...     line_number=42,
        ...     code_snippet='Invoke-Expression $cmd',
        ...     mitre_technique='T1059.001',
        ...     category='command_injection'
        ... )
    """
    description: str
    severity: str  # 'High', 'Medium', 'Low'
    confidence: float  # 0.0 to 1.0
    pattern_id: str
    mitre_technique: str
    category: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "pattern"  # Values: "pattern", "yara", "obfuscation", "ast"
    
    def __post_init__(self):
        """Validates finding fields after initialization."""
        # Validate severity
        valid_severities = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
        if self.severity not in valid_severities:
            raise ValueError(f"Invalid severity: {self.severity}. Must be one of {valid_severities}")
        
        # Validate confidence
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}. Must be between 0.0 and 1.0")

        # Validate source
        valid_sources = {'pattern', 'yara', 'obfuscation', 'ast'}
        if self.source not in valid_sources:
            raise ValueError(f"Invalid source: {self.source}. Must be one of {valid_sources}")

    def get_priority_score(self) -> float:
        """
        Calculates priority score for finding ordering.
        
        Priority is based on severity and confidence:
        - Critical severity: 4.0
        - High severity: 3.0
        - Medium severity: 2.0
        - Low severity: 1.0
        - Informational severity: 0.5
        - Multiplied by confidence score
        
        Returns:
            Priority score (0.0 to 4.0).
        """
        severity_weights = {
            'Critical': 4.0,
            'High': 3.0,
            'Medium': 2.0,
            'Low': 1.0,
            'Informational': 0.5
        }
        return severity_weights.get(self.severity, 1.0) * self.confidence
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts finding to dictionary format.
        
        Returns:
            Dictionary representation of the finding.
        """
        return {
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'pattern_id': self.pattern_id,
            'mitre_technique': self.mitre_technique,
            'category': self.category,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'metadata': self.metadata,
            'source': self.source
        }


@dataclass
class IOC:
    """
    Represents an Indicator of Compromise extracted from a script.
    
    IOCs are artifacts observed in scripts that may indicate malicious activity,
    such as IP addresses, domains, URLs, file hashes, and file paths.
    
    Attributes:
        type: IOC type ('ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'file_path', 'registry_key').
        value: The actual IOC value (e.g., '192.168.1.100', 'malicious.com').
        context: Surrounding code snippet showing where the IOC was found (optional).
        line_number: Line number where the IOC was detected (optional).
        confidence: Confidence score that this is a real IOC vs. false positive (0.0 to 1.0).
        
    Examples:
        >>> ioc = IOC(
        ...     type='ipv4',
        ...     value='192.168.1.100',
        ...     context='Invoke-WebRequest -Uri http://192.168.1.100',
        ...     line_number=42,
        ...     confidence=0.8
        ... )
    """
    type: str
    value: str
    context: Optional[str] = None
    line_number: Optional[int] = None
    confidence: float = 1.0
    
    def __post_init__(self):
        """Validates IOC fields after initialization."""
        # Validate IOC type
        valid_types = {
            'ipv4', 'ipv6', 'domain', 'url', 'email',
            'md5', 'sha1', 'sha256', 'file_path', 'registry_key'
        }
        if self.type not in valid_types:
            raise ValueError(f"Invalid IOC type: {self.type}. Must be one of {valid_types}")
        
        # Validate confidence
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}. Must be between 0.0 and 1.0")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts IOC to dictionary format.
        
        Returns:
            Dictionary representation of the IOC.
        """
        return {
            'type': self.type,
            'value': self.value,
            'context': self.context,
            'line_number': self.line_number,
            'confidence': self.confidence
        }


@dataclass
class MITRETechnique:
    """
    Represents a MITRE ATT&CK technique with enriched details.
    
    Contains comprehensive information about a MITRE ATT&CK technique including
    its ID, name, tactic, description, and aggregated confidence from findings.
    
    Attributes:
        technique_id: MITRE technique ID (e.g., 'T1059.001').
        technique_name: Human-readable technique name (e.g., 'PowerShell').
        tactic: Primary tactic category (e.g., 'Execution', 'Defense Evasion').
        description: Detailed description of the technique.
        confidence: Aggregated confidence score (0.0 to 1.0).
        finding_count: Number of findings mapped to this technique.
        url: Link to MITRE ATT&CK page for this technique.
        
    Examples:
        >>> technique = MITRETechnique(
        ...     technique_id='T1059.001',
        ...     technique_name='PowerShell',
        ...     tactic='Execution',
        ...     description='Adversaries may abuse PowerShell...',
        ...     confidence=0.9,
        ...     finding_count=3,
        ...     url='https://attack.mitre.org/techniques/T1059/001/'
        ... )
    """
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: float
    finding_count: int
    url: str
    
    def __post_init__(self):
        """Validates MITRE technique fields after initialization."""
        # Validate confidence
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}. Must be between 0.0 and 1.0")
        
        # Validate finding count
        if self.finding_count < 0:
            raise ValueError(f"Invalid finding_count: {self.finding_count}. Must be >= 0")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts MITRE technique to dictionary format.
        
        Returns:
            Dictionary representation of the MITRE technique.
        """
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'tactic': self.tactic,
            'description': self.description,
            'confidence': self.confidence,
            'finding_count': self.finding_count,
            'url': self.url
        }


@dataclass
class AnalysisResult:
    """
    Represents the complete analysis result for a script.
    
    Contains the overall verdict, confidence score, and all findings
    from both heuristic pattern matching and LLM-based semantic analysis.
    
    Attributes:
        verdict: Overall analysis verdict (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN).
        confidence_score: Overall confidence in the verdict (0.0 to 1.0).
        findings: All findings (combined heuristic and LLM findings).
        heuristic_findings: Findings from heuristic pattern matching.
        llm_findings: Findings from LLM semantic analysis.
        iocs: Extracted Indicators of Compromise grouped by type.
        mitre_techniques: MITRE ATT&CK techniques mapped from findings.
        metadata: Additional analysis metadata.
        
    Examples:
        >>> result = AnalysisResult(
        ...     verdict=Verdict.SUSPICIOUS,
        ...     confidence_score=0.75,
        ...     findings=[finding1, finding2],
        ...     heuristic_findings=[finding1],
        ...     llm_findings=[finding2]
        ... )
    """
    verdict: Verdict
    confidence_score: float
    findings: List[Finding] = field(default_factory=list)
    heuristic_findings: List[Finding] = field(default_factory=list)
    llm_findings: List[Finding] = field(default_factory=list)
    iocs: Dict[str, List[IOC]] = field(default_factory=dict)
    mitre_techniques: Dict[str, MITRETechnique] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    yara_contribution: Optional['YaraContribution'] = None

    def __post_init__(self):
        """Validates analysis result fields after initialization."""
        # Validate confidence score
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError(f"Invalid confidence_score: {self.confidence_score}. Must be between 0.0 and 1.0")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts analysis result to dictionary format.

        Returns:
            Dictionary representation of the analysis result.
        """
        result = {
            'verdict': self.verdict.value,
            'confidence_score': self.confidence_score,
            'findings': [f.to_dict() for f in self.findings],
            'heuristic_findings': [f.to_dict() for f in self.heuristic_findings],
            'llm_findings': [f.to_dict() for f in self.llm_findings],
            'iocs': {ioc_type: [ioc.to_dict() for ioc in ioc_list]
                     for ioc_type, ioc_list in self.iocs.items()},
            'mitre_techniques': {tech_id: tech.to_dict()
                                for tech_id, tech in self.mitre_techniques.items()},
            'metadata': self.metadata
        }
        if self.yara_contribution:
            result['yara_contribution'] = self.yara_contribution.to_dict()
        return result


@dataclass
class VerdictResultEnhanced:
    """
    Enhanced verdict result with detailed scoring breakdown.
    
    This dataclass extends the basic verdict tuple (Verdict, float) with
    comprehensive scoring details from the multi-scorer architecture.
    Used when enhanced scoring mode is enabled (use_enhanced_scoring=True).
    
    Attributes:
        verdict: Overall analysis verdict (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN).
        confidence: Overall confidence in the verdict (0.0 to 1.0).
        score_breakdown: Detailed breakdown of final score calculation.
        scorer_scores: Individual scores from each scorer.
        explanations: Explanations from each scorer.
        execution_time: Total execution time in seconds.
        
    Examples:
        >>> result = VerdictResultEnhanced(
        ...     verdict=Verdict.MALICIOUS,
        ...     confidence=0.85,
        ...     score_breakdown={'final_score': 75.0, 'threshold': 70},
        ...     scorer_scores={'severity': 80.0, 'cooccurrence': 70.0},
        ...     explanations={'severity': ['High severity findings detected']},
        ...     execution_time=0.123
        ... )
        >>> # Convert to legacy tuple format
        >>> legacy_result = result.to_tuple()
        >>> print(legacy_result)
        (Verdict.MALICIOUS, 0.85)
    """
    verdict: Verdict
    confidence: float
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    scorer_scores: Dict[str, float] = field(default_factory=dict)
    explanations: Dict[str, List[str]] = field(default_factory=dict)
    execution_time: float = 0.0
    
    def __post_init__(self):
        """Validates enhanced verdict result fields after initialization."""
        # Validate confidence
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}. Must be between 0.0 and 1.0")
        
        # Validate execution time
        if self.execution_time < 0.0:
            raise ValueError(f"Invalid execution_time: {self.execution_time}. Must be >= 0.0")
    
    def to_tuple(self) -> Tuple[Verdict, float]:
        """
        Converts enhanced result to legacy tuple format for backward compatibility.
        
        Returns:
            Tuple of (Verdict, confidence_score).
            
        Examples:
            >>> result = VerdictResultEnhanced(Verdict.MALICIOUS, 0.85)
            >>> legacy = result.to_tuple()
            >>> print(legacy)
            (Verdict.MALICIOUS, 0.85)
        """
        return (self.verdict, self.confidence)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts enhanced verdict result to dictionary format.
        
        Returns:
            Dictionary representation of the enhanced verdict result.
            
        Examples:
            >>> result = VerdictResultEnhanced(
            ...     verdict=Verdict.MALICIOUS,
            ...     confidence=0.85,
            ...     scorer_scores={'severity': 80.0}
            ... )
            >>> result_dict = result.to_dict()
            >>> print(result_dict['verdict'])
            'malicious'
        """
        return {
            'verdict': self.verdict.value,
            'confidence': self.confidence,
            'score_breakdown': self.score_breakdown,
            'scorer_scores': self.scorer_scores,
            'explanations': self.explanations,
            'execution_time': self.execution_time
        }