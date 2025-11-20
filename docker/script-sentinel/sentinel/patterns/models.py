# sentinel/patterns/models.py

"""
Data models for pattern matching system.

Defines the Pattern and PatternMatch data classes used throughout
the pattern matching architecture.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class Pattern:
    """
    Represents a security pattern definition.
    
    A pattern defines what to look for in scripts and how to classify findings.
    Patterns can use either AST-based detection (structural analysis) or
    regex-based detection (text pattern matching).
    
    Attributes:
        id: Unique identifier for the pattern (e.g., 'PS-001', 'BASH-002').
        name: Human-readable pattern name.
        description: Detailed description of what the pattern detects.
        languages: List of supported languages ('powershell', 'bash', 'javascript').
        detection_type: Type of detection ('ast' or 'regex').
        detection_logic: The actual detection logic (AST query or regex pattern).
        severity: Severity level ('High', 'Medium', 'Low').
        mitre_technique: MITRE ATT&CK technique ID (e.g., 'T1059.001').
        confidence: Confidence score (0.0 to 1.0).
        category: Pattern category (e.g., 'command_injection', 'obfuscation').
        enabled: Whether the pattern is active.
        metadata: Additional pattern metadata.
        
    Examples:
        >>> pattern = Pattern(
        ...     id='PS-001',
        ...     name='Invoke-Expression Usage',
        ...     description='Detects use of Invoke-Expression cmdlet',
        ...     languages=['powershell'],
        ...     detection_type='ast',
        ...     detection_logic='//command_expression[command_name="Invoke-Expression"]',
        ...     severity='High',
        ...     mitre_technique='T1059.001',
        ...     confidence=0.9
        ... )
    """
    id: str
    name: str
    description: str
    languages: List[str]
    detection_type: str  # 'ast' or 'regex'
    detection_logic: str
    severity: str  # 'High', 'Medium', 'Low'
    mitre_technique: str
    confidence: float
    category: str = 'general'
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validates pattern fields after initialization."""
        # Validate severity
        valid_severities = {'Critical', 'High', 'Medium', 'Low'}
        if self.severity not in valid_severities:
            raise ValueError(f"Invalid severity: '{self.severity}'. Must be one of {valid_severities}")
        
        # Validate detection type
        valid_types = {'ast', 'regex'}
        if self.detection_type not in valid_types:
            raise ValueError(f"Invalid detection_type: {self.detection_type}. Must be one of {valid_types}")
        
        # Validate confidence
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Invalid confidence: {self.confidence}. Must be between 0.0 and 1.0")
        
        # Validate languages
        valid_languages = {'powershell', 'bash', 'javascript'}
        for lang in self.languages:
            if lang not in valid_languages:
                raise ValueError(f"Invalid language: {lang}. Must be one of {valid_languages}")
    
    def supports_language(self, language: str) -> bool:
        """
        Checks if pattern supports the given language.
        
        Args:
            language: Language to check ('powershell', 'bash', 'javascript').
            
        Returns:
            True if pattern supports the language, False otherwise.
        """
        return language.lower() in [lang.lower() for lang in self.languages]
    
    def get_priority_score(self) -> float:
        """
        Calculates priority score for pattern ordering.
        
        Priority is based on severity and confidence:
        - Critical severity: 4.0
        - High severity: 3.0
        - Medium severity: 2.0
        - Low severity: 1.0
        - Multiplied by confidence score
        
        Returns:
            Priority score (0.0 to 4.0).
        """
        severity_weights = {
            'Critical': 4.0,
            'High': 3.0,
            'Medium': 2.0,
            'Low': 1.0
        }
        return severity_weights.get(self.severity, 1.0) * self.confidence


@dataclass
class PatternMatch:
    """
    Represents a match of a pattern in analyzed code.
    
    When a pattern detects suspicious code, a PatternMatch is created
    to record the details of the finding.
    
    Attributes:
        pattern_id: ID of the pattern that matched.
        pattern_name: Name of the pattern that matched.
        severity: Severity level from the pattern.
        confidence: Confidence score from the pattern.
        description: Description of what was detected.
        line_number: Line number where pattern matched (if available).
        code_snippet: Code snippet that matched (if available).
        mitre_technique: MITRE ATT&CK technique ID.
        category: Pattern category.
        metadata: Additional match metadata.
        
    Examples:
        >>> match = PatternMatch(
        ...     pattern_id='PS-001',
        ...     pattern_name='Invoke-Expression Usage',
        ...     severity='High',
        ...     confidence=0.9,
        ...     description='Detected Invoke-Expression cmdlet',
        ...     line_number=42,
        ...     code_snippet='Invoke-Expression $cmd'
        ... )
    """
    pattern_id: str
    pattern_name: str
    severity: str
    confidence: float
    description: str
    mitre_technique: str
    category: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converts match to dictionary format.
        
        Returns:
            Dictionary representation of the match.
        """
        return {
            'pattern_id': self.pattern_id,
            'pattern_name': self.pattern_name,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'mitre_technique': self.mitre_technique,
            'category': self.category,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'metadata': self.metadata
        }