# sentinel/obfuscation.py

"""
Obfuscation detection module for Script Sentinel.

Detects common obfuscation techniques across PowerShell, Bash, and JavaScript
using a hybrid approach combining entropy-based and pattern-based detection.

Techniques detected:
- Base64 encoding
- String concatenation/manipulation
- Character substitution
- Compression
- Variable name obfuscation
- And more...

References:
- Story 3.2: Obfuscation Detection
- Research: docs/obfuscation-research-report.md
- MITRE ATT&CK: T1027 (Obfuscated Files or Information)
"""

import re
import math
import logging
from typing import List, Optional, Dict, Any, Tuple
from collections import Counter
from dataclasses import dataclass

from .models import Finding

# Configure logging
logger = logging.getLogger(__name__)


# Language-specific entropy thresholds (from research)
ENTROPY_THRESHOLDS = {
    'powershell': {
        'suspicious': 4.5,
        'high': 5.5
    },
    'bash': {
        'suspicious': 4.5,
        'high': 5.5  # Raised from 5.0 to reduce FPs on awk/sed patterns
    },
    'javascript': {
        'suspicious': 4.5,
        'high': 5.5
    }
}


@dataclass
class ObfuscationIndicator:
    """Represents a detected obfuscation indicator."""
    technique: str
    confidence: float
    severity: str
    description: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    metadata: Dict[str, Any] = None


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text.
    
    Shannon entropy measures the randomness/information density of text.
    Higher entropy suggests more random/obfuscated content.
    
    Args:
        text: String to analyze
    
    Returns:
        Entropy value (0.0 to 8.0, higher = more random/obfuscated)
    
    Formula: H(X) = -Σ p(x) * log2(p(x))
    where p(x) is probability of character x
    
    Examples:
        >>> calculate_entropy("aaaa")  # Low entropy (repetitive)
        0.0
        >>> calculate_entropy("abcd")  # Higher entropy (diverse)
        2.0
        >>> calculate_entropy("aB3$xZ9!")  # High entropy (random)
        3.0
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(text)
    text_len = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / text_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


def detect_base64_powershell(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect base64 encoding in PowerShell scripts.
    
    Patterns detected:
    - -EncodedCommand / -enc parameter
    - [Convert]::FromBase64String()
    - [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String())
    - Base64 strings in variable assignments
    
    Args:
        script: PowerShell script content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern 1: -EncodedCommand parameter
    enc_pattern = re.compile(r'(?i)-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]{20,})', re.MULTILINE)
    for match in enc_pattern.finditer(script):
        base64_str = match.group(1)
        entropy = calculate_entropy(base64_str)
        
        # Find line number
        line_num = script[:match.start()].count('\n') + 1
        
        indicators.append(ObfuscationIndicator(
            technique='base64_encoded_command',
            confidence=0.95,
            severity='High',
            description=f'PowerShell -EncodedCommand parameter detected with base64 payload (entropy: {entropy:.2f})',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'entropy': entropy, 'base64_length': len(base64_str)}
        ))
    
    # Pattern 2: FromBase64String method with direct string
    from_base64_pattern = re.compile(
        r'\[Convert\]::FromBase64String\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']',
        re.IGNORECASE | re.MULTILINE
    )
    for match in from_base64_pattern.finditer(script):
        base64_str = match.group(1)
        entropy = calculate_entropy(base64_str)
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if followed by execution (IEX, Invoke-Expression)
        context = script[match.end():match.end()+200]
        has_execution = bool(re.search(r'(?i)(iex|invoke-expression)', context))
        
        confidence = 0.9 if has_execution else 0.7
        severity = 'High' if has_execution else 'Medium'
        
        indicators.append(ObfuscationIndicator(
            technique='base64_decoding',
            confidence=confidence,
            severity=severity,
            description=f'Base64 decoding detected (entropy: {entropy:.2f}){" with execution" if has_execution else ""}',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'entropy': entropy, 'has_execution': has_execution}
        ))
    
    # Pattern 3: Base64 strings in variable assignments (common obfuscation technique)
    # Detects: $var = 'SW52b2tlLUV4cHJlc3Npb24...'
    base64_var_pattern = re.compile(
        r'["\']([A-Za-z0-9+/=]{50,})["\']',
        re.MULTILINE
    )
    
    # Track already detected base64 strings to avoid duplicates
    detected_strings = set()
    
    for match in base64_var_pattern.finditer(script):
        base64_str = match.group(1)
        
        # Skip if already detected
        if base64_str in detected_strings:
            continue
        
        # Validate it looks like base64 (high ratio of valid base64 chars)
        valid_b64_chars = sum(1 for c in base64_str if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if valid_b64_chars / len(base64_str) < 0.95:
            continue
        
        entropy = calculate_entropy(base64_str)
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if this base64 string is used with FromBase64String or similar
        # Look for the variable name and check if it's decoded later
        context_before = script[max(0, match.start()-100):match.start()]
        context_after = script[match.end():min(len(script), match.end()+300)]
        
        # Check for FromBase64String usage
        has_decoding = bool(re.search(r'(?i)(frombase64string|convert.*frombase64)', context_after))
        
        # Check for execution after decoding
        has_execution = bool(re.search(r'(?i)(iex|invoke-expression)', context_after))
        
        # Only flag if there's evidence of decoding or execution
        if has_decoding or has_execution or len(base64_str) > 100:
            confidence = 0.85 if (has_decoding and has_execution) else 0.7 if has_decoding else 0.6
            severity = 'High' if has_execution else 'Medium'
            
            detected_strings.add(base64_str)
            
            indicators.append(ObfuscationIndicator(
                technique='base64_encoding',
                confidence=confidence,
                severity=severity,
                description=f'Base64 encoded string detected (length: {len(base64_str)}, entropy: {entropy:.2f}){" with decoding" if has_decoding else ""}{" and execution" if has_execution else ""}',
                line_number=line_num,
                code_snippet=f"'{base64_str}'",  # Show full base64 string
                metadata={
                    'entropy': entropy,
                    'base64_length': len(base64_str),
                    'has_decoding': has_decoding,
                    'has_execution': has_execution
                }
            ))
    
    return indicators


def detect_base64_bash(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect base64 encoding in Bash scripts.
    
    Patterns detected:
    - base64 -d / --decode
    - echo ... | base64 -d
    - Command substitution with base64 decoding
    
    Args:
        script: Bash script content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: base64 decode with execution
    base64_pattern = re.compile(
        r'(echo\s+["\']?([A-Za-z0-9+/=]{20,})["\']?\s*\|)?\s*base64\s+(-d|--decode)',
        re.MULTILINE
    )
    
    for match in base64_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if piped to execution (bash, sh, eval)
        context = script[match.end():match.end()+100]
        has_execution = bool(re.search(r'\|\s*(bash|sh|eval)', context))
        
        confidence = 0.9 if has_execution else 0.6
        severity = 'High' if has_execution else 'Medium'
        
        base64_str = match.group(2) if match.group(2) else ''
        entropy = calculate_entropy(base64_str) if base64_str else 0.0
        
        indicators.append(ObfuscationIndicator(
            technique='base64_decoding',
            confidence=confidence,
            severity=severity,
            description=f'Base64 decoding detected{" with execution" if has_execution else ""}',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'entropy': entropy, 'has_execution': has_execution}
        ))
    
    return indicators


def detect_base64_javascript(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect base64 encoding in JavaScript.
    
    Patterns detected:
    - atob() function calls
    - btoa() function calls
    - Buffer.from(..., 'base64')
    
    Args:
        script: JavaScript content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: atob() with potential execution
    atob_pattern = re.compile(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]{20,})["\']', re.MULTILINE)
    
    for match in atob_pattern.finditer(script):
        base64_str = match.group(1)
        entropy = calculate_entropy(base64_str)
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if used with eval or Function
        context_before = script[max(0, match.start()-50):match.start()]
        context_after = script[match.end():match.end()+100]
        has_execution = bool(re.search(r'(eval|Function|new\s+Function)', context_before + context_after))
        
        confidence = 0.95 if has_execution else 0.6
        severity = 'High' if has_execution else 'Medium'
        
        # Check for data URI (legitimate use)
        is_data_uri = 'data:' in context_before[-20:]
        if is_data_uri:
            confidence *= 0.3  # Reduce confidence for data URIs
            severity = 'Low'
        
        indicators.append(ObfuscationIndicator(
            technique='base64_decoding',
            confidence=confidence,
            severity=severity,
            description=f'Base64 decoding (atob) detected (entropy: {entropy:.2f}){" with execution" if has_execution else ""}',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'entropy': entropy, 'has_execution': has_execution, 'is_data_uri': is_data_uri}
        ))
    
    return indicators


def detect_string_concatenation_powershell(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect suspicious string concatenation in PowerShell.
    
    Patterns:
    - Excessive + operator usage
    - Variable concatenation to build cmdlet names
    - -join operator
    - Format string obfuscation
    - scriptblock::Create() usage
    
    Args:
        script: PowerShell script content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern 1: Variable concatenation to build command names
    # Detects: $a='Inv'; $b='oke-'; $c='Expr'; $cmd = $a+$b+$c
    var_concat_pattern = re.compile(
        r'\$\w+\s*=\s*\$\w+\s*\+\s*\$\w+(?:\s*\+\s*\$\w+)*',
        re.MULTILINE
    )
    for match in var_concat_pattern.finditer(script):
        # Count how many variables are being concatenated
        var_count = len(re.findall(r'\$\w+', match.group(0))) - 1  # -1 for assignment variable
        
        if var_count >= 3:  # At least 3 variables concatenated
            line_num = script[:match.start()].count('\n') + 1
            
            # Check context for suspicious patterns
            context_start = max(0, match.start() - 200)
            context = script[context_start:match.end() + 100]
            
            # Look for cmdlet name fragments in nearby variable assignments
            has_cmdlet_fragments = bool(re.search(
                r'(?i)(invoke|expression|webrequest|webclient|download|iex|bypass|hidden)',
                context
            ))
            
            # Look for execution patterns after concatenation
            has_execution = bool(re.search(
                r'(?i)(&|\.|Invoke-Expression|iex)\s+\$\w+',
                context[match.end()-match.start():]
            ))
            
            if has_cmdlet_fragments or has_execution:
                confidence = 0.9 if (has_cmdlet_fragments and has_execution) else 0.75
                severity = 'High'
                
                indicators.append(ObfuscationIndicator(
                    technique='string_concatenation',
                    confidence=confidence,
                    severity=severity,
                    description=f'Variable concatenation to build command detected ({var_count} variables)',
                    line_number=line_num,
                    code_snippet=match.group(0)[:100],
                    metadata={
                        'var_count': var_count,
                        'has_cmdlet_fragments': has_cmdlet_fragments,
                        'has_execution': has_execution
                    }
                ))
    
    # Pattern 2: Excessive string concatenation (>5 operations in single statement)
    lines = script.split('\n')
    for line_num, line in enumerate(lines, 1):
        # Count + operators between quoted strings
        concat_count = len(re.findall(r'["\']\s*\+\s*["\']', line))
        
        if concat_count >= 5:
            # Check if building cmdlet names (suspicious)
            has_cmdlet_fragments = bool(re.search(r'(?i)(invoke|expression|webrequest|object|download)', line))
            
            confidence = 0.8 if has_cmdlet_fragments else 0.6
            severity = 'High' if has_cmdlet_fragments else 'Medium'
            
            indicators.append(ObfuscationIndicator(
                technique='string_concatenation',
                confidence=confidence,
                severity=severity,
                description=f'Excessive string concatenation detected ({concat_count} operations)',
                line_number=line_num,
                code_snippet=line[:100],
                metadata={'concat_count': concat_count, 'has_cmdlet_fragments': has_cmdlet_fragments}
            ))
    
    # Pattern 3: scriptblock::Create() - dynamic code execution
    scriptblock_pattern = re.compile(
        r'\[scriptblock\]::Create\s*\(',
        re.IGNORECASE | re.MULTILINE
    )
    for match in scriptblock_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if used with base64 or other obfuscation
        context = script[max(0, match.start()-200):match.end()+100]
        has_base64 = bool(re.search(r'(?i)(frombase64|base64)', context))
        has_encoding = bool(re.search(r'(?i)(encoding|utf8|getstring)', context))
        
        confidence = 0.9 if (has_base64 or has_encoding) else 0.75
        severity = 'High'
        
        indicators.append(ObfuscationIndicator(
            technique='dynamic_code_execution',
            confidence=confidence,
            severity=severity,
            description='Dynamic scriptblock creation detected (potential obfuscation)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'has_base64': has_base64, 'has_encoding': has_encoding}
        ))
    
    # Pattern: -join operator with character arrays
    join_pattern = re.compile(r'-join\s*\(\s*["\']([^"\']{1})["\']', re.IGNORECASE)
    for match in join_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        indicators.append(ObfuscationIndicator(
            technique='string_manipulation',
            confidence=0.75,
            severity='Medium',
            description='String join operation detected (potential obfuscation)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={}
        ))
    
    return indicators


def detect_string_concatenation_bash(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect suspicious string concatenation in Bash.
    
    Args:
        script: Bash script content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: Excessive variable concatenation
    lines = script.split('\n')
    for line_num, line in enumerate(lines, 1):
        # Count consecutive variable references (e.g., $a$b$c$d)
        var_concat_matches = re.findall(r'(\$\w+){4,}', line)
        
        if var_concat_matches:
            var_concat_count = max(len(m) // 2 for m in var_concat_matches)  # Approximate count
            
            # Check if building commands
            has_command_fragments = bool(re.search(r'(curl|wget|bash|sh|eval)', line))
            
            confidence = 0.8 if has_command_fragments else 0.6
            severity = 'High' if has_command_fragments else 'Medium'
            
            indicators.append(ObfuscationIndicator(
                technique='string_concatenation',
                confidence=confidence,
                severity=severity,
                description=f'Excessive variable concatenation detected',
                line_number=line_num,
                code_snippet=line[:100],
                metadata={'concat_count': var_concat_count}
            ))
    
    return indicators


def detect_string_concatenation_javascript(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect suspicious string concatenation in JavaScript.
    
    Args:
        script: JavaScript content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: Excessive string concatenation
    lines = script.split('\n')
    for line_num, line in enumerate(lines, 1):
        # Count + operators between quoted strings
        concat_count = len(re.findall(r'["\']\s*\+\s*["\']', line))
        
        if concat_count >= 5:
            # Check if building function names (eval, Function, etc.)
            has_exec_fragments = bool(re.search(r'(eval|Function|document|window)', line))
            
            confidence = 0.8 if has_exec_fragments else 0.6
            severity = 'High' if has_exec_fragments else 'Medium'
            
            indicators.append(ObfuscationIndicator(
                technique='string_concatenation',
                confidence=confidence,
                severity=severity,
                description=f'Excessive string concatenation detected ({concat_count} operations)',
                line_number=line_num,
                code_snippet=line[:100],
                metadata={'concat_count': concat_count}
            ))
    
    # Pattern: Array join for string construction
    join_pattern = re.compile(r'\[["\'][^"\']{1}["\'](?:,\s*["\'][^"\']{1}["\']){5,}\]\.join\s*\(', re.MULTILINE)
    for match in join_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        indicators.append(ObfuscationIndicator(
            technique='string_manipulation',
            confidence=0.75,
            severity='Medium',
            description='Array join for string construction detected',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={}
        ))
    
    return indicators


def detect_amsi_bypass_powershell(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect AMSI (Antimalware Scan Interface) bypass attempts in PowerShell.

    AMSI bypasses are commonly used by attackers to evade Windows Defender
    and other security products. These are high-confidence malicious indicators.

    Args:
        script: PowerShell script content
        ast: Optional AST for structural analysis

    Returns:
        List of obfuscation indicators
    """
    indicators = []

    # Pattern 1: [Ref].Assembly.GetType() AMSI bypass (most common)
    # Detects: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    amsi_reflection_pattern = re.compile(
        r'\[Ref\]\.Assembly\.GetType\s*\(\s*["\'].*(?:Amsi|amsi).*["\']',
        re.IGNORECASE | re.MULTILINE
    )
    for match in amsi_reflection_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        indicators.append(ObfuscationIndicator(
            technique='amsi_bypass',
            confidence=0.98,
            severity='Critical',
            description='AMSI bypass via reflection detected (AmsiUtils access)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'bypass_type': 'reflection', 'technique': 'T1562.001'}
        ))

    # Pattern 2: amsiInitFailed field manipulation
    # Detects: .GetField('amsiInitFailed', 'NonPublic,Static')
    amsi_field_pattern = re.compile(
        r'\.GetField\s*\(\s*["\']amsiInitFailed["\']',
        re.IGNORECASE | re.MULTILINE
    )
    for match in amsi_field_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        indicators.append(ObfuscationIndicator(
            technique='amsi_bypass',
            confidence=0.98,
            severity='Critical',
            description='AMSI bypass via amsiInitFailed field manipulation',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'bypass_type': 'field_manipulation', 'technique': 'T1562.001'}
        ))

    # Pattern 3: AmsiScanBuffer patching via Add-Type
    # Detects attempts to patch AmsiScanBuffer in memory
    amsi_patch_pattern = re.compile(
        r'(?:AmsiScanBuffer|amsi\.dll)',
        re.IGNORECASE | re.MULTILINE
    )
    for match in amsi_patch_pattern.finditer(script):
        # Check context for patching indicators
        context_start = max(0, match.start() - 200)
        context = script[context_start:match.end() + 200]
        has_patching = bool(re.search(
            r'(?:VirtualProtect|WriteProcessMemory|Marshal\.Copy|Add-Type.*DllImport)',
            context, re.IGNORECASE
        ))

        if has_patching:
            line_num = script[:match.start()].count('\n') + 1
            indicators.append(ObfuscationIndicator(
                technique='amsi_bypass',
                confidence=0.95,
                severity='Critical',
                description='AMSI bypass via memory patching detected',
                line_number=line_num,
                code_snippet=match.group(0)[:100],
                metadata={'bypass_type': 'memory_patch', 'technique': 'T1562.001'}
            ))

    # Pattern 4: Obfuscated AMSI strings (common evasion)
    # Detects: 'A'+'m'+'s'+'i' or similar fragmentation
    amsi_concat_pattern = re.compile(
        r'["\'][Aa]["\'].*\+.*["\'][Mm]["\'].*\+.*["\'][Ss]["\'].*\+.*["\'][Ii]["\']',
        re.MULTILINE
    )
    for match in amsi_concat_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        indicators.append(ObfuscationIndicator(
            technique='amsi_bypass',
            confidence=0.90,
            severity='Critical',
            description='Obfuscated AMSI string detected (potential bypass attempt)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'bypass_type': 'string_obfuscation', 'technique': 'T1562.001'}
        ))

    # Pattern 5: PowerShell execution policy bypass indicators
    # Often used alongside AMSI bypass
    policy_bypass_pattern = re.compile(
        r'-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)',
        re.IGNORECASE | re.MULTILINE
    )
    for match in policy_bypass_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        indicators.append(ObfuscationIndicator(
            technique='policy_bypass',
            confidence=0.7,
            severity='Medium',
            description='Execution policy bypass detected',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'bypass_type': 'execution_policy', 'technique': 'T1059.001'}
        ))

    return indicators


def detect_character_substitution_powershell(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect character substitution in PowerShell (tick marks, character codes).

    Args:
        script: PowerShell script content
        ast: Optional AST for structural analysis

    Returns:
        List of obfuscation indicators
    """
    indicators = []

    # Pattern: Excessive tick marks (backticks)
    tick_pattern = re.compile(r'(?:[`][a-zA-Z]){5,}', re.MULTILINE)
    for match in tick_pattern.finditer(script):
        tick_count = match.group(0).count('`')
        line_num = script[:match.start()].count('\n') + 1

        indicators.append(ObfuscationIndicator(
            technique='character_substitution',
            confidence=0.9,
            severity='High',
            description=f'Excessive tick mark obfuscation detected ({tick_count} tick marks)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'tick_count': tick_count}
        ))

    # Pattern: Character code usage
    char_pattern = re.compile(r'\[char\]\s*\d+', re.IGNORECASE | re.MULTILINE)
    char_matches = list(char_pattern.finditer(script))

    if len(char_matches) >= 10:
        # Group by line
        line_groups = {}
        for match in char_matches:
            line_num = script[:match.start()].count('\n') + 1
            line_groups[line_num] = line_groups.get(line_num, 0) + 1

        for line_num, count in line_groups.items():
            if count >= 3:  # At least 3 char codes per line
                indicators.append(ObfuscationIndicator(
                    technique='character_substitution',
                    confidence=0.85,
                    severity='High',
                    description=f'Character code obfuscation detected ({count} character codes)',
                    line_number=line_num,
                    code_snippet='',
                    metadata={'char_code_count': count}
                ))

    # Pattern: Reverse string execution
    # Detects: -join[char[]](77,105,107,101)[-1..-4] or similar
    reverse_pattern = re.compile(
        r'\[\s*-?\d+\s*\.\.\s*-?\d+\s*\]',
        re.MULTILINE
    )
    for match in reverse_pattern.finditer(script):
        # Check context for char array or string indicators
        context_start = max(0, match.start() - 100)
        context = script[context_start:match.start()]
        if re.search(r'(?:\[char\[\]\]|-join|\[string\])', context, re.IGNORECASE):
            line_num = script[:match.start()].count('\n') + 1
            indicators.append(ObfuscationIndicator(
                technique='string_reversal',
                confidence=0.85,
                severity='High',
                description='String reversal obfuscation detected',
                line_number=line_num,
                code_snippet=match.group(0)[:100],
                metadata={'technique': 'array_reversal'}
            ))

    return indicators


def detect_character_substitution_bash(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect character substitution in Bash (escaping, hex codes, empty string insertion).

    Args:
        script: Bash script content
        ast: Optional AST for structural analysis

    Returns:
        List of obfuscation indicators
    """
    indicators = []

    # Pattern 1: Empty string insertion obfuscation (e.g., c''u''r''l)
    # Detects commands split with empty strings to evade detection
    empty_string_pattern = re.compile(
        r'\b([a-z]{1,2})(\'\'[a-z]{1,2}){2,}',
        re.IGNORECASE | re.MULTILINE
    )
    for match in empty_string_pattern.finditer(script):
        empty_count = match.group(0).count("''")
        line_num = script[:match.start()].count('\n') + 1

        # Check if it's a known command being obfuscated
        deobfuscated = match.group(0).replace("''", "")
        is_command = bool(re.match(r'^(curl|wget|bash|sh|nc|cat|chmod|eval)$', deobfuscated, re.IGNORECASE))

        confidence = 0.95 if is_command else 0.75
        severity = 'High' if is_command else 'Medium'

        indicators.append(ObfuscationIndicator(
            technique='character_substitution',
            confidence=confidence,
            severity=severity,
            description=f'Empty string insertion obfuscation detected ({empty_count} insertions, command: {deobfuscated})',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'empty_count': empty_count, 'deobfuscated_command': deobfuscated}
        ))

    # Pattern 2: Excessive backslash escaping
    escape_pattern = re.compile(r'(?:\\[a-zA-Z]){5,}', re.MULTILINE)
    for match in escape_pattern.finditer(script):
        escape_count = match.group(0).count('\\')
        line_num = script[:match.start()].count('\n') + 1

        indicators.append(ObfuscationIndicator(
            technique='character_substitution',
            confidence=0.85,
            severity='High',
            description=f'Excessive character escaping detected ({escape_count} escapes)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'escape_count': escape_count}
        ))

    # Pattern 3: Hex escape sequences (within strings)
    hex_pattern = re.compile(r'(?:\\x[0-9a-fA-F]{2}){5,}', re.MULTILINE)
    for match in hex_pattern.finditer(script):
        hex_count = match.group(0).count('\\x')
        line_num = script[:match.start()].count('\n') + 1

        indicators.append(ObfuscationIndicator(
            technique='character_substitution',
            confidence=0.9,
            severity='High',
            description=f'Hex escape sequence obfuscation detected ({hex_count} sequences)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'hex_count': hex_count}
        ))

    # Pattern 4: $'\xNN' ANSI-C quoting hex escapes (Bash-specific)
    # Detects: $'\x63\x75\x72\x6c' which decodes to 'curl'
    ansi_c_hex_pattern = re.compile(
        r"\$'(?:\\x[0-9a-fA-F]{2}){3,}'",
        re.MULTILINE
    )
    for match in ansi_c_hex_pattern.finditer(script):
        hex_count = match.group(0).count('\\x')
        line_num = script[:match.start()].count('\n') + 1

        # Try to decode the hex string
        decoded = ''
        try:
            hex_chars = re.findall(r'\\x([0-9a-fA-F]{2})', match.group(0))
            decoded = ''.join(chr(int(h, 16)) for h in hex_chars)
        except (ValueError, OverflowError):
            decoded = '<decode failed>'

        # Check if decoded string is a known command
        is_command = bool(re.match(
            r'^(curl|wget|bash|sh|nc|cat|chmod|eval|python|perl|ruby|php)$',
            decoded, re.IGNORECASE
        ))

        confidence = 0.95 if is_command else 0.85
        severity = 'Critical' if is_command else 'High'

        indicators.append(ObfuscationIndicator(
            technique='ansi_c_hex_escape',
            confidence=confidence,
            severity=severity,
            description=f"ANSI-C hex escape obfuscation detected ({hex_count} escapes, decodes to: '{decoded}')",
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'hex_count': hex_count, 'decoded': decoded, 'is_command': is_command}
        ))

    # Pattern 5: Octal escapes in $'' quoting
    # Detects: $'\143\165\162\154' which decodes to 'curl'
    ansi_c_octal_pattern = re.compile(
        r"\$'(?:\\[0-7]{1,3}){3,}'",
        re.MULTILINE
    )
    for match in ansi_c_octal_pattern.finditer(script):
        octal_count = len(re.findall(r'\\[0-7]{1,3}', match.group(0)))
        line_num = script[:match.start()].count('\n') + 1

        # Try to decode the octal string
        decoded = ''
        try:
            octal_chars = re.findall(r'\\([0-7]{1,3})', match.group(0))
            decoded = ''.join(chr(int(o, 8)) for o in octal_chars)
        except (ValueError, OverflowError):
            decoded = '<decode failed>'

        is_command = bool(re.match(
            r'^(curl|wget|bash|sh|nc|cat|chmod|eval|python|perl|ruby|php)$',
            decoded, re.IGNORECASE
        ))

        confidence = 0.95 if is_command else 0.85
        severity = 'Critical' if is_command else 'High'

        indicators.append(ObfuscationIndicator(
            technique='ansi_c_octal_escape',
            confidence=confidence,
            severity=severity,
            description=f"ANSI-C octal escape obfuscation detected ({octal_count} escapes, decodes to: '{decoded}')",
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'octal_count': octal_count, 'decoded': decoded, 'is_command': is_command}
        ))

    # Pattern 6: Brace expansion command obfuscation
    # Detects: {c,u,r,l} or eval {e,c,h,o} patterns
    brace_expansion_pattern = re.compile(
        r'\{[a-z],[a-z](?:,[a-z])+\}',
        re.IGNORECASE | re.MULTILINE
    )
    for match in brace_expansion_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1

        # Extract letters from brace expansion
        letters = re.findall(r'[a-zA-Z]', match.group(0))
        potential_cmd = ''.join(letters)

        is_command = bool(re.match(
            r'^(curl|wget|bash|sh|nc|cat|chmod|eval|echo|rm|cp|mv)$',
            potential_cmd, re.IGNORECASE
        ))

        if is_command:
            indicators.append(ObfuscationIndicator(
                technique='brace_expansion',
                confidence=0.90,
                severity='High',
                description=f"Brace expansion obfuscation detected (potential command: '{potential_cmd}')",
                line_number=line_num,
                code_snippet=match.group(0)[:100],
                metadata={'potential_command': potential_cmd}
            ))

    # Pattern 7: /dev/tcp socket connections (Bash-specific backdoor)
    dev_tcp_pattern = re.compile(
        r'/dev/tcp/[^\s]+/\d+',
        re.MULTILINE
    )
    for match in dev_tcp_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1

        indicators.append(ObfuscationIndicator(
            technique='dev_tcp_socket',
            confidence=0.95,
            severity='Critical',
            description='Bash /dev/tcp socket connection detected (potential reverse shell)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'technique': 'T1059.004'}
        ))

    return indicators


def detect_character_substitution_javascript(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect character substitution in JavaScript (fromCharCode, escapes).
    
    Args:
        script: JavaScript content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: String.fromCharCode usage
    from_char_pattern = re.compile(r'String\.fromCharCode\s*\(([^)]+)\)', re.MULTILINE)
    for match in from_char_pattern.finditer(script):
        # Count character codes
        char_codes = re.findall(r'\d+', match.group(1))
        char_count = len(char_codes)
        
        if char_count > 10:
            line_num = script[:match.start()].count('\n') + 1
            
            indicators.append(ObfuscationIndicator(
                technique='character_substitution',
                confidence=0.9,
                severity='High',
                description=f'Character code obfuscation detected ({char_count} character codes)',
                line_number=line_num,
                code_snippet=match.group(0)[:100],
                metadata={'char_count': char_count}
            ))
    
    # Pattern: Excessive Unicode/hex escapes
    escape_pattern = re.compile(r'(?:\\[xu][0-9a-fA-F]{2,4}){10,}', re.MULTILINE)
    for match in escape_pattern.finditer(script):
        escape_count = len(re.findall(r'\\[xu]', match.group(0)))
        line_num = script[:match.start()].count('\n') + 1
        
        indicators.append(ObfuscationIndicator(
            technique='character_substitution',
            confidence=0.85,
            severity='High',
            description=f'Unicode/hex escape obfuscation detected ({escape_count} escapes)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'escape_count': escape_count}
        ))
    
    return indicators


def detect_compression_powershell(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect compression usage in PowerShell.
    
    Args:
        script: PowerShell script content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: Compression namespace usage
    compression_pattern = re.compile(
        r'System\.IO\.Compression\.(GZipStream|DeflateStream)',
        re.IGNORECASE | re.MULTILINE
    )
    
    for match in compression_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if followed by execution
        context = script[match.end():match.end()+300]
        has_execution = bool(re.search(r'(?i)(iex|invoke-expression)', context))
        
        confidence = 0.9 if has_execution else 0.6
        severity = 'High' if has_execution else 'Medium'
        
        indicators.append(ObfuscationIndicator(
            technique='compression',
            confidence=confidence,
            severity=severity,
            description=f'Compression detected ({match.group(1)}){" with execution" if has_execution else ""}',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={'compression_type': match.group(1), 'has_execution': has_execution}
        ))
    
    return indicators


def detect_compression_bash(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect compression usage in Bash.
    
    Args:
        script: Bash script content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: Compression commands with execution
    compression_pattern = re.compile(r'(gzip|gunzip|zcat)\s+', re.MULTILINE)
    
    for match in compression_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        # Check if piped to execution
        context = script[match.end():match.end()+100]
        has_execution = bool(re.search(r'\|\s*(bash|sh|eval)', context))
        
        if has_execution:
            indicators.append(ObfuscationIndicator(
                technique='compression',
                confidence=0.85,
                severity='High',
                description=f'Compression with execution detected ({match.group(1)})',
                line_number=line_num,
                code_snippet=match.group(0)[:100],
                metadata={'compression_cmd': match.group(1)}
            ))
    
    return indicators


def detect_compression_javascript(script: str, ast: Optional[dict] = None) -> List[ObfuscationIndicator]:
    """
    Detect packer/compression patterns in JavaScript.
    
    Args:
        script: JavaScript content
        ast: Optional AST for structural analysis
    
    Returns:
        List of obfuscation indicators
    """
    indicators = []
    
    # Pattern: JSFuck (only uses []()!+)
    # JSFuck is extreme obfuscation where ENTIRE script uses only []()!+ characters
    # Check if script has substantial JSFuck content (at least 100 consecutive chars)
    jsfuck_pattern = re.compile(r'[\[\]()!+]{100,}', re.MULTILINE)
    jsfuck_matches = jsfuck_pattern.findall(script)
    
    if jsfuck_matches:
        # Additional validation: check if it's a significant portion of the script
        total_jsfuck_chars = sum(len(match) for match in jsfuck_matches)
        script_length = len(script.replace('\n', '').replace(' ', ''))
        
        if total_jsfuck_chars > 200 or (script_length > 0 and total_jsfuck_chars / script_length > 0.3):
            indicators.append(ObfuscationIndicator(
                technique='packer_jsfuck',
                confidence=0.99,
                severity='High',
                description='JSFuck packer detected (extreme obfuscation)',
                line_number=1,
                code_snippet=script[:100],
                metadata={'packer': 'JSFuck', 'jsfuck_chars': total_jsfuck_chars}
            ))
    
    # Pattern: eval(unescape(...))
    unescape_pattern = re.compile(r'eval\s*\(\s*unescape\s*\(', re.MULTILINE)
    for match in unescape_pattern.finditer(script):
        line_num = script[:match.start()].count('\n') + 1
        
        indicators.append(ObfuscationIndicator(
            technique='compression',
            confidence=0.9,
            severity='High',
            description='Eval with unescape detected (packed code)',
            line_number=line_num,
            code_snippet=match.group(0)[:100],
            metadata={}
        ))
    
    return indicators


def analyze_entropy_segments(script: str, language: str) -> List[ObfuscationIndicator]:
    """
    Analyze script segments for high entropy (potential obfuscation).
    
    Uses context-aware filtering to reduce false positives from:
    - File paths (e.g., /var/log/application.log)
    - Variable names (e.g., $computerName, $backupPath)
    - Normal code patterns
    
    Args:
        script: Script content
        language: Script language ('powershell', 'bash', 'javascript')
    
    Returns:
        List of obfuscation indicators for high-entropy segments
    """
    indicators = []
    thresholds = ENTROPY_THRESHOLDS.get(language, ENTROPY_THRESHOLDS['javascript'])
    
    # Analyze line by line
    lines = script.split('\n')
    for line_num, line in enumerate(lines, 1):
        # Skip empty lines and comments
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or stripped.startswith('//'):
            continue
        
        # Skip lines that are clearly legitimate (reduce false positives)
        # 1. Skip lines with common file path patterns
        if re.search(r'[/\\][\w\-./\\]+\.(log|txt|json|xml|csv|conf|cfg|ini|yml|yaml)', line, re.IGNORECASE):
            continue
        
        # 2. Skip lines with simple variable assignments (common in benign scripts)
        if re.match(r'^\s*[\$@]?\w+\s*=\s*["\']?[\w\s/\\.:-]+["\']?\s*$', line):
            continue
        
        # 3. Skip lines with common cmdlets/commands without suspicious patterns
        if re.search(r'^\s*(Write-Host|echo|Get-\w+|Set-\w+|New-\w+|Remove-\w+|Test-\w+|Start-\w+|Stop-\w+)\s+', line, re.IGNORECASE):
            continue

        # 4. Skip lines with common bash utilities that have complex but legitimate syntax
        # awk, sed, grep patterns often have high entropy but are legitimate
        if re.search(r'\b(awk|sed|grep|perl|find)\s+[\'"$-]', line):
            continue

        # 5. Skip lines with HTTP headers (User-Agent strings have high entropy)
        if re.search(r'--header[=\s]+["\']?(User-Agent|Accept|Content-Type|Authorization):', line, re.IGNORECASE):
            continue

        # 6. Skip lines with format strings (printf/awk format specs)
        if re.search(r'printf\s*\(?\s*["\'][^"\']*%[0-9]*[dsfxe]', line):
            continue

        # 7. Skip lines with Docker/container tools (complex arguments but legitimate)
        if re.search(r'\b(docker|podman|docker-compose)\s+(build|run|exec|pull|push|tag|compose|images|ps|network|volume)', line, re.IGNORECASE):
            continue

        # 8. Skip lines with Kubernetes/helm commands (kubectl, helm have complex options)
        if re.search(r'\b(kubectl|helm|k9s|minikube|kind)\s+(apply|create|delete|get|describe|logs|exec|rollout|install|upgrade)', line, re.IGNORECASE):
            continue

        # 9. Skip lines with Infrastructure-as-Code tools (terraform, ansible, packer)
        if re.search(r'\b(terraform|ansible|ansible-playbook|packer|vagrant|pulumi)\s+', line, re.IGNORECASE):
            continue

        # 10. Skip lines with CI/CD environment variables or common CI patterns
        if re.search(r'\b(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_HOME|TRAVIS|CIRCLECI|BUILDKITE|AZURE_PIPELINES)\b', line):
            continue

        # 11. Skip lines with package manager commands (npm, pip, apt, yum, brew)
        if re.search(r'\b(npm|yarn|pnpm|pip3?|apt-get|apt|yum|dnf|pacman|brew|cargo|go\s+get|gem)\s+(install|update|upgrade|add|remove|uninstall)', line, re.IGNORECASE):
            continue

        # 12. Skip lines with git commands (complex but legitimate)
        if re.search(r'\bgit\s+(clone|pull|push|fetch|checkout|branch|merge|rebase|reset|commit|log|diff|status)', line, re.IGNORECASE):
            continue

        # 13. Skip lines with build tool commands (make, cmake, gcc, maven, gradle)
        if re.search(r'\b(make|cmake|gcc|g\+\+|clang|mvn|gradle|ant|msbuild|dotnet)\s+', line, re.IGNORECASE):
            continue

        # 14. Skip lines with systemd/service management (complex options)
        if re.search(r'\b(systemctl|service|journalctl|supervisorctl)\s+(start|stop|restart|enable|disable|status|reload|daemon-reload)', line, re.IGNORECASE):
            continue

        # 15. Skip lines with cloud CLI tools (aws, gcloud, az commands have complex args)
        if re.search(r'\b(aws|gcloud|az|doctl|linode-cli|scaleway)\s+[a-z]', line, re.IGNORECASE):
            continue

        # 16. Skip lines with testing framework commands (pytest, jest, mocha, etc.)
        if re.search(r'\b(pytest|py\.test|unittest|jest|mocha|karma|jasmine|rspec|phpunit|go\s+test|cargo\s+test|bats)\b', line, re.IGNORECASE):
            continue

        # 17. Skip lines with linting/formatting tools (eslint, prettier, black, flake8)
        if re.search(r'\b(eslint|prettier|black|isort|flake8|pylint|rubocop|gofmt|rustfmt|shellcheck)\s+', line, re.IGNORECASE):
            continue

        # 18. Skip lines with SSL/certificate commands (openssl has complex but legitimate args)
        if re.search(r'\b(openssl|certbot|keytool|mkcert)\s+(req|x509|genrsa|pkcs12|s_client|renew)', line, re.IGNORECASE):
            continue

        # 19. Skip lines with database CLI commands (mysql, psql, redis-cli, mongo)
        if re.search(r'\b(mysql|psql|redis-cli|mongo|mongosh|sqlite3|pg_dump|mysqldump)\s+', line, re.IGNORECASE):
            continue

        # 20. Skip lines with rsync/scp/sftp (file transfer commands have complex options)
        if re.search(r'\b(rsync|scp|sftp)\s+[-a-zA-Z]', line, re.IGNORECASE):
            continue
        
        # Calculate entropy for line
        entropy = calculate_entropy(line)
        
        # Only flag if entropy is significantly high AND line is long enough
        # Short lines can have high entropy naturally (e.g., "$a=1")
        min_line_length = 40  # Require at least 40 chars for entropy check
        
        if len(stripped) < min_line_length:
            continue
        
        # Check against thresholds with stricter criteria
        if entropy >= thresholds['high']:
            # Additional validation: check if line contains suspicious patterns
            has_suspicious_pattern = bool(re.search(
                r'(frombase64|atob|eval|invoke-expression|iex|downloadstring|webclient|'
                r'[A-Za-z0-9+/]{50,}=*|\\x[0-9a-f]{2}|%[0-9a-f]{2})',
                line, re.IGNORECASE
            ))
            
            if has_suspicious_pattern:
                indicators.append(ObfuscationIndicator(
                    technique='high_entropy',
                    confidence=0.85,
                    severity='High',
                    description=f'High entropy with suspicious patterns (entropy: {entropy:.2f})',
                    line_number=line_num,
                    code_snippet=line[:100],
                    metadata={'entropy': entropy, 'threshold': thresholds['high']}
                ))
        elif entropy >= thresholds['suspicious']:
            # For suspicious entropy, require even stronger evidence
            has_obfuscation_markers = bool(re.search(
                r'(["\'][^"\']{1}["\'][\s+\-,]){5,}|'  # Character array patterns
                r'(\\x[0-9a-f]{2}){5,}|'  # Hex escapes
                r'([`][a-zA-Z]){3,}|'  # Tick marks (PowerShell)
                r'(\$\w+){5,}',  # Excessive variable concatenation
                line
            ))
            
            if has_obfuscation_markers:
                indicators.append(ObfuscationIndicator(
                    technique='suspicious_entropy',
                    confidence=0.6,
                    severity='Medium',
                    description=f'Suspicious entropy with obfuscation markers (entropy: {entropy:.2f})',
                    line_number=line_num,
                    code_snippet=line[:100],
                    metadata={'entropy': entropy, 'threshold': thresholds['suspicious']}
                ))
    
    return indicators


def detect_obfuscation(script_content: str, language: str, ast: Optional[dict] = None) -> List[Finding]:
    """
    Detect obfuscation techniques in script content.
    
    Uses hybrid detection strategy combining:
    - Entropy-based detection (Shannon entropy with language-specific thresholds)
    - Pattern-based detection (regex and AST analysis)
    - Context-aware analysis (to reduce false positives)
    
    Args:
        script_content: Raw script text
        language: Script language ('powershell', 'bash', 'javascript')
        ast: Optional AST for structural analysis
    
    Returns:
        List of Finding objects for detected obfuscation, sorted by priority
        (severity × confidence, descending)
    
    Raises:
        None - errors logged, empty list returned on failure
    
    Examples:
        >>> findings = detect_obfuscation(script, 'powershell')
        >>> for f in findings:
        ...     print(f"{f.severity}: {f.description}")
    """
    try:
        if not script_content or not language:
            logger.warning("Empty script content or language")
            return []
        
        # Normalize language
        language = language.lower()
        if language not in ['powershell', 'bash', 'javascript']:
            logger.error(f"Unsupported language: {language}")
            return []
        
        logger.info(f"Starting obfuscation detection for {language} script ({len(script_content)} chars)")
        
        all_indicators: List[ObfuscationIndicator] = []
        
        # 1. Entropy-based detection
        all_indicators.extend(analyze_entropy_segments(script_content, language))
        
        # 2. Base64 detection
        if language == 'powershell':
            all_indicators.extend(detect_base64_powershell(script_content, ast))
        elif language == 'bash':
            all_indicators.extend(detect_base64_bash(script_content, ast))
        elif language == 'javascript':
            all_indicators.extend(detect_base64_javascript(script_content, ast))
        
        # 3. String concatenation detection
        if language == 'powershell':
            all_indicators.extend(detect_string_concatenation_powershell(script_content, ast))
        elif language == 'bash':
            all_indicators.extend(detect_string_concatenation_bash(script_content, ast))
        elif language == 'javascript':
            all_indicators.extend(detect_string_concatenation_javascript(script_content, ast))
        
        # 4. Character substitution detection
        if language == 'powershell':
            all_indicators.extend(detect_character_substitution_powershell(script_content, ast))
        elif language == 'bash':
            all_indicators.extend(detect_character_substitution_bash(script_content, ast))
        elif language == 'javascript':
            all_indicators.extend(detect_character_substitution_javascript(script_content, ast))

        # 4.5. Security bypass detection (PowerShell-specific)
        if language == 'powershell':
            all_indicators.extend(detect_amsi_bypass_powershell(script_content, ast))

        # 5. Compression detection
        if language == 'powershell':
            all_indicators.extend(detect_compression_powershell(script_content, ast))
        elif language == 'bash':
            all_indicators.extend(detect_compression_bash(script_content, ast))
        elif language == 'javascript':
            all_indicators.extend(detect_compression_javascript(script_content, ast))
        
        # Convert indicators to Finding objects
        findings = []
        for indicator in all_indicators:
            finding = Finding(
                description=indicator.description,
                severity=indicator.severity,
                confidence=indicator.confidence,
                pattern_id=f"OBF-{indicator.technique.upper()}-{language.upper()[:2]}",
                mitre_technique='T1027',  # Obfuscated Files or Information
                category='obfuscation',
                line_number=indicator.line_number,
                code_snippet=indicator.code_snippet,
                metadata=indicator.metadata or {},
                source='obfuscation'  # Mark as obfuscation detection source
            )
            findings.append(finding)
        
        # Sort by priority (severity × confidence)
        findings.sort(key=lambda f: f.get_priority_score(), reverse=True)
        
        logger.info(f"Obfuscation detection complete: {len(findings)} findings")
        return findings
    
    except Exception as e:
        logger.error(f"Error during obfuscation detection: {e}", exc_info=True)
        return []