# sentinel/sanitizer.py

"""
Sensitive data sanitization module for Script Sentinel.

This module provides functionality to detect and redact sensitive information
from scripts before transmission to LLM services, ensuring compliance with
security and privacy requirements (NFR-2).

Sanitization patterns include:
- Credentials (passwords, API keys, tokens, bearer tokens)
- IP addresses (IPv4 and IPv6)
- File paths (Windows and Unix)
- Domain names (configurable with exceptions)
"""

import re
import hashlib
import logging
from typing import Dict, List, Tuple, Set
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SanitizationStats:
    """Statistics about sanitization operations."""
    credentials_redacted: int = 0
    ip_addresses_redacted: int = 0
    file_paths_redacted: int = 0
    domains_redacted: int = 0
    total_redactions: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        """Convert stats to dictionary."""
        return {
            'credentials_redacted': self.credentials_redacted,
            'ip_addresses_redacted': self.ip_addresses_redacted,
            'file_paths_redacted': self.file_paths_redacted,
            'domains_redacted': self.domains_redacted,
            'total_redactions': self.total_redactions
        }


# Regex patterns for sensitive data detection
CREDENTIAL_PATTERNS = {
    # Password patterns (case-insensitive)
    'password': re.compile(
        r'(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\';]+)["\']?',
        re.IGNORECASE
    ),
    # API key patterns
    'api_key': re.compile(
        r'(api[_-]?key|apikey)\s*[=:]\s*["\']?([^\s"\';]+)["\']?',
        re.IGNORECASE
    ),
    # Token patterns
    'token': re.compile(
        r'(token|access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']?([^\s"\';]+)["\']?',
        re.IGNORECASE
    ),
    # Bearer token patterns
    'bearer': re.compile(
        r'(bearer)\s+([^\s"\';]+)',
        re.IGNORECASE
    ),
    # Secret patterns
    'secret': re.compile(
        r'(secret|client[_-]?secret)\s*[=:]\s*["\']?([^\s"\';]+)["\']?',
        re.IGNORECASE
    ),
}

# IP address patterns
IP_PATTERNS = {
    # IPv4 addresses
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    # IPv6 addresses (simplified pattern)
    'ipv6': re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ),
}

# File path patterns
PATH_PATTERNS = {
    # Windows paths (e.g., C:\Users\..., \\server\share\...)
    'windows_path': re.compile(
        r'(?:[A-Za-z]:\\|\\\\)[^\s<>"|?*\n]+',
        re.IGNORECASE
    ),
    # Unix paths (e.g., /home/user/..., /var/log/...)
    'unix_path': re.compile(
        r'/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]*'
    ),
}

# Domain name pattern
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)

# System paths that should be preserved (common system directories)
SYSTEM_PATHS = {
    '/bin', '/usr', '/etc', '/var', '/tmp', '/opt', '/home',
    'C:\\Windows', 'C:\\Program Files', 'C:\\ProgramData',
    '/System', '/Library', '/Applications'
}

# Test/example domains that should be preserved
SAFE_DOMAINS = {
    'example.com', 'example.org', 'example.net',
    'localhost', 'test.com', 'demo.com'
}


def _hash_value(value: str) -> str:
    """
    Creates a consistent hash of a value for anonymization.
    
    Args:
        value: The value to hash.
        
    Returns:
        Hexadecimal hash string (first 8 characters).
    """
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _should_preserve_path(path: str) -> bool:
    """
    Determines if a file path should be preserved (not redacted).
    
    System paths and common directories are preserved to maintain
    script context while protecting user-specific paths.
    
    Args:
        path: The file path to check.
        
    Returns:
        True if path should be preserved, False if it should be redacted.
    """
    path_lower = path.lower()
    
    # Preserve system paths only if they match exactly or are direct children
    for sys_path in SYSTEM_PATHS:
        sys_path_lower = sys_path.lower()
        # Exact match or direct child (e.g., /bin/bash is ok, /home/user is not)
        if path_lower == sys_path_lower:
            return True
        # For system directories, only preserve if it's a direct binary/command
        if sys_path_lower in ['/bin', '/usr', '/etc', '/var', '/tmp', '/opt']:
            # Check if it's a direct child (no additional subdirectories after user paths)
            if path_lower.startswith(sys_path_lower + '/'):
                # Don't preserve /home/user/... paths
                if '/home/' not in path_lower or path_lower.startswith('/home/') and path_lower.count('/') <= 2:
                    continue
                return True
    
    # Preserve very short paths (likely system paths like /bin, /usr)
    if len(path) < 10 and path.count('/') <= 2:
        return True
    
    return False


def _should_preserve_domain(domain: str) -> bool:
    """
    Determines if a domain should be preserved (not redacted).
    
    Test domains and common safe domains are preserved.
    
    Args:
        domain: The domain to check.
        
    Returns:
        True if domain should be preserved, False if it should be redacted.
    """
    return domain.lower() in SAFE_DOMAINS


def sanitize_script(
    script_content: str,
    language: str = 'unknown',
    redact_domains: bool = True
) -> Tuple[str, SanitizationStats]:
    """
    Sanitizes script content by redacting sensitive information.
    
    This function removes or anonymizes:
    - Credentials (passwords, API keys, tokens)
    - IP addresses (IPv4 and IPv6)
    - File paths (with exceptions for system paths)
    - Domain names (configurable)
    
    Args:
        script_content: The raw script text to sanitize.
        language: Script language for context-aware sanitization.
        redact_domains: Whether to redact domain names (default: True).
        
    Returns:
        Tuple of (sanitized_content, sanitization_stats).
        
    Examples:
        >>> script = 'password="secret123" at 192.168.1.1'
        >>> sanitized, stats = sanitize_script(script)
        >>> print(sanitized)
        password="[REDACTED]" at [IP_REDACTED]
        >>> print(stats.credentials_redacted)
        1
    """
    if not script_content:
        return script_content, SanitizationStats()
    
    stats = SanitizationStats()
    sanitized = script_content
    
    # Track what we've already redacted to avoid double-counting
    redacted_positions: Set[Tuple[int, int]] = set()
    
    # 1. Redact credentials (highest priority)
    for pattern_name, pattern in CREDENTIAL_PATTERNS.items():
        matches = list(pattern.finditer(sanitized))
        for match in reversed(matches):  # Reverse to maintain positions
            # Only redact the value part (group 2), keep the key
            if len(match.groups()) >= 2:
                value_start = match.start(2)
                value_end = match.end(2)
                
                # Check if already redacted
                if (value_start, value_end) not in redacted_positions:
                    sanitized = (
                        sanitized[:value_start] +
                        '[REDACTED]' +
                        sanitized[value_end:]
                    )
                    redacted_positions.add((value_start, value_end))
                    stats.credentials_redacted += 1
    
    # 2. Redact IP addresses
    for pattern_name, pattern in IP_PATTERNS.items():
        matches = list(pattern.finditer(sanitized))
        for match in reversed(matches):
            start, end = match.span()
            if (start, end) not in redacted_positions:
                sanitized = (
                    sanitized[:start] +
                    '[IP_REDACTED]' +
                    sanitized[end:]
                )
                redacted_positions.add((start, end))
                stats.ip_addresses_redacted += 1
    
    # 3. Redact file paths (with exceptions for system paths)
    # Process paths before domains to avoid conflicts
    for pattern_name, pattern in PATH_PATTERNS.items():
        matches = list(pattern.finditer(sanitized))
        for match in reversed(matches):
            path = match.group(0)
            start, end = match.span()
            
            # Skip if already redacted or should be preserved
            if (start, end) in redacted_positions or _should_preserve_path(path):
                continue
            
            # Additional check: skip very short paths that might be false positives
            if len(path) < 5:
                continue
            
            # Hash the path for anonymization
            path_hash = _hash_value(path)
            sanitized = (
                sanitized[:start] +
                f'[PATH_{path_hash}]' +
                sanitized[end:]
            )
            # Mark all positions within this range as redacted
            for i in range(start, end):
                redacted_positions.add((i, i+1))
            redacted_positions.add((start, end))
            stats.file_paths_redacted += 1
    
    # 4. Redact domain names (if enabled)
    if redact_domains:
        matches = list(DOMAIN_PATTERN.finditer(sanitized))
        for match in reversed(matches):
            domain = match.group(0)
            start, end = match.span()
            
            # Skip if already redacted or should be preserved
            if (start, end) in redacted_positions or _should_preserve_domain(domain):
                continue
            
            # Check if this position overlaps with any redacted range
            overlaps = False
            for i in range(start, end):
                if any(i >= s and i < e for s, e in redacted_positions):
                    overlaps = True
                    break
            
            if overlaps:
                continue
            
            # Hash the domain for anonymization
            domain_hash = _hash_value(domain)
            sanitized = (
                sanitized[:start] +
                f'[DOMAIN_{domain_hash}]' +
                sanitized[end:]
            )
            redacted_positions.add((start, end))
            stats.domains_redacted += 1
    
    # Calculate total redactions
    stats.total_redactions = (
        stats.credentials_redacted +
        stats.ip_addresses_redacted +
        stats.file_paths_redacted +
        stats.domains_redacted
    )
    
    logger.info(
        f"Sanitization complete: {stats.total_redactions} total redactions "
        f"({stats.credentials_redacted} credentials, "
        f"{stats.ip_addresses_redacted} IPs, "
        f"{stats.file_paths_redacted} paths, "
        f"{stats.domains_redacted} domains)"
    )
    
    return sanitized, stats


def validate_sanitization(original: str, sanitized: str) -> bool:
    """
    Validates that sanitization was successful by checking for common
    sensitive data patterns in the sanitized output.
    
    Args:
        original: Original script content.
        sanitized: Sanitized script content.
        
    Returns:
        True if sanitization appears successful, False if sensitive data detected.
    """
    # Check for common credential patterns
    for pattern in CREDENTIAL_PATTERNS.values():
        matches = pattern.finditer(sanitized)
        for match in matches:
            # If we find a match with a non-redacted value, sanitization failed
            if len(match.groups()) >= 2:
                value = match.group(2)
                if value and not value.startswith('[') and len(value) > 3:
                    logger.warning(f"Potential credential leak detected: {match.group(0)}")
                    return False
    
    # Check for IP addresses
    for pattern in IP_PATTERNS.values():
        if pattern.search(sanitized):
            logger.warning("Potential IP address leak detected")
            return False
    
    return True