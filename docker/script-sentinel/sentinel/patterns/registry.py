# sentinel/patterns/registry.py

"""
Pattern registry for managing and organizing security patterns.

The PatternRegistry provides a centralized system for registering, organizing,
and retrieving patterns. It supports plugin-based pattern additions and
provides filtering by language, severity, and category.
"""

import logging
from typing import List, Optional, Dict
from pathlib import Path

from .models import Pattern

logger = logging.getLogger(__name__)


class PatternRegistry:
    """
    Central registry for security patterns.
    
    The registry manages all loaded patterns and provides methods for:
    - Registering new patterns
    - Retrieving patterns by various criteria
    - Loading patterns from directories
    - Managing pattern priorities
    
    Patterns are stored in memory and can be filtered by language, severity,
    category, or other attributes. The registry ensures no duplicate pattern IDs
    and maintains patterns in priority order.
    
    Examples:
        >>> registry = PatternRegistry()
        >>> success, error = registry.register_pattern(pattern)
        >>> if success:
        ...     patterns = registry.get_patterns(language='powershell')
    """
    
    def __init__(self):
        """Initializes an empty pattern registry."""
        self._patterns: Dict[str, Pattern] = {}
        self._patterns_by_language: Dict[str, List[str]] = {
            'powershell': [],
            'bash': [],
            'javascript': []
        }
        self._patterns_by_category: Dict[str, List[str]] = {}
        logger.info("Pattern registry initialized")
    
    def register_pattern(self, pattern: Pattern) -> tuple[bool, Optional[str]]:
        """
        Registers a new pattern in the registry.
        
        Args:
            pattern: Pattern object to register.
            
        Returns:
            Tuple of (success, error_message).
            On success: (True, None)
            On failure: (False, error_message)
            
        Examples:
            >>> registry = PatternRegistry()
            >>> pattern = Pattern(id='PS-001', name='Test', ...)
            >>> success, error = registry.register_pattern(pattern)
            >>> if not success:
            ...     print(f"Registration failed: {error}")
        """
        try:
            # Check for duplicate ID
            if pattern.id in self._patterns:
                return False, f"Pattern with ID '{pattern.id}' already registered"
            
            # Validate pattern (will raise ValueError if invalid)
            # Pattern validation happens in __post_init__
            
            # Register pattern
            self._patterns[pattern.id] = pattern
            
            # Index by language
            for language in pattern.languages:
                lang_key = language.lower()
                if lang_key in self._patterns_by_language:
                    self._patterns_by_language[lang_key].append(pattern.id)
            
            # Index by category
            if pattern.category not in self._patterns_by_category:
                self._patterns_by_category[pattern.category] = []
            self._patterns_by_category[pattern.category].append(pattern.id)
            
            logger.info(f"Registered pattern: {pattern.id} ({pattern.name})")
            return True, None
            
        except ValueError as e:
            return False, f"Invalid pattern: {str(e)}"
        except Exception as e:
            return False, f"Failed to register pattern: {str(e)}"
    
    def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """
        Retrieves a specific pattern by ID.
        
        Args:
            pattern_id: Pattern ID to retrieve.
            
        Returns:
            Pattern object if found, None otherwise.
        """
        return self._patterns.get(pattern_id)
    
    def get_patterns(
        self,
        language: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        enabled_only: bool = True
    ) -> List[Pattern]:
        """
        Retrieves patterns matching the specified criteria.
        
        Patterns are returned in priority order (highest priority first),
        based on severity and confidence scores.
        
        Args:
            language: Filter by language ('powershell', 'bash', 'javascript').
            severity: Filter by severity ('High', 'Medium', 'Low').
            category: Filter by category.
            enabled_only: If True, only return enabled patterns.
            
        Returns:
            List of Pattern objects matching criteria, sorted by priority.
            
        Examples:
            >>> # Get all high-severity PowerShell patterns
            >>> patterns = registry.get_patterns(
            ...     language='powershell',
            ...     severity='High'
            ... )
            
            >>> # Get all patterns for a specific category
            >>> patterns = registry.get_patterns(category='command_injection')
        """
        # Start with all patterns or filter by language
        if language:
            lang_key = language.lower()
            if lang_key not in self._patterns_by_language:
                return []
            pattern_ids = self._patterns_by_language[lang_key]
            candidates = [self._patterns[pid] for pid in pattern_ids]
        else:
            candidates = list(self._patterns.values())
        
        # Apply filters
        filtered = candidates
        
        if enabled_only:
            filtered = [p for p in filtered if p.enabled]
        
        if severity:
            filtered = [p for p in filtered if p.severity == severity]
        
        if category:
            filtered = [p for p in filtered if p.category == category]
        
        # Sort by priority (highest first)
        filtered.sort(key=lambda p: p.get_priority_score(), reverse=True)
        
        return filtered
    
    def get_all_patterns(self) -> List[Pattern]:
        """
        Retrieves all registered patterns.
        
        Returns:
            List of all Pattern objects, sorted by priority.
        """
        return self.get_patterns(enabled_only=False)
    
    def get_pattern_count(self) -> int:
        """
        Returns the total number of registered patterns.
        
        Returns:
            Number of patterns in registry.
        """
        return len(self._patterns)
    
    def get_enabled_count(self) -> int:
        """
        Returns the number of enabled patterns.
        
        Returns:
            Number of enabled patterns.
        """
        return len([p for p in self._patterns.values() if p.enabled])
    
    def disable_pattern(self, pattern_id: str) -> tuple[bool, Optional[str]]:
        """
        Disables a pattern without removing it from registry.
        
        Args:
            pattern_id: ID of pattern to disable.
            
        Returns:
            Tuple of (success, error_message).
        """
        pattern = self._patterns.get(pattern_id)
        if not pattern:
            return False, f"Pattern '{pattern_id}' not found"
        
        pattern.enabled = False
        logger.info(f"Disabled pattern: {pattern_id}")
        return True, None
    
    def enable_pattern(self, pattern_id: str) -> tuple[bool, Optional[str]]:
        """
        Enables a previously disabled pattern.
        
        Args:
            pattern_id: ID of pattern to enable.
            
        Returns:
            Tuple of (success, error_message).
        """
        pattern = self._patterns.get(pattern_id)
        if not pattern:
            return False, f"Pattern '{pattern_id}' not found"
        
        pattern.enabled = True
        logger.info(f"Enabled pattern: {pattern_id}")
        return True, None
    
    def clear(self):
        """Removes all patterns from the registry."""
        self._patterns.clear()
        for lang_list in self._patterns_by_language.values():
            lang_list.clear()
        self._patterns_by_category.clear()
        logger.info("Pattern registry cleared")
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Returns statistics about registered patterns.
        
        Returns:
            Dictionary with pattern statistics including:
            - total: Total number of patterns
            - enabled: Number of enabled patterns
            - by_language: Count per language
            - by_severity: Count per severity level
            - by_category: Count per category
        """
        stats = {
            'total': len(self._patterns),
            'enabled': self.get_enabled_count(),
            'by_language': {},
            'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'by_category': {}
        }
        
        # Count by language
        for lang, pattern_ids in self._patterns_by_language.items():
            stats['by_language'][lang] = len(pattern_ids)
        
        # Count by severity and category
        for pattern in self._patterns.values():
            if pattern.enabled:
                stats['by_severity'][pattern.severity] += 1
                stats['by_category'][pattern.category] = \
                    stats['by_category'].get(pattern.category, 0) + 1
        
        return stats