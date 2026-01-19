# sentinel/patterns/loader.py

"""
Pattern loader and validator for loading patterns from YAML files.

The PatternLoader handles:
- Loading pattern definitions from YAML files
- Validating pattern schemas
- Compiling regex patterns
- Loading patterns from directories
- Error reporting for invalid patterns
"""

import logging
import re
from pathlib import Path
from typing import List, Optional, Dict, Any
import yaml

from .models import Pattern

logger = logging.getLogger(__name__)


class PatternValidationError(Exception):
    """Raised when pattern validation fails."""
    pass


class PatternLoader:
    """
    Loads and validates security patterns from YAML files.
    
    The loader:
    1. Reads YAML pattern definition files
    2. Validates required fields and data types
    3. Compiles and validates regex patterns
    4. Creates Pattern objects
    5. Reports detailed validation errors
    
    Pattern files should follow the schema defined in schema.yaml.
    
    Examples:
        >>> loader = PatternLoader()
        >>> pattern, error = loader.load_pattern('patterns/ps-001.yaml')
        >>> if error:
        ...     print(f"Load failed: {error}")
        >>> else:
        ...     print(f"Loaded: {pattern.name}")
    """
    
    # Required fields for pattern definition
    REQUIRED_FIELDS = {
        'id', 'name', 'description', 'languages', 'detection_type',
        'detection_logic', 'severity', 'mitre_technique', 'confidence'
    }
    
    # Valid values for enum fields
    VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low'}
    VALID_DETECTION_TYPES = {'ast', 'regex'}
    VALID_LANGUAGES = {'powershell', 'bash', 'javascript'}
    
    def __init__(self):
        """Initializes the pattern loader."""
        self._validation_errors: List[str] = []
    
    def load_pattern(self, file_path: str | Path) -> tuple[Optional[Pattern], Optional[str]]:
        """
        Loads a single pattern from a YAML file.
        
        Args:
            file_path: Path to YAML pattern file.
            
        Returns:
            Tuple of (Pattern object, error_message).
            On success: (Pattern, None)
            On failure: (None, error_message)
            
        Examples:
            >>> loader = PatternLoader()
            >>> pattern, error = loader.load_pattern('patterns/ps-001.yaml')
            >>> if pattern:
            ...     print(f"Loaded pattern: {pattern.id}")
        """
        try:
            file_path = Path(file_path)
            
            # Check file exists
            if not file_path.exists():
                return None, f"Pattern file not found: {file_path}"
            
            # Read YAML file
            with open(file_path, 'r', encoding='utf-8') as f:
                pattern_data = yaml.safe_load(f)
            
            if not pattern_data:
                return None, f"Empty pattern file: {file_path}"
            
            # Validate and create pattern
            is_valid, errors = self.validate_pattern(pattern_data)
            if not is_valid:
                error_msg = f"Invalid pattern in {file_path}:\n" + "\n".join(errors)
                return None, error_msg
            
            # Create Pattern object
            pattern = self._create_pattern(pattern_data)
            logger.info(f"Loaded pattern: {pattern.id} from {file_path}")
            return pattern, None
            
        except yaml.YAMLError as e:
            return None, f"YAML parsing error in {file_path}: {str(e)}"
        except Exception as e:
            return None, f"Failed to load pattern from {file_path}: {str(e)}"
    
    def validate_pattern(self, pattern_data: Dict[str, Any]) -> tuple[bool, List[str]]:
        """
        Validates a pattern definition dictionary.
        
        Checks:
        - All required fields are present
        - Field types are correct
        - Enum values are valid
        - Regex patterns compile successfully
        - Confidence is in valid range
        
        Args:
            pattern_data: Dictionary containing pattern definition.
            
        Returns:
            Tuple of (is_valid, list_of_errors).
            
        Examples:
            >>> loader = PatternLoader()
            >>> data = {'id': 'PS-001', 'name': 'Test', ...}
            >>> is_valid, errors = loader.validate_pattern(data)
            >>> if not is_valid:
            ...     for error in errors:
            ...         print(f"Error: {error}")
        """
        errors = []
        
        # Check required fields
        missing_fields = self.REQUIRED_FIELDS - set(pattern_data.keys())
        if missing_fields:
            errors.append(f"Missing required fields: {', '.join(missing_fields)}")
            return False, errors
        
        # Validate ID format (should be LANG-NNN)
        pattern_id = pattern_data.get('id', '')
        if not re.match(r'^[A-Z]+-\d+$', pattern_id):
            errors.append(f"Invalid ID format: '{pattern_id}'. Expected format: 'LANG-NNN' (e.g., 'PS-001')")
        
        # Validate severity
        severity = pattern_data.get('severity')
        if severity not in self.VALID_SEVERITIES:
            errors.append(f"Invalid severity: '{severity}'. Must be one of {self.VALID_SEVERITIES}")
        
        # Validate detection type
        detection_type = pattern_data.get('detection_type')
        if detection_type not in self.VALID_DETECTION_TYPES:
            errors.append(f"Invalid detection_type: '{detection_type}'. Must be one of {self.VALID_DETECTION_TYPES}")
        
        # Validate languages
        languages = pattern_data.get('languages', [])
        if not isinstance(languages, list):
            errors.append(f"'languages' must be a list, got {type(languages).__name__}")
        else:
            invalid_langs = set(languages) - self.VALID_LANGUAGES
            if invalid_langs:
                errors.append(f"Invalid languages: {invalid_langs}. Must be from {self.VALID_LANGUAGES}")
        
        # Validate confidence
        confidence = pattern_data.get('confidence')
        try:
            conf_float = float(confidence)
            if not 0.0 <= conf_float <= 1.0:
                errors.append(f"Confidence must be between 0.0 and 1.0, got {conf_float}")
        except (TypeError, ValueError):
            errors.append(f"Confidence must be a number, got {type(confidence).__name__}")
        
        # Validate detection logic based on type
        detection_logic = pattern_data.get('detection_logic', '')
        if detection_type == 'regex':
            # Try to compile regex
            try:
                re.compile(detection_logic)
            except re.error as e:
                errors.append(f"Invalid regex pattern: {str(e)}")
        elif detection_type == 'ast':
            # Basic AST query validation (just check it's not empty)
            if not detection_logic or not detection_logic.strip():
                errors.append("AST detection_logic cannot be empty")
        
        # Validate MITRE technique format (basic check)
        mitre = pattern_data.get('mitre_technique', '')
        if not re.match(r'^T\d{4}(\.\d{3})?$', mitre):
            errors.append(f"Invalid MITRE technique format: '{mitre}'. Expected format: 'T1234' or 'T1234.001'")
        
        return len(errors) == 0, errors
    
    def _create_pattern(self, pattern_data: Dict[str, Any]) -> Pattern:
        """
        Creates a Pattern object from validated data.
        
        Args:
            pattern_data: Validated pattern dictionary.
            
        Returns:
            Pattern object.
        """
        return Pattern(
            id=pattern_data['id'],
            name=pattern_data['name'],
            description=pattern_data['description'],
            languages=pattern_data['languages'],
            detection_type=pattern_data['detection_type'],
            detection_logic=pattern_data['detection_logic'],
            severity=pattern_data['severity'],
            mitre_technique=pattern_data['mitre_technique'],
            confidence=float(pattern_data['confidence']),
            category=pattern_data.get('category', 'general'),
            enabled=pattern_data.get('enabled', True),
            metadata=pattern_data.get('metadata', {})
        )
    
    def load_directory(
        self,
        dir_path: str | Path,
        recursive: bool = True
    ) -> tuple[List[Pattern], List[str]]:
        """
        Loads all pattern files from a directory.
        
        Args:
            dir_path: Path to directory containing pattern files.
            recursive: If True, search subdirectories recursively.
            
        Returns:
            Tuple of (list_of_patterns, list_of_errors).
            Errors are non-fatal - successfully loaded patterns are still returned.
            
        Examples:
            >>> loader = PatternLoader()
            >>> patterns, errors = loader.load_directory('patterns/')
            >>> print(f"Loaded {len(patterns)} patterns")
            >>> if errors:
            ...     print(f"Encountered {len(errors)} errors")
        """
        dir_path = Path(dir_path)
        
        if not dir_path.exists():
            return [], [f"Directory not found: {dir_path}"]
        
        if not dir_path.is_dir():
            return [], [f"Not a directory: {dir_path}"]
        
        patterns = []
        errors = []
        
        # Find all YAML files (excluding schema files)
        pattern_files = []
        if recursive:
            all_files = list(dir_path.rglob('*.yaml')) + list(dir_path.rglob('*.yml'))
        else:
            all_files = list(dir_path.glob('*.yaml')) + list(dir_path.glob('*.yml'))
        
        # Filter out schema files
        pattern_files = [f for f in all_files if 'schema' not in f.name.lower()]
        
        logger.info(f"Found {len(pattern_files)} pattern files in {dir_path}")
        
        # Load each file
        for file_path in pattern_files:
            pattern, error = self.load_pattern(file_path)
            if pattern:
                patterns.append(pattern)
            else:
                errors.append(error)
        
        logger.info(f"Loaded {len(patterns)} patterns from {dir_path}")
        if errors:
            logger.warning(f"Encountered {len(errors)} errors while loading patterns")
        
        return patterns, errors
    
    def get_last_validation_errors(self) -> List[str]:
        """
        Returns validation errors from the last validation attempt.
        
        Returns:
            List of validation error messages.
        """
        return self._validation_errors.copy()