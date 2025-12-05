# sentinel/reporters/json_reporter.py

"""
JSON report generator for Script Sentinel analysis results.

Provides JSON output in both pretty-print (human-readable) and compact
(machine-optimized) formats, compatible with XSOAR SOAR platform integration.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from sentinel.models import AnalysisResult

# Tool version for schema metadata
TOOL_VERSION = "0.1.0"
SCHEMA_VERSION = "2.0"  # Updated for IOC support

logger = logging.getLogger(__name__)


class JSONReporter:
    """
    Generates JSON reports from analysis results.
    
    Supports both pretty-print (human-readable) and compact (machine-optimized)
    output formats. Includes schema versioning and metadata for XSOAR integration.
    
    Examples:
        >>> from sentinel.models import AnalysisResult, Verdict
        >>> result = AnalysisResult(verdict=Verdict.SUSPICIOUS, confidence_score=0.75)
        >>> reporter = JSONReporter()
        >>> json_str = reporter.generate(result, pretty=True)
        >>> success, error = reporter.write_to_file(result, "output.json")
    """
    
    def __init__(self):
        """Initialize the JSON reporter."""
        self.schema_version = SCHEMA_VERSION
        self.tool_version = TOOL_VERSION
    
    def generate(self, result: AnalysisResult, pretty: bool = True) -> str:
        """
        Generate JSON string from analysis result.
        
        Converts the AnalysisResult to a JSON string with schema metadata,
        timestamp, and tool version information. Supports both pretty-print
        and compact output formats.
        
        Args:
            result: AnalysisResult object from analyzer.
            pretty: If True, use pretty-print format (indent=2, sorted keys).
                   If False, use compact format (minimal whitespace).
        
        Returns:
            JSON string representation of analysis result.
        
        Raises:
            TypeError: If result is not an AnalysisResult instance.
            ValueError: If result data cannot be serialized to JSON.
        
        Examples:
            >>> reporter = JSONReporter()
            >>> json_output = reporter.generate(result, pretty=True)
            >>> print(json_output)  # Pretty-printed JSON
        """
        if not isinstance(result, AnalysisResult):
            raise TypeError(f"Expected AnalysisResult, got {type(result).__name__}")
        
        try:
            # Build JSON structure with schema metadata
            output_data = self._build_output_structure(result)
            
            # Serialize to JSON with appropriate formatting
            if pretty:
                json_str = json.dumps(output_data, indent=2, sort_keys=True, ensure_ascii=False)
            else:
                json_str = json.dumps(output_data, separators=(',', ':'), ensure_ascii=False)
            
            logger.debug(f"Generated JSON report ({len(json_str)} bytes, pretty={pretty})")
            return json_str
            
        except (TypeError, ValueError) as e:
            logger.error(f"Failed to serialize analysis result to JSON: {e}")
            raise ValueError(f"JSON serialization failed: {e}") from e
    
    def write_to_file(
        self,
        result: AnalysisResult,
        file_path: str,
        pretty: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Write JSON report to file.
        
        Writes the analysis result to a JSON file with proper error handling,
        directory creation, and atomic file writing (write to temp, then rename).
        Supports both relative and absolute file paths with cross-platform
        compatibility via pathlib.
        
        Args:
            result: AnalysisResult object from analyzer.
            file_path: Output file path (relative or absolute).
            pretty: If True, use pretty-print format.
        
        Returns:
            Tuple of (success: bool, error_message: str | None).
            - (True, None) on success
            - (False, error_message) on failure
        
        Examples:
            >>> reporter = JSONReporter()
            >>> success, error = reporter.write_to_file(result, "./output.json")
            >>> if success:
            ...     print("Report written successfully")
            ... else:
            ...     print(f"Error: {error}")
        """
        try:
            # Convert to Path object for cross-platform compatibility
            output_path = Path(file_path)
            
            # Validate path is not a directory
            if output_path.exists() and output_path.is_dir():
                error_msg = f"Path is a directory, not a file: {file_path}"
                logger.error(error_msg)
                return False, error_msg
            
            # Create parent directories if they don't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured parent directory exists: {output_path.parent}")
            
            # Generate JSON content
            json_content = self.generate(result, pretty=pretty)
            
            # Atomic write: write to temp file, then rename
            temp_path = output_path.with_suffix(output_path.suffix + '.tmp')
            
            try:
                # Write to temporary file
                temp_path.write_text(json_content, encoding='utf-8')
                logger.debug(f"Wrote to temporary file: {temp_path}")
                
                # Atomic rename (overwrites existing file on most platforms)
                temp_path.replace(output_path)
                logger.info(f"Successfully wrote JSON report to: {output_path}")
                
                return True, None
                
            except Exception as e:
                # Clean up temp file if it exists
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except Exception:
                        pass  # Best effort cleanup
                raise
            
        except PermissionError as e:
            error_msg = f"Permission denied writing to {file_path}: {e}"
            logger.error(error_msg)
            return False, error_msg
            
        except OSError as e:
            error_msg = f"OS error writing to {file_path}: {e}"
            logger.error(error_msg)
            return False, error_msg
            
        except Exception as e:
            error_msg = f"Unexpected error writing to {file_path}: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def _build_output_structure(self, result: AnalysisResult) -> Dict[str, Any]:
        """
        Build the complete JSON output structure with metadata.
        
        Creates a dictionary containing the analysis result data plus
        schema metadata (version, timestamp, tool version) for XSOAR
        compatibility and future schema evolution.
        
        Args:
            result: AnalysisResult object to convert.
        
        Returns:
            Dictionary with complete JSON structure including metadata.
        """
        # Get base analysis data from AnalysisResult.to_dict()
        analysis_data = result.to_dict()
        
        # Add schema metadata
        output_data = {
            'schema_version': self.schema_version,
            'timestamp': datetime.utcnow().isoformat() + 'Z',  # ISO 8601 UTC format
            'tool_version': self.tool_version,
        }
        
        # Merge analysis data
        output_data.update(analysis_data)
        
        return output_data