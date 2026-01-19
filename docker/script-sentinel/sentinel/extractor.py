# sentinel/extractor.py

"""
Script extraction module for embedded scripts in HTML, XML, and SCT files.

This module detects and extracts scripts embedded in various container formats,
enabling analysis of scripts within HTML pages, XML configurations, and SCT files.
"""

import re
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExtractedScript:
    """
    Represents a script extracted from a container file.
    
    Attributes:
        content: The extracted script content.
        language: Detected language ('javascript', 'powershell', 'bash', 'jscript').
        line_start: Starting line number in the original file.
        line_end: Ending line number in the original file.
        source_type: Type of container ('html', 'xml', 'sct').
        context: Additional context about the extraction (e.g., tag name).
    """
    content: str
    language: str
    line_start: int
    line_end: int
    source_type: str
    context: str = ""


class ScriptExtractor:
    """
    Extracts embedded scripts from HTML, XML, and SCT files.
    
    Supports:
    - HTML: <script> tags with JavaScript
    - XML: <![CDATA[]]> sections with type hints
    - SCT: <script language="JScript"> with CDATA sections
    """
    
    def __init__(self):
        """Initialize the script extractor."""
        # Pattern for HTML script tags
        self.html_script_pattern = re.compile(
            r'<script[^>]*>(.*?)</script>',
            re.DOTALL | re.IGNORECASE
        )
        
        # Pattern for CDATA sections
        self.cdata_pattern = re.compile(
            r'<!\[CDATA\[(.*?)\]\]>',
            re.DOTALL
        )
        
        # Pattern for SCT script tags with language attribute
        self.sct_script_pattern = re.compile(
            r'<script\s+language=["\']?(\w+)["\']?[^>]*>(.*?)</script>',
            re.DOTALL | re.IGNORECASE
        )
        
        # Pattern for XML script tags with type attribute
        self.xml_script_pattern = re.compile(
            r'<script\s+type=["\']?(\w+)["\']?[^>]*>(.*?)</script>',
            re.DOTALL | re.IGNORECASE
        )
    
    def detect_file_type(self, content: str) -> Optional[str]:
        """
        Detect the file type based on content.
        
        Args:
            content: File content to analyze.
            
        Returns:
            File type ('html', 'xml', 'sct') or None if unknown.
        """
        content_lower = content.lower().strip()
        
        # Check for SCT (scriptlet) files
        if '<scriptlet' in content_lower or 'progid=' in content_lower:
            return 'sct'
        
        # Check for HTML
        if '<!doctype html' in content_lower or '<html' in content_lower:
            return 'html'
        
        # Check for XML
        if content_lower.startswith('<?xml'):
            return 'xml'
        
        return None
    
    def extract_from_html(self, content: str) -> List[ExtractedScript]:
        """
        Extract JavaScript from HTML <script> tags.
        
        Args:
            content: HTML file content.
            
        Returns:
            List of extracted scripts.
        """
        scripts = []
        lines = content.split('\n')
        
        for match in self.html_script_pattern.finditer(content):
            script_content = match.group(1).strip()
            
            if not script_content:
                continue
            
            # Find line numbers
            start_pos = match.start()
            end_pos = match.end()
            line_start = content[:start_pos].count('\n') + 1
            line_end = content[:end_pos].count('\n') + 1
            
            scripts.append(ExtractedScript(
                content=script_content,
                language='javascript',
                line_start=line_start,
                line_end=line_end,
                source_type='html',
                context='<script> tag'
            ))
            
            logger.debug(f"Extracted JavaScript from HTML (lines {line_start}-{line_end})")
        
        return scripts
    
    def extract_from_sct(self, content: str) -> List[ExtractedScript]:
        """
        Extract scripts from SCT (Windows Script Component) files.
        
        Args:
            content: SCT file content.
            
        Returns:
            List of extracted scripts.
        """
        scripts = []
        
        # Look for <script language="..."> tags
        for match in self.sct_script_pattern.finditer(content):
            language_attr = match.group(1).lower()
            script_block = match.group(2)
            
            # Extract CDATA content if present
            cdata_match = self.cdata_pattern.search(script_block)
            if cdata_match:
                script_content = cdata_match.group(1).strip()
            else:
                script_content = script_block.strip()
            
            if not script_content:
                continue
            
            # Map language attribute to our language names
            language_map = {
                'jscript': 'javascript',
                'javascript': 'javascript',
                'vbscript': 'vbscript',  # Not supported yet, but detected
            }
            language = language_map.get(language_attr, 'javascript')
            
            # Find line numbers
            start_pos = match.start()
            end_pos = match.end()
            line_start = content[:start_pos].count('\n') + 1
            line_end = content[:end_pos].count('\n') + 1
            
            scripts.append(ExtractedScript(
                content=script_content,
                language=language,
                line_start=line_start,
                line_end=line_end,
                source_type='sct',
                context=f'<script language="{language_attr}">'
            ))
            
            logger.debug(f"Extracted {language} from SCT (lines {line_start}-{line_end})")
        
        return scripts
    
    def extract_from_xml(self, content: str) -> List[ExtractedScript]:
        """
        Extract scripts from XML configuration files.
        
        Args:
            content: XML file content.
            
        Returns:
            List of extracted scripts.
        """
        scripts = []
        
        # Look for <script type="..."> tags
        for match in self.xml_script_pattern.finditer(content):
            type_attr = match.group(1).lower()
            script_block = match.group(2)
            
            # Extract CDATA content if present
            cdata_match = self.cdata_pattern.search(script_block)
            if cdata_match:
                script_content = cdata_match.group(1).strip()
            else:
                script_content = script_block.strip()
            
            if not script_content:
                continue
            
            # Map type attribute to our language names
            language_map = {
                'powershell': 'powershell',
                'bash': 'bash',
                'shell': 'bash',
                'javascript': 'javascript',
                'js': 'javascript',
            }
            language = language_map.get(type_attr, 'bash')  # Default to bash for shell scripts
            
            # Find line numbers
            start_pos = match.start()
            end_pos = match.end()
            line_start = content[:start_pos].count('\n') + 1
            line_end = content[:end_pos].count('\n') + 1
            
            scripts.append(ExtractedScript(
                content=script_content,
                language=language,
                line_start=line_start,
                line_end=line_end,
                source_type='xml',
                context=f'<script type="{type_attr}">'
            ))
            
            logger.debug(f"Extracted {language} from XML (lines {line_start}-{line_end})")
        
        return scripts
    
    def extract(self, content: str, file_type: Optional[str] = None) -> List[ExtractedScript]:
        """
        Extract all scripts from the given content.
        
        Args:
            content: File content to extract scripts from.
            file_type: Optional file type hint ('html', 'xml', 'sct').
                      If not provided, will be auto-detected.
            
        Returns:
            List of extracted scripts.
        """
        # Auto-detect file type if not provided
        if file_type is None:
            file_type = self.detect_file_type(content)
            if file_type:
                logger.info(f"Auto-detected file type: {file_type}")
        
        if not file_type:
            logger.warning("Could not detect file type - no scripts extracted")
            return []
        
        # Extract based on file type
        if file_type == 'html':
            return self.extract_from_html(content)
        elif file_type == 'sct':
            return self.extract_from_sct(content)
        elif file_type == 'xml':
            return self.extract_from_xml(content)
        else:
            logger.warning(f"Unsupported file type: {file_type}")
            return []


def extract_scripts(content: str, file_type: Optional[str] = None) -> List[ExtractedScript]:
    """
    Convenience function to extract scripts from content.
    
    Args:
        content: File content to extract scripts from.
        file_type: Optional file type hint ('html', 'xml', 'sct').
        
    Returns:
        List of extracted scripts.
        
    Examples:
        >>> scripts = extract_scripts(html_content, 'html')
        >>> for script in scripts:
        ...     print(f"Found {script.language} script at lines {script.line_start}-{script.line_end}")
    """
    extractor = ScriptExtractor()
    return extractor.extract(content, file_type)


def detect_language_from_content(content: str) -> Optional[str]:
    """
    Detect script language from content using heuristics.
    
    Args:
        content: Script content to analyze
        
    Returns:
        Detected language ('powershell', 'bash', 'javascript') or None
    """
    # PowerShell indicators (strongest first)
    powershell_indicators = [
        r'\$\w+\s*=',  # Variable assignment with $
        r'(?i)\b(Get-|Set-|New-|Remove-|Invoke-|Write-|Start-|Stop-)\w+',  # Cmdlets
        r'(?i)\[System\.',  # .NET types
        r'(?i)\bparam\s*\(',  # Param blocks
        r'(?i)\$PSVersionTable',  # PowerShell variable
    ]
    
    # Bash indicators
    bash_indicators = [
        r'^#!/bin/(ba)?sh',  # Shebang
        r'\b(echo|grep|sed|awk|cat|ls|cd|pwd)\b',  # Common commands
        r'\$\{[^}]+\}',  # Variable expansion ${var}
        r'\[\[.*\]\]',  # Bash test
    ]
    
    # JavaScript indicators
    javascript_indicators = [
        r'\b(function|const|let|var)\s+\w+',  # Function/variable declarations
        r'\b(document|window|console)\.',  # Browser objects
        r'=>',  # Arrow functions
        r'\b(async|await)\b',  # Async keywords
    ]
    
    # Count matches for each language
    ps_score = sum(1 for pattern in powershell_indicators if re.search(pattern, content, re.MULTILINE))
    bash_score = sum(1 for pattern in bash_indicators if re.search(pattern, content, re.MULTILINE))
    js_score = sum(1 for pattern in javascript_indicators if re.search(pattern, content, re.MULTILINE))
    
    # Return language with highest score (minimum 2 matches required)
    scores = {'powershell': ps_score, 'bash': bash_score, 'javascript': js_score}
    max_lang = max(scores, key=scores.get)
    
    if scores[max_lang] >= 2:
        logger.info(f"Content-based detection: {max_lang} (score: {scores[max_lang]})")
        return max_lang
    
    return None


def get_script_from_file(file_path: str) -> Tuple[str, str, Optional[str]]:
    """
    Read a script file and detect its language.
    
    Supports both extension-based and content-based language detection.
    If the extension is unknown or ambiguous (e.g., .bat, .cmd, .txt),
    the content will be analyzed to detect the actual scripting language.
    
    Args:
        file_path: Path to the script file
        
    Returns:
        Tuple of (content, language, error)
        - content: The script content (or empty string on error)
        - language: Detected language ('bash', 'powershell', 'javascript', etc.)
        - error: Error message if any, None on success
    """
    from pathlib import Path
    
    try:
        path = Path(file_path)
        
        if not path.exists():
            return "", "", f"File not found: {file_path}"
        
        if not path.is_file():
            return "", "", f"Not a file: {file_path}"
        
        # Read file content
        try:
            content = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            # Try with latin-1 encoding as fallback
            content = path.read_text(encoding='latin-1')
        
        # Detect language from file extension
        ext = path.suffix.lower()
        
        # Direct language mapping (high confidence)
        language_map = {
            '.sh': 'bash',
            '.bash': 'bash',
            '.ps1': 'powershell',
            '.psm1': 'powershell',
            '.psd1': 'powershell',
            '.js': 'javascript',
        }
        
        if ext in language_map:
            return content, language_map[ext], None
        
        # Container formats that need script extraction
        container_map = {
            '.html': 'html',
            '.htm': 'html',
            '.xml': 'xml',
            '.sct': 'sct',
        }
        
        if ext in container_map:
            # Use extension hint but allow auto-detection to override
            # This handles cases like .xml files that are actually SCT format
            extractor = ScriptExtractor()
            scripts = extractor.extract(content, file_type=None)  # Let auto-detection work
            
            if not scripts:
                return "", "", f"No scripts found in {ext} file"
            
            # Use the first script found
            script = scripts[0]
            return script.content, script.language, None
        
        # Unknown or ambiguous extension - try content-based detection
        # This handles cases like .bat, .cmd, .txt, or no extension
        logger.info(f"Unknown extension '{ext}' - attempting content-based language detection")
        detected_language = detect_language_from_content(content)
        
        if detected_language:
            logger.info(f"Detected language from content: {detected_language}")
            return content, detected_language, None
        
        # Could not detect language
        return "", "", f"Unsupported file type '{ext}' and could not detect language from content"
        
    except Exception as e:
        return "", "", f"Error reading file: {str(e)}"
