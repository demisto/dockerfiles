# sentinel/yara_engine.py

"""
Yara rule loading and compilation engine for Script Sentinel.

Provides functionality to load, compile, and manage Yara rules from the
rules directory structure. Supports both graceful degradation (default mode)
and strict mode for CI environments.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
import time

import yara

logger = logging.getLogger(__name__)


class YaraRuleError(Exception):
    """Raised when a Yara rule fails to compile in strict mode."""

    def __init__(self, file_path: str, error: str):
        self.file_path = file_path
        self.error = error
        super().__init__(f"Invalid Yara rule {file_path}: {error}")


@dataclass
class LoadStats:
    """Statistics from Yara rule loading."""

    total_files: int = 0
    loaded: int = 0
    skipped: int = 0
    public_count: int = 0
    custom_count: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    load_time_seconds: float = 0.0


@dataclass
class YaraMatch:
    """Represents a single Yara rule match result."""

    rule_name: str
    rule_namespace: str  # "public/rulename" or "custom/rulename"
    matched_strings: List[Tuple[int, str, bytes]]  # (offset, identifier, data)
    metadata: Dict[str, str]  # severity, confidence, mitre_technique, description


class YaraEngine:
    """Yara rule loading and compilation engine."""

    def __init__(self, rules_dir: Path, strict_mode: bool = False):
        """
        Initialize the YaraEngine.

        Args:
            rules_dir: Path to the rules directory containing public/, custom/, staging/.
            strict_mode: If True, raise YaraRuleError on first invalid rule.
                         If False, skip invalid rules with warning log.
        """
        self.rules_dir = Path(rules_dir)
        self.strict_mode = strict_mode
        self._compiled_rules: Optional[yara.Rules] = None
        self._load_stats: Optional[LoadStats] = None

    def load_rules(self) -> Tuple[Optional[yara.Rules], LoadStats]:
        """
        Load and compile all Yara rules from rules directory.

        Recursively discovers .yar files in public/ and custom/ directories,
        excludes staging/ directory, and compiles rules using namespaced
        compilation.

        Returns:
            Tuple of (compiled_rules, LoadStats). compiled_rules may be None
            if no valid rules were found.

        Raises:
            YaraRuleError: In strict mode, if any rule fails to compile.
        """
        start_time = time.perf_counter()
        stats = LoadStats()

        # Collect all rule files
        filepaths: Dict[str, str] = {}
        public_dir = self.rules_dir / "public"
        custom_dir = self.rules_dir / "custom"

        # Discover public rules
        if public_dir.exists():
            public_rules = list(public_dir.rglob("*.yar"))
            for rule_file in public_rules:
                namespace = f"public/{rule_file.stem}"
                filepaths[namespace] = str(rule_file)
                stats.public_count += 1
                stats.total_files += 1

        # Discover custom rules
        if custom_dir.exists():
            custom_rules = list(custom_dir.rglob("*.yar"))
            for rule_file in custom_rules:
                # Create namespace with subdirectory for organization
                relative_path = rule_file.relative_to(custom_dir)
                if len(relative_path.parts) > 1:
                    # Has subdirectory (e.g., powershell/rule.yar)
                    namespace = f"custom/{relative_path.parent}/{rule_file.stem}"
                else:
                    namespace = f"custom/{rule_file.stem}"
                filepaths[namespace] = str(rule_file)
                stats.custom_count += 1
                stats.total_files += 1

        # Handle empty case
        if not filepaths:
            stats.load_time_seconds = time.perf_counter() - start_time
            self._load_stats = stats
            self._compiled_rules = None
            logger.info("No Yara rules found in rules directory")
            return (None, stats)

        # Compile rules
        compiled_rules: Optional[yara.Rules] = None

        if self.strict_mode:
            # Strict mode: fail on first error
            try:
                compiled_rules = yara.compile(filepaths=filepaths)
                stats.loaded = stats.total_files
            except yara.SyntaxError as e:
                # Find which file caused the error
                error_msg = str(e)
                # Try to extract file path from error message
                for namespace, filepath in filepaths.items():
                    if filepath in error_msg or namespace in error_msg:
                        raise YaraRuleError(filepath, error_msg)
                # If we can't identify the file, use generic error
                raise YaraRuleError("unknown", error_msg)
        else:
            # Default mode: graceful degradation - compile one at a time
            valid_filepaths: Dict[str, str] = {}
            for namespace, filepath in filepaths.items():
                try:
                    # Test compile individual rule
                    yara.compile(filepath=filepath)
                    valid_filepaths[namespace] = filepath
                    stats.loaded += 1
                except yara.SyntaxError as e:
                    error_msg = f"Skipping invalid rule {filepath}: {e}"
                    logger.warning(error_msg)
                    stats.errors.append(error_msg)
                    stats.skipped += 1

            # Compile all valid rules together
            if valid_filepaths:
                try:
                    compiled_rules = yara.compile(filepaths=valid_filepaths)
                except yara.SyntaxError as e:
                    # Should not happen if individual compiles succeeded
                    error_msg = f"Unexpected compilation error: {e}"
                    logger.error(error_msg)
                    stats.errors.append(error_msg)
                    compiled_rules = None

        # Calculate timing
        stats.load_time_seconds = time.perf_counter() - start_time

        # Warn if loading exceeded 2 seconds (NFR3)
        if stats.load_time_seconds > 2.0:
            warning_msg = (
                f"Yara rule loading exceeded 2 second threshold: "
                f"{stats.load_time_seconds:.2f}s"
            )
            logger.warning(warning_msg)
            stats.warnings.append(warning_msg)

        self._compiled_rules = compiled_rules
        self._load_stats = stats

        logger.info(
            f"Loaded {stats.loaded}/{stats.total_files} Yara rules "
            f"(public: {stats.public_count}, custom: {stats.custom_count}, "
            f"skipped: {stats.skipped}) in {stats.load_time_seconds:.3f}s"
        )

        return (compiled_rules, stats)

    @property
    def compiled_rules(self) -> Optional[yara.Rules]:
        """Get compiled rules (load if not already loaded)."""
        if self._compiled_rules is None and self._load_stats is None:
            self.load_rules()
        return self._compiled_rules

    @property
    def load_stats(self) -> Optional[LoadStats]:
        """Get load statistics from last load operation."""
        return self._load_stats

    def match(self, content: str) -> List[YaraMatch]:
        """
        Match compiled Yara rules against script content.

        Args:
            content: Script content to match against.

        Returns:
            List of YaraMatch objects for matching rules.
            Empty list if no rules compiled or no matches found.
        """
        # Use property to trigger lazy load if needed
        if self.compiled_rules is None:
            return []

        matches = []
        try:
            yara_matches = self.compiled_rules.match(data=content)
            for m in yara_matches:
                matched_strings = []
                # yara-python 4.3+ API: use string_match.instances
                for string_match in m.strings:
                    for instance in string_match.instances:
                        matched_strings.append((
                            instance.offset,
                            string_match.identifier,
                            instance.matched_data
                        ))

                metadata = {
                    'severity': m.meta.get('severity', 'Medium'),
                    'confidence': str(m.meta.get('confidence', '0.9')),
                    'mitre_technique': m.meta.get('mitre_technique', ''),
                    'description': m.meta.get('description', m.rule)
                }

                matches.append(YaraMatch(
                    rule_name=m.rule,
                    rule_namespace=m.namespace,
                    matched_strings=matched_strings,
                    metadata=metadata
                ))
        except yara.Error as e:
            logger.error(f"Yara matching error: {e}")

        return matches


def _namespace_to_category(namespace: str) -> str:
    """
    Map Yara rule namespace to Finding category.

    Args:
        namespace: The Yara rule namespace (e.g., 'public/powershell/rule').

    Returns:
        Category string for the Finding.
    """
    namespace_lower = namespace.lower()
    if "powershell" in namespace_lower:
        return "execution"
    elif "bash" in namespace_lower:
        return "execution"
    elif "javascript" in namespace_lower:
        return "execution"
    elif "malware" in namespace_lower:
        return "malware"
    elif "webshell" in namespace_lower:
        return "webshell"
    return "signature"


def _safe_decode_snippet(data: bytes, max_len: int = 100) -> str:
    """
    Safely decode binary match data to string snippet.

    Args:
        data: Binary data from Yara match.
        max_len: Maximum length of returned string.

    Returns:
        Decoded string or repr() fallback.
    """
    try:
        return data.decode('utf-8', errors='replace')[:max_len]
    except Exception:
        return repr(data)[:max_len]


def yara_match_to_finding(match: YaraMatch) -> 'Finding':
    """
    Convert a YaraMatch to a Finding object.

    Args:
        match: YaraMatch object from YaraEngine.match().

    Returns:
        Finding object with Yara match data.
    """
    # Import here to avoid circular imports
    from .models import Finding

    # Format pattern_id: YARA-{namespace}-{rule_name}
    # Replace slashes with dashes for cleaner ID
    # Avoid duplication when namespace already contains rule name (custom rules)
    namespace_clean = match.rule_namespace.replace('/', '-')
    if namespace_clean.endswith(match.rule_name):
        # Namespace already includes rule name (e.g., custom-powershell-rule_052_...)
        pattern_id = f"YARA-{namespace_clean}"
    else:
        pattern_id = f"YARA-{namespace_clean}-{match.rule_name}"

    # Truncate description to prevent unwieldy findings from malicious rules
    description = match.metadata.get('description', match.rule_name)
    if len(description) > 500:
        description = description[:497] + "..."

    # Validate and default severity
    severity = match.metadata.get('severity', 'Medium')
    valid_severities = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
    if severity not in valid_severities:
        severity = 'Medium'

    # Parse and clamp confidence
    try:
        confidence = float(match.metadata.get('confidence', '0.9'))
        confidence = max(0.0, min(1.0, confidence))
    except (ValueError, TypeError):
        confidence = 0.9

    mitre_technique = match.metadata.get('mitre_technique', '')
    category = _namespace_to_category(match.rule_namespace)

    # Extract code snippet from first match
    code_snippet = None
    if match.matched_strings:
        _, _, data = match.matched_strings[0]
        code_snippet = _safe_decode_snippet(data, max_len=100)

    return Finding(
        description=f"[YARA] {description}",
        severity=severity,
        confidence=confidence,
        pattern_id=pattern_id,
        mitre_technique=mitre_technique,
        category=category,
        line_number=None,
        code_snippet=code_snippet,
        source="yara",
        metadata={
            'rule_name': match.rule_name,
            'namespace': match.rule_namespace,
            'match_count': len(match.matched_strings)
        }
    )
