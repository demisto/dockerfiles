"""Content Intelligence Scorer for verdict calculation.

This module implements the ContentIntelligenceScorer which analyzes script content
for suspicious characteristics including Shannon entropy, encoding layers,
cyclomatic complexity, and suspicious string patterns.
"""

import base64
import math
import re
from collections import Counter
from typing import List, Tuple, Dict, Any, Optional
from sentinel.scorers.base import BaseScorer


class ContentIntelligenceScorer(BaseScorer):
    """
    Scores based on script content analysis.

    This scorer analyzes the actual script content for suspicious
    characteristics beyond pattern matching, including:
    - Shannon entropy (obfuscation detection)
    - Encoding layers (multiple encoding levels) - Future
    - Cyclomatic complexity (code complexity) - Future
    - Suspicious string patterns - Future

    The scorer uses mathematical content analysis to detect obfuscation
    without relying on ML infrastructure.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        entropy_thresholds: Thresholds for entropy scoring
        max_entropy_score: Maximum score contribution from entropy (30 points)

    Examples:
        >>> config = {
        ...     'content_intelligence': {
        ...         'entropy': {
        ...             'thresholds': {'high': 7.5, 'medium': 6.5},
        ...             'scoring': {'max_score': 30}
        ...         }
        ...     }
        ... }
        >>> scorer = ContentIntelligenceScorer(config)
        >>> score, explanations = scorer.score(script_content="test")
        >>> 0 <= score <= 30
        True
    """

    # Default configuration values
    DEFAULT_ENTROPY_THRESHOLDS = {
        "high": 7.5,  # High entropy (>7.5) indicates strong obfuscation
        "medium": 6.5,  # Medium entropy (6.5-7.5) indicates moderate obfuscation
    }
    DEFAULT_MAX_ENTROPY_SCORE = 30  # Maximum score contribution from entropy

    # Default encoding detection configuration
    DEFAULT_MIN_BASE64_LENGTH = 20  # Minimum base64 sequence length to detect
    DEFAULT_MAX_RECURSION_DEPTH = 5  # Maximum nested encoding layers to check
    DEFAULT_ENCODING_SCORES = {
        "single_layer": 10,
        "double_layer": 25,
        "triple_plus_layer": 40,
    }
    DEFAULT_MAX_ENCODING_SCORE = 40  # Maximum score contribution from encoding

    # Default complexity detection configuration
    DEFAULT_COMPLEXITY_THRESHOLDS = {
        "low": 30,  # Simple scripts (<30 decision points)
        "medium": 50,  # Moderately complex (30-50 decision points)
        "high": 100,  # Highly complex (50-100 decision points)
    }
    DEFAULT_MAX_COMPLEXITY_SCORE = 30  # Maximum score contribution from complexity

    # Default suspicious string patterns configuration
    DEFAULT_SUSPICIOUS_PATTERNS = {
        "critical": [
            "invoke-expression",
            "iex",
            "eval",
            "exec",
            "cmd.exe",
            "powershell.exe",
        ],
        "high": [
            "downloadstring",
            "webclient",
            "encodedcommand",
            "frombase64",
            "hidden",
            "bypass",
        ],
        "medium": ["schtasks", "reg add", "wmi"],
    }
    DEFAULT_SUSPICIOUS_STRING_THRESHOLDS = {
        "low": 2,  # 1-2 patterns
        "medium": 5,  # 3-5 patterns
        "high": 10,  # 6-10 patterns
    }
    DEFAULT_MAX_SUSPICIOUS_STRING_SCORE = 25  # Maximum score contribution

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the content intelligence scorer.

        Args:
            config: Configuration dictionary containing content_intelligence section
                   with entropy thresholds and scoring settings
        """
        super().__init__(config)

        # Extract content intelligence configuration
        content_config = config.get("content_intelligence", {})
        entropy_config = content_config.get("entropy", {})
        encoding_config = content_config.get("encoding", {})
        complexity_config = content_config.get("complexity", {})

        # Load entropy thresholds with defaults
        config_thresholds = entropy_config.get("thresholds", {})
        self.entropy_thresholds = {**self.DEFAULT_ENTROPY_THRESHOLDS, **config_thresholds}

        # Load max entropy score setting (default: 30)
        entropy_scoring = entropy_config.get("scoring", {})
        self.max_entropy_score = entropy_scoring.get("max_score", self.DEFAULT_MAX_ENTROPY_SCORE)

        # Load encoding detection configuration
        detection_config = encoding_config.get("detection", {})
        self.min_base64_length = detection_config.get(
            "min_base64_length", self.DEFAULT_MIN_BASE64_LENGTH
        )
        self.max_recursion_depth = detection_config.get(
            "max_recursion_depth", self.DEFAULT_MAX_RECURSION_DEPTH
        )

        # Load encoding scoring configuration
        encoding_scoring = encoding_config.get("scoring", {})
        self.encoding_scores = {**self.DEFAULT_ENCODING_SCORES, **encoding_scoring}
        self.max_encoding_score = encoding_scoring.get("max_score", self.DEFAULT_MAX_ENCODING_SCORE)

        # Check if encoding detection is enabled
        self.encoding_enabled = encoding_config.get("enabled", False)

        # Load complexity thresholds with defaults
        complexity_thresholds = complexity_config.get("thresholds", {})
        self.complexity_thresholds = {
            **self.DEFAULT_COMPLEXITY_THRESHOLDS,
            **complexity_thresholds,
        }

        # Load complexity scoring configuration
        complexity_scoring = complexity_config.get("scoring", {})
        self.max_complexity_score = complexity_scoring.get(
            "max_score", self.DEFAULT_MAX_COMPLEXITY_SCORE
        )

        # Check if complexity analysis is enabled
        self.complexity_enabled = complexity_config.get("enabled", False)

        # Load suspicious string patterns configuration
        string_patterns_config = content_config.get("string_patterns", {})

        # Load patterns with defaults
        patterns_dict = string_patterns_config.get("patterns", {})
        self.suspicious_patterns = {
            "critical": patterns_dict.get("critical", self.DEFAULT_SUSPICIOUS_PATTERNS["critical"]),
            "high": patterns_dict.get("high", self.DEFAULT_SUSPICIOUS_PATTERNS["high"]),
            "medium": patterns_dict.get("medium", self.DEFAULT_SUSPICIOUS_PATTERNS["medium"]),
        }

        # Compile regex patterns for performance (case-insensitive)
        self.compiled_patterns = []
        for severity, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                # Escape special regex characters and compile
                escaped_pattern = re.escape(pattern)
                compiled = re.compile(escaped_pattern, re.IGNORECASE)
                self.compiled_patterns.append((compiled, pattern, severity))

        # Load suspicious string scoring configuration
        string_scoring = string_patterns_config.get("scoring", {})
        self.suspicious_string_thresholds = {
            **self.DEFAULT_SUSPICIOUS_STRING_THRESHOLDS,
            **string_scoring.get("thresholds", {}),
        }
        self.max_suspicious_string_score = string_scoring.get(
            "max_score", self.DEFAULT_MAX_SUSPICIOUS_STRING_SCORE
        )

        # Check if suspicious string detection is enabled
        self.suspicious_strings_enabled = string_patterns_config.get("enabled", False)

    def score(
        self, script_content: Optional[str] = None, ast: Optional[Dict] = None, **kwargs
    ) -> Tuple[float, List[str]]:
        """
        Calculate content intelligence score from script content and AST.

        Implements:
        - Shannon entropy analysis (Story 2.1)
        - Encoding layer detection (Story 2.2)
        - Cyclomatic complexity analysis (Story 2.3)
        - Suspicious string pattern detection (Story 2.4)

        Args:
            script_content: Raw script text to analyze
            ast: Abstract Syntax Tree (dict or list structure) for complexity analysis
            **kwargs: Additional parameters (reserved for future use)

        Returns:
            Tuple of (score: 0-100, explanations: list of strings)
            Score range: 0-30 (entropy) + 0-40 (encoding) + 0-30 (complexity) + 0-25 (suspicious strings) = 0-125 total

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> score, explanations = scorer.score(script_content="")
            >>> score
            0.0
            >>> score, explanations = scorer.score(script_content="normal code")
            >>> 0 <= score <= 100
            True
        """
        # Handle missing or empty script content
        if not script_content:
            return 0.0, ["No script content to analyze"]

        total_score = 0.0
        explanations = []
        entropy_score = 0.0
        encoding_score = 0.0
        complexity_score = 0.0
        suspicious_strings_score = 0.0

        # Calculate Shannon entropy
        entropy_value = self._calculate_entropy(script_content)
        entropy_score = self._score_entropy(entropy_value)
        total_score += entropy_score

        # Generate entropy explanations
        entropy_explanations = self._generate_entropy_explanation(entropy_value, entropy_score)
        explanations.extend(entropy_explanations)

        # Calculate encoding layers (if enabled)
        if self.encoding_enabled:
            encoding_layers = self._detect_encoding_layers(script_content)
            encoding_score = self._score_encoding(encoding_layers)
            total_score += encoding_score

            # Generate encoding explanations
            encoding_explanations = self._generate_encoding_explanation(
                encoding_layers, encoding_score
            )
            explanations.extend(encoding_explanations)

        # Calculate cyclomatic complexity (if enabled and AST provided)
        if self.complexity_enabled and ast is not None:
            complexity_value = self._calculate_complexity(ast)
            complexity_score, complexity_explanations = self._score_complexity(complexity_value)
            total_score += complexity_score
            explanations.extend(complexity_explanations)

        # Detect suspicious string patterns (if enabled)
        if self.suspicious_strings_enabled:
            matched_patterns = self._detect_suspicious_strings(script_content)
            suspicious_strings_score = self._score_suspicious_strings(len(matched_patterns))
            total_score += suspicious_strings_score

            # Generate suspicious string explanations
            suspicious_explanations = self._generate_suspicious_strings_explanation(
                matched_patterns, suspicious_strings_score
            )
            explanations.extend(suspicious_explanations)

        # Update overall score summary
        # Build comprehensive score summary
        components = [f"entropy: {entropy_score:.1f}/{self.max_entropy_score}"]
        if self.encoding_enabled:
            components.append(f"encoding: {encoding_score:.1f}/{self.max_encoding_score}")
        if self.complexity_enabled:
            components.append(f"complexity: {complexity_score:.1f}/{self.max_complexity_score}")
        if self.suspicious_strings_enabled:
            components.append(
                f"suspicious strings: {suspicious_strings_score:.1f}/{self.max_suspicious_string_score}"
            )

        explanations[0] = f"Content intelligence score: {total_score:.1f} ({', '.join(components)})"

        return total_score, explanations

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text.

        Shannon entropy measures the randomness/information density of text.
        Higher entropy suggests more random/obfuscated content.

        This implementation reuses the core algorithm from obfuscation.py
        but is wrapped for use in the content intelligence scorer.

        Args:
            text: String to analyze

        Returns:
            Entropy value (0.0 to 8.0, higher = more random/obfuscated)

        Formula:
            H(X) = -Σ p(x) * log2(p(x))
            where p(x) is probability of character x

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> scorer._calculate_entropy("")
            0.0
            >>> scorer._calculate_entropy("aaaa")
            0.0
            >>> abs(scorer._calculate_entropy("ab") - 1.0) < 0.01
            True
            >>> scorer._calculate_entropy("abcdefgh") > 2.5
            True
        """
        if not text:
            return 0.0

        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)

        # Calculate entropy using Shannon's formula
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _score_entropy(self, entropy: float) -> float:
        """
        Convert entropy value to score (0-30 points).

        Scoring logic:
        - High obfuscation (>7.5): 30 points (maximum)
        - Medium obfuscation (6.5-7.5): 15-25 points (linear interpolation)
        - Low obfuscation (<6.5): 0-10 points (linear interpolation)

        Args:
            entropy: Entropy value (0.0 to 8.0)

        Returns:
            Score value (0.0 to max_entropy_score, typically 30)

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> scorer._score_entropy(8.0)  # Maximum entropy
            30.0
            >>> scorer._score_entropy(7.5)  # High threshold
            30.0
            >>> 15.0 <= scorer._score_entropy(7.0) <= 25.0  # Medium range
            True
            >>> scorer._score_entropy(6.0) <= 10.0  # Low entropy
            True
            >>> scorer._score_entropy(0.0)
            0.0
        """
        high_threshold = self.entropy_thresholds["high"]
        medium_threshold = self.entropy_thresholds["medium"]

        # High obfuscation: entropy > 7.5 → 30 points
        if entropy >= high_threshold:
            return float(self.max_entropy_score)

        # Medium obfuscation: 6.5 <= entropy < 7.5 → 15-25 points (linear)
        elif entropy >= medium_threshold:
            # Linear interpolation between 15 and 25 points
            range_size = high_threshold - medium_threshold
            position = (entropy - medium_threshold) / range_size
            min_score = self.max_entropy_score * 0.5  # 15 points
            max_score = self.max_entropy_score * 0.833  # 25 points
            score = min_score + (position * (max_score - min_score))
            return score

        # Low obfuscation: entropy < 6.5 → 0-10 points (linear)
        else:
            # Linear interpolation between 0 and 10 points
            # Cap at medium threshold to avoid scores above 10
            capped_entropy = min(entropy, medium_threshold)
            position = capped_entropy / medium_threshold
            max_score = self.max_entropy_score * 0.333  # 10 points
            score = position * max_score
            return score

    def _generate_entropy_explanation(self, entropy: float, score: float) -> List[str]:
        """
        Generate human-readable explanation of entropy score.

        Args:
            entropy: Calculated entropy value
            score: Calculated score

        Returns:
            List of explanation strings

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> explanations = scorer._generate_entropy_explanation(7.8, 30.0)
            >>> len(explanations) > 0
            True
            >>> any('entropy' in e.lower() for e in explanations)
            True
        """
        explanations = []

        # Overall score summary (will be updated in score() if encoding is enabled)
        explanations.append(
            f"Content intelligence score: {score:.1f}/{self.max_entropy_score} "
            f"(entropy: {entropy:.2f})"
        )

        # Entropy interpretation
        high_threshold = self.entropy_thresholds["high"]
        medium_threshold = self.entropy_thresholds["medium"]

        if entropy >= high_threshold:
            explanations.append(
                f"High entropy detected ({entropy:.2f} >= {high_threshold}) - "
                "strong obfuscation indicators"
            )
        elif entropy >= medium_threshold:
            explanations.append(
                f"Medium entropy detected ({entropy:.2f} in range "
                f"{medium_threshold}-{high_threshold}) - "
                "moderate obfuscation indicators"
            )
        else:
            explanations.append(
                f"Low entropy ({entropy:.2f} < {medium_threshold}) - "
                "readable code characteristics"
            )

        return explanations

    def _detect_base64(self, text: str) -> List[str]:
        """
        Detect base64 encoded sequences in text.

        Looks for sequences of 20+ characters matching base64 character set.
        Filters out false positives like comments and quoted strings.

        Args:
            text: String to analyze

        Returns:
            List of detected base64 sequences

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> sequences = scorer._detect_base64("SGVsbG8gV29ybGQhSGVsbG8gV29ybGQh")
            >>> len(sequences) > 0
            True
            >>> scorer._detect_base64("short")
            []
        """
        if not text:
            return []

        # Pattern: 20+ base64 characters with optional padding
        pattern = r"[A-Za-z0-9+/]{" + str(self.min_base64_length) + r",}={0,2}"
        matches = re.findall(pattern, text)

        # Filter out false positives
        valid_sequences = []
        for match in matches:
            # Skip if it's in a comment (simple heuristic)
            if self._is_in_comment(text, match):
                continue

            # Add to valid sequences (basic pattern match is sufficient)
            # We don't strictly validate base64 here to avoid false negatives
            valid_sequences.append(match)

        return valid_sequences

    def _detect_hex_encoding(self, text: str) -> List[str]:
        """
        Detect hex encoded sequences in text.

        Detects both 0x prefix (e.g., 0x48656c6c6f) and \\x prefix
        (e.g., \\x48\\x65\\x6c\\x6c\\x6f) patterns.

        Args:
            text: String to analyze

        Returns:
            List of detected hex sequences

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> sequences = scorer._detect_hex_encoding("0x48656c6c6f")
            >>> len(sequences) > 0
            True
            >>> sequences = scorer._detect_hex_encoding("\\x48\\x65\\x6c")
            >>> len(sequences) > 0
            True
        """
        if not text:
            return []

        sequences = []

        # Pattern 1: 0x prefix (e.g., 0x48656c6c6f)
        hex_0x_pattern = r"0x[0-9a-fA-F]{6,}"
        sequences.extend(re.findall(hex_0x_pattern, text))

        # Pattern 2: \x prefix (e.g., \x48\x65\x6c\x6c\x6f)
        hex_backslash_pattern = r"(?:\\x[0-9a-fA-F]{2}){3,}"
        sequences.extend(re.findall(hex_backslash_pattern, text))

        return sequences

    def _detect_url_encoding(self, text: str) -> List[str]:
        """
        Detect URL encoded sequences in text.

        Looks for % followed by hex digits pattern.

        Args:
            text: String to analyze

        Returns:
            List of detected URL encoded sequences

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> sequences = scorer._detect_url_encoding("%48%65%6c%6c%6f")
            >>> len(sequences) > 0
            True
        """
        if not text:
            return []

        # Pattern: % followed by hex digits (at least 3 occurrences)
        url_pattern = r"(?:%[0-9a-fA-F]{2}){3,}"
        sequences = re.findall(url_pattern, text)

        return sequences

    def _detect_encoding_layers(self, content: str, max_depth: Optional[int] = None) -> int:
        """
        Recursively detect encoding layers in content.

        Attempts to decode base64 sequences and check for nested encoding.
        Limits recursion to prevent infinite loops.

        Args:
            content: String to analyze
            max_depth: Maximum recursion depth (uses config default if None)

        Returns:
            Total number of encoding layers detected (0-N)

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> # Single layer base64
            >>> scorer._detect_encoding_layers("SGVsbG8gV29ybGQh")
            1
            >>> # No encoding
            >>> scorer._detect_encoding_layers("Hello World")
            0
        """
        if max_depth is None:
            max_depth = self.max_recursion_depth

        layers = 0
        current_content = content

        for depth in range(max_depth):
            # Detect base64 sequences
            base64_sequences = self._detect_base64(current_content)

            if not base64_sequences:
                # No more base64 found, check for other encoding types
                hex_sequences = self._detect_hex_encoding(current_content)
                url_sequences = self._detect_url_encoding(current_content)

                if hex_sequences or url_sequences:
                    layers += 1
                break

            # Try to decode the first/longest base64 sequence
            decoded = None
            for seq in sorted(base64_sequences, key=len, reverse=True):
                decoded = self._try_decode_base64(seq)
                if decoded and decoded != seq:
                    break

            if decoded and decoded != current_content:
                layers += 1
                current_content = decoded
            else:
                # Can't decode further
                if base64_sequences:
                    layers += 1
                break

        return layers

    def _score_encoding(self, layers: int) -> float:
        """
        Convert encoding layer count to score (0-40 points).

        Scoring logic:
        - 1 layer: 10 points
        - 2 layers: 25 points
        - 3+ layers: 40 points (maximum)

        Args:
            layers: Number of encoding layers detected

        Returns:
            Score value (0.0 to max_encoding_score, typically 40)

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> scorer._score_encoding(0)
            0.0
            >>> scorer._score_encoding(1)
            10.0
            >>> scorer._score_encoding(2)
            25.0
            >>> scorer._score_encoding(3)
            40.0
            >>> scorer._score_encoding(5)
            40.0
        """
        if layers == 0:
            return 0.0
        elif layers == 1:
            return float(self.encoding_scores.get("single_layer", 10))
        elif layers == 2:
            return float(self.encoding_scores.get("double_layer", 25))
        else:  # 3 or more layers
            return float(self.encoding_scores.get("triple_plus_layer", 40))

    def _generate_encoding_explanation(self, layers: int, score: float) -> List[str]:
        """
        Generate human-readable explanation of encoding score.

        Args:
            layers: Number of encoding layers detected
            score: Calculated encoding score

        Returns:
            List of explanation strings

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> explanations = scorer._generate_encoding_explanation(2, 25.0)
            >>> len(explanations) > 0
            True
            >>> any('layer' in e.lower() for e in explanations)
            True
        """
        explanations = []

        if layers == 0:
            explanations.append("No encoding layers detected")
        elif layers == 1:
            explanations.append(
                f"Single encoding layer detected - {score:.1f}/{self.max_encoding_score} points"
            )
        elif layers == 2:
            explanations.append(
                f"Double encoding layer detected (base64 within base64) - "
                f"{score:.1f}/{self.max_encoding_score} points"
            )
        else:
            explanations.append(
                f"Multiple encoding layers detected ({layers} layers) - "
                f"{score:.1f}/{self.max_encoding_score} points (maximum)"
            )

        return explanations

    def _calculate_complexity(self, ast: Optional[Dict]) -> int:
        """
        Calculate cyclomatic complexity from AST.

        Cyclomatic complexity measures code complexity by counting decision points.
        Formula: Complexity = 1 + (number of decision points)

        Decision points include:
        - Conditional statements: if, elif, else if
        - Loop statements: while, for, foreach
        - Switch/case statements
        - Exception handlers: try/catch
        - Boolean operators: and, or, &&, ||

        Args:
            ast: Abstract Syntax Tree (dict or list structure)

        Returns:
            Cyclomatic complexity score (integer, 0 if AST is None/empty)

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> scorer._calculate_complexity(None)
            0
            >>> scorer._calculate_complexity({})
            0
            >>> simple_ast = {'type': 'If', 'body': []}
            >>> scorer._calculate_complexity(simple_ast)
            2
        """
        if not ast:
            return 0

        decision_points = 0
        visited = set()  # Prevent infinite loops in circular references

        def traverse(node, path=""):
            """Recursively traverse AST and count decision points."""
            nonlocal decision_points

            # Prevent infinite loops
            node_id = id(node)
            if node_id in visited:
                return
            visited.add(node_id)

            # Handle dict nodes
            if isinstance(node, dict):
                node_type = node.get("type", node.get("kind", ""))

                # Check if this is a decision point
                if self._is_decision_node(node_type):
                    decision_points += 1

                # Recursively traverse children
                for key, value in node.items():
                    if key not in [
                        "type",
                        "kind",
                        "position",
                        "line",
                        "col",
                        "lineno",
                        "col_offset",
                    ]:
                        traverse(value, f"{path}.{key}")

            # Handle list nodes
            elif isinstance(node, list):
                for i, item in enumerate(node):
                    traverse(item, f"{path}[{i}]")

        traverse(ast)
        return 1 + decision_points

    def _is_decision_node(self, node_type: str) -> bool:
        """
        Check if AST node type represents a decision point.

        Supports multiple language AST formats:
        - PowerShell: IfStatementAst, WhileStatementAst, ForStatementAst, etc.
        - Bash: if, while, for, case, operator (&&, ||)
        - Python: If, While, For, Try, BoolOp
        - JavaScript: if_statement, while_statement, for_statement, etc.

        Args:
            node_type: AST node type string

        Returns:
            True if node represents a decision point, False otherwise

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> scorer._is_decision_node('If')
            True
            >>> scorer._is_decision_node('IfStatementAst')
            True
            >>> scorer._is_decision_node('if_statement')
            True
            >>> scorer._is_decision_node('Assignment')
            False
        """
        if not node_type:
            return False

        # Normalize to lowercase for case-insensitive matching
        node_type_lower = node_type.lower()

        # Decision node patterns (language-agnostic)
        decision_patterns = [
            # Conditional statements
            "if",
            "elif",
            "elseif",
            "else if",
            # Loop statements
            "while",
            "for",
            "foreach",
            "do",
            # Switch/case statements
            "switch",
            "case",
            # Exception handling
            "try",
            "catch",
            "except",
            # Boolean operators
            "and",
            "or",
            "boolop",
            "&&",
            "||",
            # Ternary/conditional expressions
            "conditional",
            "ternary",
        ]

        # Check if node type contains any decision pattern
        return any(pattern in node_type_lower for pattern in decision_patterns)

    def _score_complexity(self, complexity: int) -> Tuple[float, List[str]]:
        """
        Convert complexity value to score (0-30 points) with explanations.

        Scoring logic:
        - Low complexity (<30): 0-10 points (linear interpolation)
        - Medium complexity (30-50): 10-20 points (linear interpolation)
        - High complexity (50-100): 20-30 points (linear interpolation)
        - Very high complexity (>100): 30 points (maximum)

        Args:
            complexity: Cyclomatic complexity value

        Returns:
            Tuple of (score: 0-30, explanations: list of strings)

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> score, explanations = scorer._score_complexity(0)
            >>> score
            0.0
            >>> score, explanations = scorer._score_complexity(25)
            >>> 0 < score <= 10
            True
            >>> score, explanations = scorer._score_complexity(40)
            >>> 10 < score <= 20
            True
            >>> score, explanations = scorer._score_complexity(75)
            >>> 20 < score <= 30
            True
            >>> score, explanations = scorer._score_complexity(150)
            >>> score
            30.0
        """
        explanations = []

        # Get thresholds from configuration
        low_threshold = self.complexity_thresholds["low"]
        medium_threshold = self.complexity_thresholds["medium"]
        high_threshold = self.complexity_thresholds["high"]

        if complexity == 0:
            score = 0.0
            explanations.append("No complexity detected (AST not provided or empty)")
        elif complexity < low_threshold:
            # Low complexity: 0-10 points (linear interpolation)
            ratio = complexity / low_threshold
            score = ratio * (self.max_complexity_score / 3)  # 0-10 points
            explanations.append(
                f"Low complexity ({complexity} decision points) - simple code structure"
            )
        elif complexity < medium_threshold:
            # Medium complexity: 10-20 points (linear interpolation)
            ratio = (complexity - low_threshold) / (medium_threshold - low_threshold)
            score = (self.max_complexity_score / 3) + (ratio * (self.max_complexity_score / 3))
            explanations.append(
                f"Medium complexity ({complexity} decision points) - moderately complex code"
            )
        elif complexity < high_threshold:
            # High complexity: 20-30 points (linear interpolation)
            ratio = (complexity - medium_threshold) / (high_threshold - medium_threshold)
            score = (2 * self.max_complexity_score / 3) + (ratio * (self.max_complexity_score / 3))
            explanations.append(
                f"High complexity ({complexity} decision points) - complex code, potentially suspicious"
            )
        else:
            # Very high complexity: 30 points (maximum)
            score = float(self.max_complexity_score)
            explanations.append(
                f"Very high complexity ({complexity} decision points) - highly suspicious, "
                "typical of obfuscated malware"
            )

        # Cap at max score
        score = min(score, self.max_complexity_score)

        return score, explanations

    def _is_in_comment(self, text: str, sequence: str) -> bool:
        """
        Check if a sequence appears within a comment.

        Simple heuristic: checks if sequence is on a line starting with # or //

        Args:
            text: Full text content
            sequence: Sequence to check

        Returns:
            True if sequence appears to be in a comment
        """
        # Find the line containing the sequence
        for line in text.split("\n"):
            if sequence in line:
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    return True
        return False

    def _detect_suspicious_strings(self, text: str) -> List[Tuple[str, str]]:
        """
        Detect suspicious string patterns in script content.

        Uses compiled regex patterns for case-insensitive matching.
        Counts total occurrences (not just unique patterns) to reflect severity.

        Args:
            text: Script content to analyze

        Returns:
            List of tuples (pattern, severity) for all matched patterns

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> matches = scorer._detect_suspicious_strings("Invoke-Expression $cmd")
            >>> len(matches) > 0
            True
            >>> matches = scorer._detect_suspicious_strings("echo 'hello'")
            >>> len(matches)
            0
        """
        if not text:
            return []

        matched_patterns = []

        # Search for all compiled patterns
        for compiled_pattern, original_pattern, severity in self.compiled_patterns:
            # Find all occurrences of this pattern
            matches = compiled_pattern.findall(text)
            # Add each occurrence to the list (not just unique)
            for _ in matches:
                matched_patterns.append((original_pattern, severity))

        return matched_patterns

    def _score_suspicious_strings(self, pattern_count: int) -> float:
        """
        Convert suspicious string pattern count to score (0-25 points).

        Scoring logic:
        - 0 patterns: 0 points
        - 1-2 patterns: 5-10 points (linear interpolation)
        - 3-5 patterns: 10-15 points (linear interpolation)
        - 6-10 patterns: 15-20 points (linear interpolation)
        - 10+ patterns: 20-25 points (capped at max)

        Args:
            pattern_count: Total number of suspicious patterns detected

        Returns:
            Score value (0.0 to max_suspicious_string_score, typically 25)

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> scorer._score_suspicious_strings(0)
            0.0
            >>> 5.0 <= scorer._score_suspicious_strings(1) <= 10.0
            True
            >>> 10.0 <= scorer._score_suspicious_strings(4) <= 15.0
            True
            >>> 15.0 <= scorer._score_suspicious_strings(8) <= 20.0
            True
            >>> scorer._score_suspicious_strings(15)
            25.0
        """
        if pattern_count == 0:
            return 0.0

        low_threshold = self.suspicious_string_thresholds["low"]
        medium_threshold = self.suspicious_string_thresholds["medium"]
        high_threshold = self.suspicious_string_thresholds["high"]

        # 1-2 patterns: 5-10 points (linear interpolation)
        if pattern_count <= low_threshold:
            # Linear interpolation between 5 and 10 points
            position = pattern_count / low_threshold
            min_score = self.max_suspicious_string_score * 0.2  # 5 points
            max_score = self.max_suspicious_string_score * 0.4  # 10 points
            score = min_score + (position * (max_score - min_score))
            return score

        # 3-5 patterns: 10-15 points (linear interpolation)
        elif pattern_count <= medium_threshold:
            # Linear interpolation between 10 and 15 points
            range_size = medium_threshold - low_threshold
            position = (pattern_count - low_threshold) / range_size
            min_score = self.max_suspicious_string_score * 0.4  # 10 points
            max_score = self.max_suspicious_string_score * 0.6  # 15 points
            score = min_score + (position * (max_score - min_score))
            return score

        # 6-10 patterns: 15-20 points (linear interpolation)
        elif pattern_count <= high_threshold:
            # Linear interpolation between 15 and 20 points
            range_size = high_threshold - medium_threshold
            position = (pattern_count - medium_threshold) / range_size
            min_score = self.max_suspicious_string_score * 0.6  # 15 points
            max_score = self.max_suspicious_string_score * 0.8  # 20 points
            score = min_score + (position * (max_score - min_score))
            return score

        # 10+ patterns: 20-25 points (capped at max)
        else:
            # Linear interpolation between 20 and 25 points, capped
            # Use pattern_count - high_threshold for additional patterns
            additional = min(pattern_count - high_threshold, high_threshold)
            position = additional / high_threshold
            min_score = self.max_suspicious_string_score * 0.8  # 20 points
            max_score = self.max_suspicious_string_score  # 25 points
            score = min_score + (position * (max_score - min_score))
            return min(score, self.max_suspicious_string_score)

    def _generate_suspicious_strings_explanation(
        self, matched_patterns: List[Tuple[str, str]], score: float
    ) -> List[str]:
        """
        Generate human-readable explanation of suspicious string detection.

        Args:
            matched_patterns: List of (pattern, severity) tuples
            score: Calculated suspicious string score

        Returns:
            List of explanation strings

        Examples:
            >>> scorer = ContentIntelligenceScorer({})
            >>> patterns = [("invoke-expression", "critical"), ("iex", "critical")]
            >>> explanations = scorer._generate_suspicious_strings_explanation(patterns, 10.0)
            >>> len(explanations) > 0
            True
            >>> any("suspicious" in e.lower() for e in explanations)
            True
        """
        explanations = []

        if not matched_patterns:
            explanations.append("No suspicious string patterns detected")
            return explanations

        # Count patterns by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0}
        pattern_counts = {}

        for pattern, severity in matched_patterns:
            severity_counts[severity] += 1
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        total_count = len(matched_patterns)
        unique_count = len(pattern_counts)

        # Main explanation
        explanations.append(
            f"Detected {total_count} suspicious string pattern(s) "
            f"({unique_count} unique) - {score:.1f}/{self.max_suspicious_string_score} points"
        )

        # Severity breakdown
        severity_parts = []
        if severity_counts["critical"] > 0:
            severity_parts.append(f"{severity_counts['critical']} critical")
        if severity_counts["high"] > 0:
            severity_parts.append(f"{severity_counts['high']} high")
        if severity_counts["medium"] > 0:
            severity_parts.append(f"{severity_counts['medium']} medium")

        if severity_parts:
            explanations.append(f"Severity breakdown: {', '.join(severity_parts)}")

        # List top patterns (up to 5 most frequent)
        sorted_patterns = sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True)
        top_patterns = sorted_patterns[:5]

        if top_patterns:
            pattern_list = [f"'{p}' ({c}x)" for p, c in top_patterns]
            explanations.append(f"Top patterns: {', '.join(pattern_list)}")

        return explanations

    def _is_valid_base64(self, text: str) -> bool:
        """
        Validate if text is valid base64.

        Args:
            text: String to validate

        Returns:
            True if valid base64, False otherwise
        """
        try:
            # Try to decode
            base64.b64decode(text, validate=True)
            return True
        except Exception:
            return False

    def _try_decode_base64(self, text: str) -> Optional[str]:
        """
        Attempt to decode base64 text.

        Args:
            text: Base64 string to decode

        Returns:
            Decoded string if successful, None otherwise
        """
        try:
            decoded_bytes = base64.b64decode(text, validate=True)
            # Try to decode as UTF-8
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            return decoded_str
        except Exception:
            return None
