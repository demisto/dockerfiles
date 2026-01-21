"""Configuration loader for Script Sentinel verdict engine.

This module provides configuration loading, validation, and caching for the
enhanced verdict engine. It supports YAML configuration files with graceful
fallback to defaults when files are missing or invalid.

The ConfigLoader implements a singleton-like caching pattern to avoid repeated
file I/O operations while maintaining immutability after load.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import yaml

logger = logging.getLogger(__name__)

# Global cache for configuration (singleton-like pattern)
_config_cache: Optional[Dict[str, Any]] = None
_config_path_cache: Optional[str] = None


class ConfigLoader:
    """
    Loads and validates configuration from YAML files.

    This class implements configuration loading with:
    - YAML file parsing with error handling
    - Configuration validation
    - Default fallback for missing/invalid configs
    - Singleton-like caching to avoid repeated I/O
    - Immutable configuration after load

    The configuration is cached globally on first load and reused for
    subsequent requests with the same path.

    Attributes:
        DEFAULT_CONFIG: Default configuration used as fallback

    Examples:
        >>> loader = ConfigLoader()
        >>> config = loader.load_config('config/patterns_config.yaml')
        >>> severity_weights = config['severity_scorer']['weights']
        >>> print(severity_weights['Critical'])
        100
    """

    # Default configuration - used when file is missing or invalid
    DEFAULT_CONFIG = {
        "aggregator": {
            "weights": {
                "severity": 0.30,
                "cooccurrence": 0.20,
                "killchain": 0.15,
                "content": 0.10,
                "yara": 0.15,
                "ml": 0.10,
            }
        },
        "severity_scorer": {
            "weights": {
                "Critical": 100,
                "High": 70,
                "Medium": 40,
                "Low": 20,
                "Informational": 5,
            },
            "confidence_multiplier": True,
        },
        "cooccurrence_scorer": {
            "enabled": False,
            "threshold": 0.6,
            "window_size": 50,
        },
        "killchain_scorer": {
            "enabled": False,
            "progression_bonus": 1.2,
            "stages": [
                "reconnaissance",
                "weaponization",
                "delivery",
                "exploitation",
                "installation",
                "command_and_control",
                "actions_on_objectives",
            ],
        },
        "content_scorer": {
            "enabled": False,
            "entropy_threshold": 7.0,
            "encoding_layers": 3,
            "complexity_threshold": 15,
        },
        "pattern_combinations": {
            "critical": [],
            "high": [],
            "medium": []
        },
        "kill_chain_progressions": {
            "critical": [],
            "high": [],
            "medium": []
        },
        "verdict_thresholds": {
            "malicious": 70,
            "suspicious": 40
        },
        "confidence_caps": {
            "malicious": 0.95,
            "suspicious": 0.85,
            "benign": 0.75
        },
        "paranoia_levels": {
            1: {"malicious_threshold": 70, "suspicious_threshold": 40},
            2: {"malicious_threshold": 55, "suspicious_threshold": 30},
            3: {"malicious_threshold": 40, "suspicious_threshold": 20}
        },
        "content_intelligence": {
            "entropy": {
                "thresholds": {"high": 7.5, "medium": 6.5},
                "scoring": {"max_score": 30}
            },
            "encoding": {
                "enabled": True,
                "detection": {"min_base64_length": 20, "max_recursion_depth": 5},
                "scoring": {"single_layer": 10, "double_layer": 25, "triple_plus_layer": 40, "max_score": 40}
            },
            "complexity": {
                "enabled": True,
                "thresholds": {"low": 30, "medium": 50, "high": 100},
                "scoring": {"max_score": 30}
            },
            "string_patterns": {
                "enabled": True,
                "scoring": {"max_score": 25}
            }
        },
        "yara_scorer": {
            "severity_weights": {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "informational": 0.5},
            "normalization_factor": 3.0,
            "max_score": 100
        },
        "ml_scorer": {
            "enabled": True,
            "models_dir": "ml_models",
            "supported_languages": ["powershell", "javascript", "vbscript"],
            "thresholds": {
                "powershell": 0.85,
                "javascript": 0.5,
                "vbscript": 0.9
            },
            "normalization_factor": 100.0,
            "max_score": 100.0
        },
        "context_aware_scoring": {
            "enabled": True
        }
    }

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file with caching and fallback.

        This method implements the following behavior:
        1. Check if config is already cached for this path
        2. If not cached, attempt to load from file
        3. Validate loaded configuration
        4. Fall back to defaults if file missing or invalid
        5. Cache the result for future calls

        Args:
            config_path: Path to YAML configuration file (relative or absolute)

        Returns:
            Configuration dictionary with all required sections

        Examples:
            >>> loader = ConfigLoader()
            >>> # First call loads from file
            >>> config1 = loader.load_config('config/patterns_config.yaml')
            >>> # Second call returns cached config
            >>> config2 = loader.load_config('config/patterns_config.yaml')
            >>> config1 is config2  # Same object reference
            True
        """
        global _config_cache, _config_path_cache

        # Return cached config if available for this path
        if _config_cache is not None and _config_path_cache == config_path:
            logger.debug(f"Returning cached configuration for {config_path}")
            return _config_cache

        # Attempt to load from file
        config, error = self._load_from_file(config_path)

        if error:
            logger.warning(f"Configuration load failed: {error}. Using defaults.")
            config = self.DEFAULT_CONFIG.copy()
        else:
            # Validate and merge with defaults
            config = self._validate_and_merge(config)

        # Cache the configuration
        _config_cache = config
        _config_path_cache = config_path

        logger.info(f"Configuration loaded and cached from {config_path}")
        return config

    def _load_from_file(self, config_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Load YAML configuration from file.

        Args:
            config_path: Path to YAML file

        Returns:
            Tuple of (config_dict, error_message)
            - If successful: (config, None)
            - If failed: (None, error_message)

        Examples:
            >>> loader = ConfigLoader()
            >>> config, error = loader._load_from_file('config/patterns_config.yaml')
            >>> if error is None:
            ...     print("Config loaded successfully")
            Config loaded successfully
        """
        try:
            # Resolve path (handle both relative and absolute)
            path = Path(config_path)
            if not path.is_absolute():
                # Try relative to current directory first
                if not path.exists():
                    # Try relative to script-sentinel directory
                    sentinel_path = Path(__file__).parent.parent.parent / config_path
                    if sentinel_path.exists():
                        path = sentinel_path

            # Check if file exists
            if not path.exists():
                return None, f"Configuration file not found: {config_path}"

            # Read and parse YAML
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            if config is None:
                return None, "Configuration file is empty"

            if not isinstance(config, dict):
                return None, f"Invalid configuration format: expected dict, got {type(config).__name__}"

            logger.debug(f"Successfully loaded configuration from {path}")
            return config, None

        except yaml.YAMLError as e:
            return None, f"YAML parsing error: {str(e)}"
        except PermissionError:
            return None, f"Permission denied reading {config_path}"
        except Exception as e:
            return None, f"Unexpected error loading config: {str(e)}"

    def _validate_and_merge(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration and merge with defaults.

        This method ensures all required sections exist and have valid values.
        Missing sections are filled from defaults. Invalid values trigger warnings
        and are replaced with defaults.

        Args:
            config: Loaded configuration dictionary

        Returns:
            Validated and merged configuration

        Examples:
            >>> loader = ConfigLoader()
            >>> partial_config = {'severity_scorer': {'weights': {'Critical': 100}}}
            >>> full_config = loader._validate_and_merge(partial_config)
            >>> 'aggregator' in full_config
            True
        """
        # Start with deep copy of defaults
        import copy

        merged = copy.deepcopy(self.DEFAULT_CONFIG)

        # Validate and merge each section
        sections = [
            "aggregator", "severity_scorer", "cooccurrence_scorer", "killchain_scorer", "content_scorer",
            "pattern_combinations", "kill_chain_progressions", "verdict_thresholds",
            "confidence_caps", "paranoia_levels", "content_intelligence", "yara_scorer",
            "ml_scorer", "context_aware_scoring"
        ]
        for section in sections:
            if section in config:
                if isinstance(config[section], dict):
                    # Ensure section exists in merged config
                    if section not in merged:
                        merged[section] = {}
                    
                    # Deep merge section with defaults (nested dicts like 'weights')
                    for key, value in config[section].items():
                        is_nested_dict = isinstance(value, dict)
                        key_exists = key in merged[section]
                        target_is_dict = key_exists and isinstance(merged[section][key], dict)
                        if is_nested_dict and target_is_dict:
                            # Merge nested dicts (like weights)
                            merged[section][key] = {**merged[section][key], **value}
                        else:
                            # Replace top-level values
                            merged[section][key] = value

                    # Validate specific sections
                    if section == "severity_scorer":
                        self._validate_severity_weights(merged[section])
                    elif section == "aggregator":
                        self._validate_aggregator_weights(merged[section])
                else:
                    logger.warning(f"Invalid {section} section (not a dict), using defaults")

        return merged

    def _validate_severity_weights(self, config: Dict[str, Any]) -> None:
        """
        Validate severity scorer weights.

        Checks that all required severity levels have numeric weights.
        Logs warnings for invalid values but doesn't fail.

        Args:
            config: Severity scorer configuration section
        """
        if "weights" not in config:
            logger.warning("Missing 'weights' in severity_scorer config")
            return

        weights = config["weights"]
        required_levels = ["Critical", "High", "Medium", "Low", "Informational"]

        for level in required_levels:
            if level not in weights:
                logger.warning(f"Missing severity weight for '{level}', using default")
            elif not isinstance(weights[level], (int, float)):
                logger.warning(f"Invalid weight for '{level}': {weights[level]}, using default")

    def _validate_aggregator_weights(self, config: Dict[str, Any]) -> None:
        """
        Validate aggregator weights.

        Checks that weights sum to approximately 1.0 and are all numeric.
        Logs warnings for invalid configurations.

        Args:
            config: Aggregator configuration section
        """
        if "weights" not in config:
            logger.warning("Missing 'weights' in aggregator config")
            return

        weights = config["weights"]
        required_scorers = ["severity", "cooccurrence", "killchain", "content", "yara", "ml"]

        # Check all weights are present and numeric
        total = 0.0
        for scorer in required_scorers:
            if scorer not in weights:
                logger.warning(f"Missing aggregator weight for '{scorer}'")
            elif not isinstance(weights[scorer], (int, float)):
                logger.warning(f"Invalid aggregator weight for '{scorer}': {weights[scorer]}")
            else:
                total += weights[scorer]

        # Warn if weights don't sum to ~1.0
        if abs(total - 1.0) > 0.01:
            logger.warning(f"Aggregator weights sum to {total:.2f}, expected 1.0")

    @staticmethod
    def clear_cache() -> None:
        """
        Clear the configuration cache.

        This is primarily useful for testing to force reload of configuration.

        Examples:
            >>> ConfigLoader.clear_cache()
            >>> # Next load_config call will read from file again
        """
        global _config_cache, _config_path_cache
        _config_cache = None
        _config_path_cache = None
        logger.debug("Configuration cache cleared")


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Convenience function to load configuration.

    This is a simplified interface to ConfigLoader for backward compatibility
    and ease of use.

    Args:
        config_path: Path to YAML configuration file

    Returns:
        Configuration dictionary

    Examples:
        >>> config = load_config('config/patterns_config.yaml')
        >>> print(config['severity_scorer']['weights']['Critical'])
        100
    """
    loader = ConfigLoader()
    return loader.load_config(config_path)
