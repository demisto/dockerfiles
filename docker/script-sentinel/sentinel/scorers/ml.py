"""Machine Learning scorer for verdict calculation using Hornet LightGBM models.

This module implements the MLScorer which uses pre-trained LightGBM models
to detect malicious scripts in PowerShell, JavaScript, and VBScript.

The scorer integrates Hornet ML models as a 6th scorer in Script-Sentinel's
multi-scorer verdict system, providing ML-based detection alongside heuristic
pattern matching, YARA rules, and other scorers.

Architecture:
- Uses external binaries (genpsvector, hornet_genvector) for feature extraction
- Loads LightGBM models from ml_models/ directory
- Parses sparse binary feature vectors
- Generates predictions and normalizes to 0-100 scale
- Implements graceful degradation if models unavailable

Supported Languages:
- PowerShell (.ps1) - 26,143 features, threshold 0.85
- JavaScript (.js) - 9,355 features, threshold 0.5
- VBScript (.vbs) - 707 features, threshold 0.9
"""

import logging
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

from sentinel.scorers.base import BaseScorer

logger = logging.getLogger(__name__)


class MLScorer(BaseScorer):
    """
    Machine Learning scorer using Hornet LightGBM models.

    Integrates pre-trained LightGBM models for PowerShell, JavaScript, and
    VBScript malware detection. Uses external binaries for feature extraction
    and LightGBM for prediction.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        models_dir: Path to ml_models directory
        models: Dictionary of loaded LightGBM models by language
        thresholds: Detection thresholds by language
        supported_languages: Set of supported language identifiers

    Examples:
        >>> config = {
        ...     'ml_scorer': {
        ...         'enabled': True,
        ...         'models_dir': 'ml_models',
        ...         'supported_languages': ['powershell', 'javascript']
        ...     }
        ... }
        >>> scorer = MLScorer(config)
        >>> score, explanations = scorer.score('powershell', script_content)
        >>> print(f"ML Score: {score:.1f}/100")
        ML Score: 75.0/100
    """

    # Default configuration
    DEFAULT_CONFIG = {
        'enabled': True,
        'models_dir': 'ml_models',
        'supported_languages': ['powershell', 'javascript', 'vbscript'],
        'thresholds': {
            'powershell': 0.85,
            'javascript': 0.5,
            'vbscript': 0.9
        },
        'normalization_factor': 100.0,  # Scale probability to 0-100
        'max_score': 100.0
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the ML scorer with configuration.

        Args:
            config: Configuration dictionary containing ml_scorer section
        """
        super().__init__(config)

        # Extract ML scorer configuration with defaults
        ml_config = config.get('ml_scorer', {})
        self.enabled = ml_config.get('enabled', self.DEFAULT_CONFIG['enabled'])

        # Get models directory from config or environment variable
        models_dir = ml_config.get('models_dir') or os.environ.get('ML_MODELS_DIR')
        if not models_dir:
            models_dir = self.DEFAULT_CONFIG['models_dir']

        self.models_dir = Path(models_dir)

        # Load configuration
        self.supported_languages = set(
            ml_config.get('supported_languages', self.DEFAULT_CONFIG['supported_languages'])
        )
        self.thresholds = ml_config.get('thresholds', self.DEFAULT_CONFIG['thresholds'])
        self.normalization_factor = ml_config.get(
            'normalization_factor', self.DEFAULT_CONFIG['normalization_factor']
        )
        self.max_score = ml_config.get('max_score', self.DEFAULT_CONFIG['max_score'])

        # Initialize models dictionary
        self.models = {}
        self._lightgbm_available = False

        # Try to import LightGBM
        try:
            import lightgbm as lgb
            self._lgb = lgb
            self._lightgbm_available = True
            logger.info("LightGBM library loaded successfully")
        except ImportError:
            logger.warning(
                "LightGBM not available. ML scoring will be disabled. "
                "Install with: pip install lightgbm"
            )
            self.enabled = False
            return

        # Load models if enabled
        if self.enabled:
            self._load_models()

    def _load_models(self) -> None:
        """
        Load LightGBM models from ml_models directory.

        Loads models for each supported language. Logs warnings for missing
        models but continues with available ones.
        """
        if not self.models_dir.exists():
            logger.warning(
                f"ML models directory not found: {self.models_dir}. "
                f"ML scoring will be disabled."
            )
            self.enabled = False
            return

        loaded_count = 0
        for language in self.supported_languages:
            model_path = self._get_model_path(language)
            if model_path and model_path.exists():
                try:
                    model = self._lgb.Booster(model_file=str(model_path))
                    self.models[language] = model
                    loaded_count += 1
                    logger.info(f"Loaded {language} ML model from {model_path}")
                except Exception as e:
                    logger.error(f"Failed to load {language} model: {e}")
            else:
                logger.warning(
                    f"Model file not found for {language}: {model_path}. "
                    f"Skipping {language} ML scoring."
                )

        if loaded_count == 0:
            logger.warning("No ML models loaded. ML scoring will be disabled.")
            self.enabled = False
        else:
            logger.info(f"ML scorer initialized with {loaded_count} model(s)")

    def _get_model_path(self, language: str) -> Optional[Path]:
        """
        Get path to model file for a language.

        Args:
            language: Language identifier ('powershell', 'javascript', 'vbscript')

        Returns:
            Path to model.txt file, or None if language not supported
        """
        language_dirs = {
            'powershell': 'powershell',
            'javascript': 'js',
            'vbscript': 'vbs'
        }

        lang_dir = language_dirs.get(language)
        if not lang_dir:
            return None

        return self.models_dir / lang_dir / 'model.txt'

    def _get_binary_path(self, language: str) -> Optional[Path]:
        """
        Get path to feature extraction binary for a language.

        Args:
            language: Language identifier ('powershell', 'javascript', 'vbscript')

        Returns:
            Path to binary, or None if not found
        """
        if language == 'powershell':
            binary_path = self.models_dir / 'powershell' / 'genpsvector'
        else:
            # JavaScript and VBScript use hornet_genvector
            binary_path = self.models_dir / 'hornet_genvector'

        if binary_path.exists():
            return binary_path
        return None

    def score(
        self,
        language: Optional[str] = None,
        script_content: Optional[str] = None,
        script_path: Optional[str] = None
    ) -> Tuple[float, List[str]]:
        """
        Calculate ML-based malware detection score.

        Uses Hornet LightGBM models to predict malware probability and
        converts to 0-100 score scale.

        Args:
            language: Script language ('powershell', 'javascript', 'vbscript')
            script_content: Script content as string (optional if script_path provided)
            script_path: Path to script file (optional if script_content provided)

        Returns:
            Tuple of (score: 0-100, explanations: list of strings)

        Examples:
            >>> scorer = MLScorer(config)
            >>> score, explanations = scorer.score('powershell', script_content='...')
            >>> print(f"Score: {score:.1f}")
            Score: 85.0
        """
        # Graceful degradation: return 0 if ML scoring disabled
        if not self.enabled:
            return 0.0, ["ML scoring disabled (models not available)"]

        # Validate inputs
        if not language:
            return 0.0, ["ML scoring skipped (no language specified)"]

        if language not in self.supported_languages:
            return 0.0, [f"ML scoring skipped (language '{language}' not supported)"]

        if language not in self.models:
            return 0.0, [f"ML scoring skipped (no model loaded for '{language}')"]

        if not script_content and not script_path:
            return 0.0, ["ML scoring skipped (no script content or path provided)"]

        try:
            # Extract features
            feature_vector = self._extract_features(language, script_content, script_path)
            if feature_vector is None:
                return 0.0, ["ML scoring failed (feature extraction error)"]

            # Generate prediction
            model = self.models[language]
            probability = model.predict([feature_vector])[0]

            # Get threshold for this language
            threshold = self.thresholds.get(language, 0.5)

            # Normalize to 0-100 scale
            # Score increases as probability approaches/exceeds threshold
            if probability >= threshold:
                # Above threshold: scale from 50-100
                score = 50.0 + (probability - threshold) / (1.0 - threshold) * 50.0
            else:
                # Below threshold: scale from 0-50
                score = (probability / threshold) * 50.0

            score = self.validate_score(score)

            # Generate explanation
            explanations = [
                f"ML prediction: {probability:.3f} (threshold: {threshold})",
                f"ML score: {score:.1f}/100 for {language}"
            ]

            if probability >= threshold:
                explanations.append(
                    f"⚠️ ML model detected malicious patterns (confidence: {probability:.1%})"
                )

            return score, explanations

        except Exception as e:
            logger.error(f"ML scoring error: {e}", exc_info=True)
            return 0.0, [f"ML scoring failed: {str(e)}"]

    def _extract_features(
        self,
        language: str,
        script_content: Optional[str],
        script_path: Optional[str]
    ) -> Optional[List[float]]:
        """
        Extract feature vector from script using Hornet binaries.

        Args:
            language: Script language
            script_content: Script content (optional)
            script_path: Path to script file (optional)

        Returns:
            Feature vector as list of floats, or None on error
        """
        binary_path = self._get_binary_path(language)
        if not binary_path:
            logger.warning(f"Feature extraction binary not found for {language}")
            return None

        # Create temporary file if content provided instead of path
        temp_file = None
        temp_dir = None
        try:
            if script_content and not script_path:
                # Write content to temporary file
                temp_file = tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix=f'.{language[:2]}',
                    delete=False
                )
                temp_file.write(script_content)
                temp_file.close()
                script_path = temp_file.name

            # Create temporary directory for output
            temp_dir = tempfile.mkdtemp()

            # Run feature extraction binary
            # PowerShell: genpsvector <script_path> <output_directory>
            # JS/VBS: hornet_genvector <js|vbs> <script_path> <output_directory>
            if language == 'powershell':
                cmd = [str(binary_path), script_path, temp_dir]
            else:
                # JavaScript and VBScript need language type as first argument
                lang_arg = 'js' if language == 'javascript' else 'vbs'
                cmd = [str(binary_path), lang_arg, script_path, temp_dir]
            
            # Pass environment variables to subprocess for library paths
            env = os.environ.copy()
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=30,
                env=env
            )

            if result.returncode != 0:
                logger.error(
                    f"Feature extraction failed: {result.stderr.decode('utf-8', errors='ignore')}"
                )
                return None

            # Find the generated feature vector file
            # Different binaries create different structures:
            # - genpsvector (PowerShell): output_dir/<hash> (no extension, no subdirectory)
            # - hornet_genvector (JS/VBS): output_dir/<first_3_chars>/<hash>.bin
            
            # First try to find .bin files (JS/VBS)
            output_files = list(Path(temp_dir).rglob('*.bin'))
            
            # If no .bin files, look for any files (PowerShell)
            if not output_files:
                output_files = [
                    f for f in Path(temp_dir).rglob('*')
                    if f.is_file() and not f.name.startswith('.')
                ]
            
            if not output_files:
                logger.error(f"No feature vector file generated in {temp_dir}")
                return None
            
            # Use the first (and typically only) file
            fv_file = output_files[0]
            logger.debug(f"Found feature vector file: {fv_file}")

            # Read the binary feature vector file
            with open(fv_file, 'rb') as f:
                binary_data = f.read()

            # Parse binary feature vector
            feature_vector = self._parse_feature_vector(binary_data, language)
            return feature_vector

        except subprocess.TimeoutExpired:
            logger.error("Feature extraction timed out")
            return None
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return None
        finally:
            # Clean up temporary file
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.unlink(temp_file.name)
                except Exception as e:
                    logger.warning(f"Failed to delete temp file: {e}")
            
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                try:
                    import shutil
                    shutil.rmtree(temp_dir)
                except Exception as e:
                    logger.warning(f"Failed to delete temp directory: {e}")

    def _parse_feature_vector(self, binary_data: bytes, language: str) -> Optional[List[float]]:
        """
        Parse sparse binary feature vector to dense format.

        Binary format: [(index: uint64, value: double), ...]
        Each feature is 16 bytes (8 bytes index + 8 bytes value)

        Args:
            binary_data: Raw binary feature vector
            language: Script language (determines feature count)

        Returns:
            Dense feature vector as list of floats, or None on error
        """
        try:
            # Determine feature count based on language
            feature_counts = {
                'powershell': 26143,
                'javascript': 9355,
                'vbscript': 707
            }
            feature_count = feature_counts.get(language, 10000)

            # Initialize dense vector with zeros
            dense_vector = [0.0] * feature_count

            # Parse sparse binary format
            # Each entry is 16 bytes: uint64 (index) + double (value)
            entry_size = 16
            num_entries = len(binary_data) // entry_size

            for i in range(num_entries):
                offset = i * entry_size
                # Unpack: Q = unsigned long long (uint64), d = double
                index, value = struct.unpack('Qd', binary_data[offset:offset + entry_size])

                # Validate index
                if 0 <= index < feature_count:
                    dense_vector[index] = value
                else:
                    logger.warning(f"Invalid feature index: {index} (max: {feature_count})")

            return dense_vector

        except Exception as e:
            logger.error(f"Failed to parse feature vector: {e}")
            return None