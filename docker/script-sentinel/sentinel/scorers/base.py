"""Base scorer interface for verdict calculation."""

from abc import ABC, abstractmethod
from typing import List, Tuple, Dict, Any


class BaseScorer(ABC):
    """
    Abstract base class for all verdict scorers.

    Each scorer analyzes findings and/or script content to produce
    a score (0-100) and optional explanations.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml

    Examples:
        >>> class MyScorer(BaseScorer):
        ...     def score(self, findings):
        ...         return 50.0, ["Example explanation"]
        >>> scorer = MyScorer({})
        >>> score, explanations = scorer.score([])
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize scorer with configuration.

        Args:
            config: Configuration dictionary from patterns_config.yaml
        """
        self.config = config

    @abstractmethod
    def score(self, *args, **kwargs) -> Tuple[float, List[str]]:
        """
        Calculate score based on inputs.

        This method must be implemented by all concrete scorer classes.
        The specific parameters depend on the scorer type.

        Returns:
            Tuple of (score: 0-100, explanations: list of strings)

        Raises:
            NotImplementedError: If not implemented by subclass
        """
        pass

    def validate_score(self, score: float) -> float:
        """
        Ensure score is in valid range [0, 100].

        Args:
            score: Raw score value

        Returns:
            Validated score clamped to [0, 100]

        Examples:
            >>> scorer = MyScorer({})
            >>> scorer.validate_score(150.0)
            100.0
            >>> scorer.validate_score(-10.0)
            0.0
            >>> scorer.validate_score(75.5)
            75.5
        """
        return max(0.0, min(100.0, score))
