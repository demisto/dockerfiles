"""MITRE kill chain scorer for verdict calculation.

This module implements the MitreKillChainScorer which detects MITRE ATT&CK
tactic progressions and scores based on their severity.
"""

from typing import List, Tuple, Dict, Any, Set
import logging
import os
import yaml
from sentinel.scorers.base import BaseScorer
from sentinel.models import Finding

logger = logging.getLogger(__name__)

def _load_technique_to_tactic_mapping() -> Dict[str, str]:
    """
    Load MITRE ATT&CK technique to tactic mapping from YAML config file.
    
    Returns:
        Dictionary mapping technique IDs (e.g., 'T1027') to tactic IDs (e.g., 'TA0005')
    
    Raises:
        FileNotFoundError: If the config file doesn't exist
        yaml.YAMLError: If the config file is malformed
        KeyError: If the expected structure is not found in the config
    """
    # Get the directory containing this file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Navigate to config directory (../../config from sentinel/scorers/)
    config_path = os.path.join(current_dir, '..', '..', 'config', 'mitre_attack_mapping.yaml')
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        if not config or 'technique_to_tactic' not in config:
            raise KeyError("Missing 'technique_to_tactic' key in MITRE ATT&CK mapping config")
            
        mapping = config['technique_to_tactic']
        
        if not isinstance(mapping, dict):
            raise ValueError("'technique_to_tactic' must be a dictionary")
            
        logger.info(f"Loaded {len(mapping)} MITRE technique-to-tactic mappings from {config_path}")
        return mapping
        
    except FileNotFoundError:
        logger.error(f"MITRE ATT&CK mapping config not found at {config_path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Error parsing MITRE ATT&CK mapping config: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading MITRE ATT&CK mapping: {e}")
        raise

# Load the mapping at module level (cached for performance)
TECHNIQUE_TO_TACTIC = _load_technique_to_tactic_mapping()

# Legacy comment preserved for reference:
# MITRE ATT&CK Technique to Tactic Mapping
# Comprehensive mapping of MITRE ATT&CK techniques to their primary tactics
# Source: MITRE ATT&CK Framework v15 (https://attack.mitre.org/)
# Last updated: 2025-12-03
# Coverage: Enterprise ATT&CK Matrix - All 14 Tactics
#
# Note: Some techniques map to multiple tactics. This mapping uses the PRIMARY tactic
# for each technique. The _extract_tactics() method handles this by using set() to
# deduplicate tactics when multiple findings reference the same technique.
#
# The mapping is now loaded from: script-sentinel/config/mitre_attack_mapping.yaml


class MitreKillChainScorer(BaseScorer):
    """
    Scores based on MITRE ATT&CK tactic progressions.

    This scorer analyzes MITRE ATT&CK tactics that appear together in findings,
    detecting multi-stage attack chains. When tactics from a configured progression
    are detected together, it assigns the progression's score. Uses max() not sum()
    for overlapping progressions to avoid double-counting.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        kill_chain_progressions: Dictionary of tactic progressions by severity
        critical_progressions: List of critical severity progressions
        high_progressions: List of high severity progressions
        medium_progressions: List of medium severity progressions

    Examples:
        >>> config = {
        ...     'kill_chain_progressions': {
        ...         'critical': [
        ...             {
        ...                 'name': 'Full Attack Chain',
        ...                 'tactics': None,
        ...                 'min_tactics': 5,
        ...                 'score': 40,
        ...                 'description': 'Multi-stage attack with 5+ tactics'
        ...             }
        ...         ]
        ...     }
        ... }
        >>> scorer = MitreKillChainScorer(config)
        >>> findings = [
        ...     Finding(
        ...         description='Initial Access',
        ...         severity='High',
        ...         confidence=0.9,
        ...         pattern_id='initial_access',
        ...         mitre_technique='T1566',
        ...         category='initial_access',
        ...         metadata={'mitre_tactic': 'TA0001'}
        ...     ),
        ...     Finding(
        ...         description='Execution',
        ...         severity='High',
        ...         confidence=0.8,
        ...         pattern_id='execution',
        ...         mitre_technique='T1059',
        ...         category='execution',
        ...         metadata={'mitre_tactic': 'TA0002'}
        ...     )
        ... ]
        >>> score, explanations = scorer.score(findings)
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the MITRE kill chain scorer.

        Args:
            config: Configuration dictionary containing kill_chain_progressions section
                   with critical, high, and medium severity categories
        """
        super().__init__(config)

        # Extract kill chain progressions configuration
        kill_chain = config.get('kill_chain_progressions', {})

        # Load progressions by severity category with defaults
        self.critical_progressions = kill_chain.get('critical', [])
        self.high_progressions = kill_chain.get('high', [])
        self.medium_progressions = kill_chain.get('medium', [])

        # Validate progressions on initialization
        self._validate_progressions()

    def _validate_progressions(self) -> None:
        """
        Validate kill chain progression structure.

        Logs warnings for invalid progressions but doesn't fail initialization.
        Invalid progressions are skipped during scoring.
        """
        for category, progressions in [
            ('critical', self.critical_progressions),
            ('high', self.high_progressions),
            ('medium', self.medium_progressions)
        ]:
            for i, progression in enumerate(progressions):
                # Check required fields
                if not isinstance(progression, dict):
                    continue

                # Must have either tactics list or tactics: null with min_tactics
                if 'tactics' not in progression:
                    continue

                if progression['tactics'] is None:
                    # Special "any N tactics" rule - must have min_tactics
                    if 'min_tactics' not in progression or not isinstance(progression['min_tactics'], int):
                        continue
                elif not isinstance(progression['tactics'], list):
                    continue

                # Must have score
                if 'score' not in progression or not isinstance(progression['score'], (int, float)):
                    continue

                # Name is required for explanations
                if 'name' not in progression:
                    progression['name'] = f"{category.capitalize()} tactic progression"

                # Description is optional but recommended
                if 'description' not in progression:
                    progression['description'] = progression['name']

    def score(self, findings: List[Finding]) -> Tuple[float, List[str]]:
        """
        Calculate score based on MITRE ATT&CK progressions AND single-tactic depth.
        
        Algorithm:
        1. Extract tactics with techniques (enhanced data structure)
        2. Calculate multi-tactic progression score (existing logic)
        3. Calculate single-tactic depth score (NEW)
        4. Use max(progression_score, depth_score) to avoid double-counting
        5. Generate combined explanations
        
        Args:
            findings: List of Finding objects to analyze
            
        Returns:
            Tuple of (score: 0-100, explanations: list of strings)
        """
        if not findings:
            return 0.0, ["No findings to analyze for MITRE kill chain"]
        
        # Extract tactics with technique details (ENHANCED)
        tactics_dict = self._extract_tactics_with_techniques(findings)
        
        if not tactics_dict:
            return 0.0, ["No valid MITRE tactic IDs found in findings"]
        
        # Calculate multi-tactic progression score (EXISTING LOGIC)
        tactics_set = set(tactics_dict.keys())
        progression_score = 0.0
        progression_explanations = []
        
        # Check progressions (existing logic - unchanged)
        for progression in self.critical_progressions:
            if self._is_valid_progression(progression):
                if self._progression_matches(progression, tactics_set):
                    progression_score = max(progression_score, progression['score'])
                    explanation = self._generate_explanation(progression, tactics_set, 'CRITICAL')
                    progression_explanations.append(explanation)
        
        for progression in self.high_progressions:
            if self._is_valid_progression(progression):
                if self._progression_matches(progression, tactics_set):
                    progression_score = max(progression_score, progression['score'])
                    explanation = self._generate_explanation(progression, tactics_set, 'HIGH')
                    progression_explanations.append(explanation)
        
        for progression in self.medium_progressions:
            if self._is_valid_progression(progression):
                if self._progression_matches(progression, tactics_set):
                    progression_score = max(progression_score, progression['score'])
                    explanation = self._generate_explanation(progression, tactics_set, 'MEDIUM')
                    progression_explanations.append(explanation)
        
        # Calculate single-tactic depth score (NEW)
        depth_score = self._score_single_tactic_depth(tactics_dict)
        depth_explanations = []
        
        if depth_score > 0:
            # Find which tactic has max techniques
            max_tactic = max(tactics_dict.items(), key=lambda x: len(x[1]))
            tactic_id, techniques = max_tactic
            depth_explanations.append(
                f"[DEPTH] {len(techniques)} techniques in {tactic_id}: "
                f"{', '.join(techniques)} (Score: {depth_score:.0f})"
            )
        
        # Use max to avoid double-counting
        final_score = max(progression_score, depth_score)
        
        # Combine explanations
        explanations = []
        if progression_score > 0:
            explanations.extend(progression_explanations)
        if depth_score > 0:
            explanations.extend(depth_explanations)
        
        if not explanations:
            return 0.0, ["No MITRE kill chain progressions or depth detected"]
        
        # Add summary
        summary = (
            f"MITRE kill chain score: {final_score:.1f}/100 "
            f"(Progression: {progression_score:.0f}, Depth: {depth_score:.0f})"
        )
        explanations.insert(0, summary)
        
        return self.validate_score(final_score), explanations

    def _extract_tactics(self, findings: List[Finding]) -> Set[str]:
        """
        Extract MITRE tactic IDs from findings by mapping techniques to tactics.

        Reads mitre_technique from the Finding object's mitre_technique attribute
        and maps it to the corresponding MITRE tactic using the TECHNIQUE_TO_TACTIC
        mapping. Handles sub-techniques by falling back to parent technique if
        sub-technique is not in mapping.

        Args:
            findings: List of Finding objects

        Returns:
            Set of MITRE tactic ID strings (e.g., {'TA0001', 'TA0002'})
        
        Examples:
            >>> finding = Finding(mitre_technique='T1027', ...)
            >>> tactics = scorer._extract_tactics([finding])
            >>> 'TA0005' in tactics  # Defense Evasion
            True
        """
        tactics = set()
        for finding in findings:
            # Get mitre_technique from Finding attribute (not metadata)
            technique = finding.mitre_technique
            if technique and isinstance(technique, str):
                # Try direct lookup first
                if technique in TECHNIQUE_TO_TACTIC:
                    tactic = TECHNIQUE_TO_TACTIC[technique]
                    tactics.add(tactic)
                # Handle sub-techniques by trying parent technique
                elif '.' in technique:
                    parent_technique = technique.split('.')[0]
                    if parent_technique in TECHNIQUE_TO_TACTIC:
                        tactic = TECHNIQUE_TO_TACTIC[parent_technique]
                        tactics.add(tactic)
                    else:
                        logger.warning(
                            f"Unmapped MITRE technique (parent): {parent_technique} "
                            f"(from sub-technique: {technique})"
                        )
                else:
                    logger.warning(f"Unmapped MITRE technique: {technique}")
        return tactics

    def _extract_tactics_with_techniques(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """
        Extract MITRE tactics with their associated techniques from findings.
        
        Maps each finding's MITRE technique to its tactic, building a dictionary
        that groups techniques by tactic. Handles sub-techniques by falling back
        to parent technique if sub-technique is not in mapping.
        
        Args:
            findings: List of Finding objects with mitre_technique attributes
            
        Returns:
            Dictionary mapping tactic IDs to lists of technique IDs
            Example: {
                'TA0005': ['T1027', 'T1027.009', 'T1140'],  # Defense Evasion
                'TA0002': ['T1059']                          # Execution
            }
            
        Examples:
            >>> finding1 = Finding(mitre_technique='T1027', ...)
            >>> finding2 = Finding(mitre_technique='T1027.009', ...)
            >>> tactics_dict = scorer._extract_tactics_with_techniques([finding1, finding2])
            >>> tactics_dict
            {'TA0005': ['T1027', 'T1027.009']}
        """
        from collections import defaultdict
        
        tactics_dict = defaultdict(list)
        
        for finding in findings:
            technique = finding.mitre_technique
            if not technique or not isinstance(technique, str):
                continue
                
            # Try direct lookup first
            if technique in TECHNIQUE_TO_TACTIC:
                tactic = TECHNIQUE_TO_TACTIC[technique]
                if technique not in tactics_dict[tactic]:  # Deduplicate
                    tactics_dict[tactic].append(technique)
            # Handle sub-techniques by trying parent technique
            elif '.' in technique:
                parent_technique = technique.split('.')[0]
                if parent_technique in TECHNIQUE_TO_TACTIC:
                    tactic = TECHNIQUE_TO_TACTIC[parent_technique]
                    if technique not in tactics_dict[tactic]:  # Deduplicate
                        tactics_dict[tactic].append(technique)
                else:
                    logger.warning(
                        f"Unmapped MITRE technique (parent): {parent_technique} "
                        f"(from sub-technique: {technique})"
                    )
            else:
                logger.warning(f"Unmapped MITRE technique: {technique}")
        
        return dict(tactics_dict)  # Convert defaultdict to regular dict

    def _score_single_tactic_depth(self, tactics_dict: Dict[str, List[str]]) -> float:
        """
        Score based on technique depth within a single tactic.
        
        Multiple techniques in the same tactic indicate sophisticated attack
        methodology, even without multi-tactic progression. Awards points based
        on the maximum technique count across all tactics.
        
        Scoring Tiers:
        - 5+ techniques in one tactic: 20 points (Very Sophisticated)
        - 3-4 techniques in one tactic: 15 points (Sophisticated)
        - 2 techniques in one tactic: 10 points (Moderate)
        - 1 technique: 0 points (No bonus)
        
        Args:
            tactics_dict: Dictionary mapping tactic IDs to technique lists
            
        Returns:
            Score from 0-20 based on maximum technique depth
            
        Examples:
            >>> tactics = {'TA0005': ['T1027', 'T1027.009', 'T1140']}
            >>> score = scorer._score_single_tactic_depth(tactics)
            >>> score
            15.0  # 3 techniques = Sophisticated
            
            >>> tactics = {'TA0005': ['T1027'], 'TA0002': ['T1059']}
            >>> score = scorer._score_single_tactic_depth(tactics)
            >>> score
            0.0  # Only 1 technique per tactic = No bonus
        """
        if not tactics_dict:
            return 0.0
        
        # Find maximum technique count across all tactics
        max_techniques = max(len(techniques) for techniques in tactics_dict.values())
        
        # Apply scoring tiers
        if max_techniques >= 5:
            return 20.0  # Very sophisticated
        elif max_techniques >= 3:
            return 15.0  # Sophisticated
        elif max_techniques >= 2:
            return 10.0  # Moderate
        else:
            return 0.0   # Single technique (no bonus)

    def _is_valid_progression(self, progression: Dict[str, Any]) -> bool:
        """
        Check if a progression has valid structure.

        Args:
            progression: Progression dictionary

        Returns:
            True if progression has required fields, False otherwise
        """
        if not isinstance(progression, dict):
            return False

        # Must have tactics (can be None for "any N tactics" rule)
        if 'tactics' not in progression:
            return False

        # If tactics is None, must have min_tactics
        if progression['tactics'] is None:
            if 'min_tactics' not in progression or not isinstance(progression['min_tactics'], int):
                return False
            if progression['min_tactics'] < 1:
                return False
        # If tactics is a list, must not be empty
        elif isinstance(progression['tactics'], list):
            if not progression['tactics']:
                return False
        else:
            # tactics must be either None or a list
            return False

        # Must have score
        if 'score' not in progression or not isinstance(progression['score'], (int, float)):
            return False

        # Must have name
        if 'name' not in progression:
            return False

        return True

    def _progression_matches(self, progression: Dict[str, Any], tactics: Set[str]) -> bool:
        """
        Check if a progression matches the detected tactics.

        For "any N tactics" rules (tactics: None), checks if len(tactics) >= min_tactics.
        For specific tactic lists, checks if ALL tactics in progression are present.

        Args:
            progression: Progression dictionary with 'tactics' and optional 'min_tactics'
            tactics: Set of MITRE tactic IDs from findings

        Returns:
            True if progression matches, False otherwise
        """
        if progression['tactics'] is None:
            # Special "any N tactics" rule
            min_tactics = progression['min_tactics']
            return len(tactics) >= min_tactics
        else:
            # Specific tactic list - all must be present
            progression_tactics = progression['tactics']
            return all(tactic in tactics for tactic in progression_tactics)

    def _generate_explanation(
        self,
        progression: Dict[str, Any],
        tactics: Set[str],
        severity: str
    ) -> str:
        """
        Generate explanation for a matched progression.

        For "any N tactics" rules, includes the actual tactic count.
        For specific progressions, uses the progression name.

        Args:
            progression: Matched progression dictionary
            tactics: Set of detected MITRE tactic IDs
            severity: Severity level ('CRITICAL', 'HIGH', 'MEDIUM')

        Returns:
            Formatted explanation string
        """
        name = progression['name']

        if progression['tactics'] is None:
            # "any N tactics" rule - include count
            return f"[{severity}] {name}: {len(tactics)} tactics detected"
        else:
            # Specific progression
            return f"[{severity}] {name}"
