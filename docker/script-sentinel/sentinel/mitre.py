# sentinel/mitre.py

"""
MITRE ATT&CK technique mapper for Script Sentinel.

Maps security findings to MITRE ATT&CK techniques, providing enriched
threat intelligence context for analysis results.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from collections import defaultdict

from .models import Finding, MITRETechnique


class MITREMapper:
    """
    Maps security findings to MITRE ATT&CK techniques.
    
    Loads MITRE ATT&CK technique data and enriches findings with
    comprehensive threat intelligence including technique names,
    tactics, descriptions, and reference URLs.
    
    Attributes:
        techniques: Dictionary of MITRE technique data keyed by technique ID.
        
    Examples:
        >>> mapper = MITREMapper(Path('sentinel/data'))
        >>> findings = [finding1, finding2]  # Findings with mitre_technique field
        >>> mitre_techniques = mapper.map_findings(findings)
        >>> print(f"Mapped {len(mitre_techniques)} techniques")
    """
    
    def __init__(self, data_dir: Path):
        """
        Initializes the MITRE mapper with technique data.
        
        Args:
            data_dir: Directory containing mitre_attack.json data file.
            
        Raises:
            FileNotFoundError: If MITRE data file is not found.
            ValueError: If MITRE data file is invalid.
        """
        self.techniques: Dict[str, dict] = {}
        self._load_techniques(data_dir)
    
    def _load_techniques(self, data_dir: Path) -> None:
        """
        Loads MITRE ATT&CK technique data from JSON file.
        
        Args:
            data_dir: Directory containing mitre_attack.json.
            
        Raises:
            FileNotFoundError: If data file not found.
            ValueError: If data file is invalid JSON.
        """
        data_file = data_dir / 'mitre_attack.json'
        
        if not data_file.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK data file not found: {data_file}. "
                f"Please ensure sentinel/data/mitre_attack.json exists."
            )
        
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)
            
            # Extract techniques dictionary
            self.techniques = data.get('techniques', {})
            
            if not self.techniques:
                raise ValueError("No techniques found in MITRE data file")
                
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in MITRE data file: {e}")
    
    def map_findings(self, findings: List[Finding]) -> Dict[str, MITRETechnique]:
        """
        Maps findings to MITRE ATT&CK techniques with enriched details.
        
        Aggregates findings by technique ID, calculates confidence scores,
        and enriches with technique metadata from the MITRE ATT&CK framework.
        
        Args:
            findings: List of findings with mitre_technique field populated.
            
        Returns:
            Dictionary mapping technique IDs to MITRETechnique objects.
            
        Examples:
            >>> findings = [
            ...     Finding(..., mitre_technique='T1059.001', confidence=0.9),
            ...     Finding(..., mitre_technique='T1059.001', confidence=0.8),
            ...     Finding(..., mitre_technique='T1140', confidence=0.7)
            ... ]
            >>> techniques = mapper.map_findings(findings)
            >>> print(techniques['T1059.001'].finding_count)  # 2
            >>> print(techniques['T1059.001'].confidence)  # 0.85 (average)
        """
        # Group findings by technique ID
        technique_findings: Dict[str, List[Finding]] = defaultdict(list)
        
        for finding in findings:
            if finding.mitre_technique:
                technique_findings[finding.mitre_technique].append(finding)
        
        # Create MITRETechnique objects with enriched data
        mitre_techniques: Dict[str, MITRETechnique] = {}
        
        for technique_id, tech_findings in technique_findings.items():
            # Get technique details from loaded data
            technique_data = self.techniques.get(technique_id)
            
            if not technique_data:
                # Technique not in our data - use basic info from finding
                technique_name = technique_id
                tactic = "Unknown"
                description = f"MITRE ATT&CK technique {technique_id}"
                url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
            else:
                technique_name = technique_data.get('name', technique_id)
                # Get first tactic if multiple
                tactic_list = technique_data.get('tactic', ['Unknown'])
                tactic = tactic_list[0] if isinstance(tactic_list, list) else tactic_list
                description = technique_data.get('description', '')
                url = technique_data.get('url', '')
            
            # Calculate aggregated confidence (average of all findings)
            confidences = [f.confidence for f in tech_findings]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
            
            # Create MITRETechnique object
            mitre_techniques[technique_id] = MITRETechnique(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                description=description,
                confidence=round(avg_confidence, 2),
                finding_count=len(tech_findings),
                url=url
            )
        
        return mitre_techniques
    
    def get_technique_info(self, technique_id: str) -> Optional[dict]:
        """
        Retrieves detailed information for a specific MITRE technique.
        
        Args:
            technique_id: MITRE technique ID (e.g., 'T1059.001').
            
        Returns:
            Dictionary with technique details, or None if not found.
            
        Examples:
            >>> info = mapper.get_technique_info('T1059.001')
            >>> print(info['name'])  # 'PowerShell'
            >>> print(info['tactic'])  # ['Execution']
        """
        return self.techniques.get(technique_id)
    
    def get_all_technique_ids(self) -> List[str]:
        """
        Returns list of all available MITRE technique IDs.
        
        Returns:
            List of technique IDs.
            
        Examples:
            >>> ids = mapper.get_all_technique_ids()
            >>> print(len(ids))  # 15
            >>> print('T1059.001' in ids)  # True
        """
        return list(self.techniques.keys())