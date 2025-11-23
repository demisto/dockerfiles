# sentinel/analyzer.py

"""
Main analysis orchestrator for Script Sentinel.

This module coordinates the analysis pipeline, integrating parsing,
heuristic pattern matching, and (future) LLM-based semantic analysis
to produce comprehensive security assessments.
"""

import logging
import asyncio
import time
from typing import Optional, Dict, Any
from pathlib import Path

from .models import AnalysisResult, Finding, Verdict
from .parser import parse
from .heuristics import HeuristicEngine
from .obfuscation import detect_obfuscation
from .ioc_extractor import IOCExtractor
from .mitre import MITREMapper
from .adk_agent import analyze_with_adk
from .verdict import calculate_verdict
from .extractor import ScriptExtractor, ExtractedScript

logger = logging.getLogger(__name__)


class ScriptAnalyzer:
    """
    Main analyzer that orchestrates the complete analysis pipeline.
    
    The analyzer:
    1. Parses scripts into AST
    2. Runs heuristic pattern matching
    3. (Future) Runs LLM semantic analysis
    4. Generates overall verdict and confidence score
    
    Attributes:
        heuristic_engine: HeuristicEngine instance for pattern matching.
        patterns_loaded: Whether patterns have been loaded.
        
    Examples:
        >>> analyzer = ScriptAnalyzer()
        >>> analyzer.load_patterns('sentinel/patterns')
        >>> result = analyzer.analyze(script_content, 'powershell')
        >>> print(f"Verdict: {result.verdict.value}")
    """
    
    def __init__(self, patterns_dir: Optional[str | Path] = None):
        """
        Initializes the script analyzer.
        
        Args:
            patterns_dir: Directory containing pattern files (optional).
                         If not provided, patterns must be loaded explicitly.
        """
        self.heuristic_engine = HeuristicEngine()
        self.ioc_extractor = IOCExtractor()
        self.script_extractor = ScriptExtractor()
        self.patterns_loaded = False
        
        # Initialize MITRE mapper with data directory
        data_dir = Path(__file__).parent / 'data'
        try:
            self.mitre_mapper = MITREMapper(data_dir)
            logger.info("MITRE ATT&CK mapper initialized")
        except (FileNotFoundError, ValueError) as e:
            logger.warning(f"MITRE mapper initialization failed: {e}")
            self.mitre_mapper = None
        
        if patterns_dir:
            self.load_patterns(patterns_dir)
        
        logger.info("Script analyzer initialized")
    
    def load_patterns(self, patterns_dir: str | Path) -> tuple[int, list[str]]:
        """
        Loads patterns from directory into the heuristic engine.
        
        Args:
            patterns_dir: Path to directory containing pattern YAML files.
            
        Returns:
            Tuple of (number_of_patterns_loaded, list_of_errors).
        """
        count, errors = self.heuristic_engine.load_patterns(patterns_dir)
        self.patterns_loaded = count > 0
        
        if self.patterns_loaded:
            logger.info(f"Loaded {count} patterns for analysis")
        else:
            logger.error("Failed to load any patterns")
        
        return count, errors
    
    def analyze(
        self,
        script_content: str,
        language: str,
        include_llm: bool = False,
        paranoia_level: int = 1,
        file_type: Optional[str] = None,
        llm_model: str = 'flash'
    ) -> tuple[Optional[AnalysisResult], Optional[str]]:
        """
        Analyzes a script and returns comprehensive security assessment.
        
        Args:
            script_content: The script content to analyze.
            language: Script language ('powershell', 'bash', 'javascript') or container type ('html', 'xml', 'sct').
            include_llm: Whether to include LLM semantic analysis.
            paranoia_level: Analysis sensitivity level (1=Balanced, 2=Aggressive, 3=Maximum).
            file_type: Optional file type hint for embedded script extraction ('html', 'xml', 'sct').
            llm_model: Gemini model to use for LLM analysis ('flash', 'pro', or 'flash-thinking').
                      Default is 'flash' for speed and cost-effectiveness.
            
        Returns:
            Tuple of (AnalysisResult, error_message).
            On success: (AnalysisResult, None)
            On failure: (None, error_message)
            
        Examples:
            >>> analyzer = ScriptAnalyzer('sentinel/patterns')
            >>> # Use default Flash model
            >>> result, error = analyzer.analyze(script_content, 'powershell', include_llm=True)
            >>> # Use Pro model for deeper analysis
            >>> result, error = analyzer.analyze(script_content, 'powershell', include_llm=True, llm_model='pro')
            >>> if result:
            ...     print(f"Found {len(result.findings)} issues")
        """
        # Start timing for overall analysis
        analysis_start_time = time.time()
        
        try:
            # Validate inputs
            if not script_content or not script_content.strip():
                return None, "Empty script content provided"
            
            if not language:
                return None, "Language not specified"
            
            # Preprocess script content: remove null bytes and other control characters
            # that can break pattern matching while preserving legitimate content
            original_size = len(script_content)
            script_content = script_content.replace('\x00', '')  # Remove null bytes
            if len(script_content) != original_size:
                logger.info(f"Removed {original_size - len(script_content)} null bytes from script")
            
            # Normalize language
            language = language.lower()
            valid_languages = {'powershell', 'bash', 'javascript'}
            container_types = {'html', 'xml', 'sct'}
            
            # Check if this is a container file that needs script extraction
            if language in container_types or file_type in container_types:
                return self._analyze_embedded(
                    script_content,
                    file_type or language,
                    include_llm,
                    paranoia_level,
                    llm_model
                )
            
            if language not in valid_languages:
                return None, f"Unsupported language: {language}. Must be one of {valid_languages} or {container_types}"
            
            # Check patterns are loaded
            if not self.patterns_loaded:
                logger.warning("No patterns loaded - analysis will have limited effectiveness")
            
            # Step 1: Parse script into AST
            logger.info(f"Parsing {language} script ({len(script_content)} bytes)")
            ast, parse_error = parse(script_content, language)
            
            # Enable fallback mode for unparseable scripts
            fallback_mode = False
            if parse_error or not ast:
                logger.warning(f"Parser failed: {parse_error or 'Empty AST'}")
                logger.info("Enabling fallback mode: regex-only pattern matching")
                fallback_mode = True
                # Create minimal AST for fallback mode
                ast = {'type': 'fallback', 'children': []}
            
            # Step 2: Run heuristic pattern matching
            logger.info("Running heuristic pattern matching")
            heuristic_start_time = time.time()
            heuristic_findings = []
            
            if self.patterns_loaded:
                heuristic_findings = self.heuristic_engine.match_patterns(
                    ast,
                    language,
                    script_content,
                    paranoia_level
                )
                logger.info(f"Heuristic analysis found {len(heuristic_findings)} findings (paranoia level: {paranoia_level})")
            
            heuristic_duration = time.time() - heuristic_start_time
            
            # Step 2.5: Run obfuscation detection
            logger.info("Running obfuscation detection")
            obfuscation_start_time = time.time()
            obfuscation_findings = detect_obfuscation(script_content, language, ast)
            logger.info(f"Obfuscation detection found {len(obfuscation_findings)} findings")
            obfuscation_duration = time.time() - obfuscation_start_time
            obfuscation_detected = len(obfuscation_findings) > 0
            
            # Combine heuristic and obfuscation findings
            heuristic_findings.extend(obfuscation_findings)
            
            # Step 2.75: Extract IOCs from script content
            logger.info("Extracting Indicators of Compromise (IOCs)")
            ioc_start_time = time.time()
            iocs = self.ioc_extractor.extract(script_content, language, heuristic_findings)
            ioc_duration = time.time() - ioc_start_time
            
            # Count total IOCs
            total_iocs = sum(len(ioc_list) for ioc_list in iocs.values())
            logger.info(f"IOC extraction found {total_iocs} IOCs across {len(iocs)} types")
            
            # Step 2.8: Map findings to MITRE ATT&CK techniques
            mitre_techniques = {}
            mitre_duration = 0.0
            
            if self.mitre_mapper:
                logger.info("Mapping findings to MITRE ATT&CK techniques")
                mitre_start_time = time.time()
                mitre_techniques = self.mitre_mapper.map_findings(heuristic_findings)
                mitre_duration = time.time() - mitre_start_time
                
                total_techniques = len(mitre_techniques)
                logger.info(f"MITRE mapping found {total_techniques} unique techniques")
            else:
                logger.warning("MITRE mapper not available - skipping technique mapping")
            
            # Step 3: Run LLM semantic analysis (if enabled)
            llm_findings = []
            llm_available = False
            llm_error = None
            llm_duration = 0.0
            
            if include_llm:
                logger.info("Running LLM semantic analysis with ADK")
                llm_start_time = time.time()
                try:
                    # Run ADK analysis asynchronously
                    llm_findings_result, adk_error = asyncio.run(
                        analyze_with_adk(
                            script_content=script_content,
                            language=language,
                            ast=ast,
                            heuristic_findings=heuristic_findings,
                            model=llm_model
                        )
                    )
                    
                    if llm_findings_result is not None:
                        llm_findings = llm_findings_result
                        llm_available = True
                        logger.info(f"LLM analysis complete: {len(llm_findings)} findings")
                    else:
                        llm_error = adk_error
                        logger.warning(f"LLM analysis unavailable: {adk_error}")
                        logger.info("Falling back to heuristics-only mode")
                        
                except Exception as e:
                    llm_error = str(e)
                    logger.error(f"LLM analysis failed: {e}", exc_info=True)
                    logger.info("Falling back to heuristics-only mode")
                
                llm_duration = time.time() - llm_start_time
            
            # Step 4: Generate overall verdict and confidence using verdict module
            logger.info("Calculating final verdict and confidence score")
            verdict_start_time = time.time()
            
            # Combine all findings for verdict calculation
            all_findings = heuristic_findings + llm_findings
            
            verdict, confidence = calculate_verdict(
                findings=all_findings,
                llm_available=llm_available,
                obfuscation_detected=obfuscation_detected,
                paranoia_level=paranoia_level
            )
            
            verdict_duration = time.time() - verdict_start_time
            
            # Calculate total analysis time
            analysis_duration = time.time() - analysis_start_time
            
            # Calculate script metrics
            script_lines = script_content.count('\n') + 1
            script_bytes = len(script_content.encode('utf-8'))
            
            # Get severity distribution for metadata
            from .verdict import get_severity_distribution
            severity_dist = get_severity_distribution(all_findings)
            
            # Create analysis result with comprehensive metadata
            result = AnalysisResult(
                verdict=verdict,
                confidence_score=confidence,
                findings=all_findings,
                heuristic_findings=heuristic_findings,
                llm_findings=llm_findings,
                iocs=iocs,
                mitre_techniques=mitre_techniques,
                metadata={
                    # Script information
                    'script_language': language,
                    'script_lines': script_lines,
                    'script_bytes': script_bytes,
                    'script_size': len(script_content),  # Kept for backward compatibility
                    
                    # Analysis timing
                    'analysis_time_seconds': round(analysis_duration, 3),
                    'heuristic_duration': round(heuristic_duration, 3),
                    'obfuscation_duration': round(obfuscation_duration, 3),
                    'ioc_duration': round(ioc_duration, 3),
                    'mitre_duration': round(mitre_duration, 3),
                    'llm_duration': round(llm_duration, 3),
                    'verdict_duration': round(verdict_duration, 3),
                    
                    # Finding counts
                    'total_findings': len(all_findings),
                    'heuristic_findings_count': len(heuristic_findings),
                    'obfuscation_findings_count': len(obfuscation_findings),
                    'llm_findings_count': len(llm_findings),
                    
                    # IOC counts
                    'total_iocs': total_iocs,
                    'ioc_types_found': len(iocs),
                    'iocs_by_type': {ioc_type: len(ioc_list) for ioc_type, ioc_list in iocs.items()},
                    
                    # MITRE ATT&CK counts
                    'total_mitre_techniques': len(mitre_techniques),
                    'mitre_techniques_by_tactic': self._group_techniques_by_tactic(mitre_techniques),
                    
                    # Pattern matching info
                    'patterns_checked': self.heuristic_engine.registry.get_enabled_count(),
                    'pattern_matches': severity_dist,
                    
                    # Analysis mode
                    'paranoia_level': paranoia_level,
                    'obfuscation_detected': obfuscation_detected,
                    'llm_available': llm_available,
                    'llm_error': llm_error,
                    'parser_fallback_mode': fallback_mode,
                    'parse_error': parse_error if fallback_mode else None,
                    'llm_fallback_mode': include_llm and not llm_available
                }
            )
            
            logger.info(f"Analysis complete: {verdict.value} (confidence: {confidence:.2f}, "
                       f"time: {analysis_duration:.2f}s)")
            return result, None
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return None, error_msg
    
    def _analyze_embedded(
        self,
        content: str,
        file_type: str,
        include_llm: bool,
        paranoia_level: int,
        llm_model: str = 'flash'
    ) -> tuple[Optional[AnalysisResult], Optional[str]]:
        """
        Analyzes embedded scripts in HTML, XML, or SCT files.
        
        Args:
            content: Container file content.
            file_type: Type of container ('html', 'xml', 'sct').
            include_llm: Whether to include LLM semantic analysis.
            paranoia_level: Analysis sensitivity level.
            
        Returns:
            Tuple of (AnalysisResult, error_message).
        """
        logger.info(f"Analyzing embedded scripts in {file_type} file")
        
        # Extract scripts from container
        extracted_scripts = self.script_extractor.extract(content, file_type)
        
        if not extracted_scripts:
            return None, f"No scripts found in {file_type} file"
        
        logger.info(f"Extracted {len(extracted_scripts)} script(s) from {file_type} file")
        
        # Analyze each extracted script
        all_findings = []
        all_heuristic_findings = []
        all_llm_findings = []
        all_iocs = {}
        all_mitre_techniques = {}
        
        highest_verdict = Verdict.BENIGN
        total_confidence = 0.0
        analysis_errors = []
        
        for i, script in enumerate(extracted_scripts, 1):
            logger.info(f"Analyzing script {i}/{len(extracted_scripts)}: "
                       f"{script.language} (lines {script.line_start}-{script.line_end})")
            
            # Analyze the extracted script
            result, error = self.analyze(
                script.content,
                script.language,
                include_llm=include_llm,
                paranoia_level=paranoia_level,
                llm_model=llm_model
            )
            
            if error:
                logger.warning(f"Failed to analyze script {i}: {error}")
                analysis_errors.append(f"Script {i} ({script.context}): {error}")
                continue
            
            if not result:
                continue
            
            # Adjust finding line numbers to match original file
            for finding in result.findings:
                if hasattr(finding, 'line_number') and finding.line_number:
                    finding.line_number += script.line_start - 1
                # Add context about which embedded script this came from
                finding.description = f"[{script.context}] {finding.description}"
            
            # Aggregate results
            all_findings.extend(result.findings)
            all_heuristic_findings.extend(result.heuristic_findings)
            all_llm_findings.extend(result.llm_findings)
            
            # Merge IOCs
            for ioc_type, ioc_list in result.iocs.items():
                if ioc_type not in all_iocs:
                    all_iocs[ioc_type] = []
                all_iocs[ioc_type].extend(ioc_list)
            
            # Merge MITRE techniques
            all_mitre_techniques.update(result.mitre_techniques)
            
            # Track highest severity verdict
            if result.verdict.value > highest_verdict.value:
                highest_verdict = result.verdict
            
            total_confidence += result.confidence_score
        
        # If all scripts failed to analyze, return error
        if not all_findings and analysis_errors:
            return None, f"Failed to analyze embedded scripts: {'; '.join(analysis_errors)}"
        
        # Calculate aggregate confidence (average of all scripts)
        num_analyzed = len(extracted_scripts) - len(analysis_errors)
        aggregate_confidence = total_confidence / num_analyzed if num_analyzed > 0 else 0.0
        
        # Use the highest verdict found across all scripts
        final_verdict = highest_verdict
        
        # Get severity distribution
        from .verdict import get_severity_distribution
        severity_dist = get_severity_distribution(all_findings)
        
        # Create aggregate result
        result = AnalysisResult(
            verdict=final_verdict,
            confidence_score=aggregate_confidence,
            findings=all_findings,
            heuristic_findings=all_heuristic_findings,
            llm_findings=all_llm_findings,
            iocs=all_iocs,
            mitre_techniques=all_mitre_techniques,
            metadata={
                'file_type': file_type,
                'embedded_scripts_count': len(extracted_scripts),
                'scripts_analyzed': num_analyzed,
                'scripts_failed': len(analysis_errors),
                'analysis_errors': analysis_errors,
                'total_findings': len(all_findings),
                'heuristic_findings_count': len(all_heuristic_findings),
                'llm_findings_count': len(all_llm_findings),
                'total_iocs': sum(len(ioc_list) for ioc_list in all_iocs.values()),
                'total_mitre_techniques': len(all_mitre_techniques),
                'pattern_matches': severity_dist,
                'paranoia_level': paranoia_level,
                'embedded_analysis': True
            }
        )
        
        logger.info(f"Embedded script analysis complete: {final_verdict.value} "
                   f"(confidence: {aggregate_confidence:.2f}, "
                   f"{num_analyzed}/{len(extracted_scripts)} scripts analyzed)")
        
        return result, None
    
    def _group_techniques_by_tactic(self, mitre_techniques: dict) -> Dict[str, int]:
        """
        Groups MITRE techniques by tactic for metadata.
        
        Args:
            mitre_techniques: Dictionary of MITRETechnique objects.
            
        Returns:
            Dictionary mapping tactic names to technique counts.
        """
        tactic_counts = {}
        for technique in mitre_techniques.values():
            tactic = technique.tactic
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        return tactic_counts
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Returns statistics about the analyzer.
        
        Returns:
            Dictionary with analyzer statistics.
        """
        stats = {
            'patterns_loaded': self.patterns_loaded,
            'heuristic_engine': self.heuristic_engine.get_statistics()
        }
        return stats


# Convenience function for one-off analysis
def analyze_script(
    script_content: str,
    language: str,
    patterns_dir: Optional[str | Path] = None
) -> tuple[Optional[AnalysisResult], Optional[str]]:
    """
    Convenience function to analyze a script without managing analyzer instance.
    
    Creates a ScriptAnalyzer, loads patterns, and performs analysis.
    For repeated use, create an analyzer instance and reuse it.
    
    Args:
        script_content: The script content to analyze.
        language: Script language ('powershell', 'bash', 'javascript').
        patterns_dir: Directory containing patterns (default: auto-detect).
        
    Returns:
        Tuple of (AnalysisResult, error_message).
        
    Examples:
        >>> result, error = analyze_script(script_content, 'powershell')
        >>> if result:
        ...     print(f"Verdict: {result.verdict.value}")
    """
    # Auto-detect patterns directory if not provided
    if patterns_dir is None:
        current_file = Path(__file__)
        patterns_dir = current_file.parent / 'patterns'
    
    analyzer = ScriptAnalyzer(patterns_dir)
    return analyzer.analyze(script_content, language)
