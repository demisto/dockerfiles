#!/usr/bin/env python3
"""
Script Sentinel - XSIAM/XSOAR Automation Script

This script integrates Script Sentinel malware analysis into XSIAM/XSOAR,
using the Demisto Class API for proper platform integration.

Analyzes PowerShell, Bash, and JavaScript scripts for malicious patterns,
providing XDR-enriched output with IOCs, MITRE ATT&CK mapping, and threat scoring.

IMPORTANT: This script is designed to run within the XSIAM/XSOAR platform.
The following functions are provided by the Demisto API at runtime:
- demisto.args() - Get script arguments
- demisto.getFilePath() - Retrieve uploaded files
- return_error() - Return error to War Room
- return_results() - Return results to War Room
- entryTypes - Entry type constants
- formats - Format constants

For standalone testing, these functions need to be mocked.
"""

# Standard library imports
import json
import hashlib
import base64
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import re

# Note: demisto, return_error, return_results, entryTypes, and formats
# are injected by the XSIAM/XSOAR platform at runtime


def clean_code_snippet(snippet: str) -> str:
    """
    Clean code snippet by removing comment lines, prefixes, and extra whitespace.
    
    Args:
        snippet: Raw code snippet that may contain comments and prefixes
        
    Returns:
        Cleaned code snippet with comments and prefixes removed
    """
    if not snippet:
        return snippet
    
    lines = snippet.split('\n')
    cleaned_lines = []
    
    for line in lines:
        stripped = line.strip()
        # Skip empty lines and comment-only lines
        if not stripped or stripped.startswith('#'):
            continue
        
        # Remove common prefixes like >>>, ..., etc.
        prefixes_to_remove = ['>>> ', '... ', '> ', '$ ']
        for prefix in prefixes_to_remove:
            if stripped.startswith(prefix):
                stripped = stripped[len(prefix):]
                break
        
        cleaned_lines.append(stripped)
    
    return '\n'.join(cleaned_lines).strip()


def calculate_hash(content: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of script content."""
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(content.encode('utf-8'))
    return hash_obj.hexdigest()


def calculate_threat_score(verdict: str, confidence: float, findings_count: int, 
                          high_severity_count: int) -> int:
    """
    Calculate XSIAM threat score (0-100) based on analysis results.
    
    Args:
        verdict: Analysis verdict (malicious, suspicious, benign, unknown)
        confidence: Confidence score (0.0-1.0)
        findings_count: Total number of findings
        high_severity_count: Number of high/critical severity findings
        
    Returns:
        Threat score from 0-100
    """
    verdict_scores = {
        'malicious': 90,
        'suspicious': 60,
        'benign': 10,
        'unknown': 30
    }
    base_score = verdict_scores.get(verdict.lower(), 30)
    
    # Adjust by confidence
    score = base_score * confidence
    
    # Boost for high severity findings
    severity_boost = min(high_severity_count * 5, 20)
    score = min(score + severity_boost, 100)
    
    # Ensure minimum score for any findings
    if findings_count > 0 and score < 20:
        score = 20
    
    return int(score)


def count_by_severity(findings: List[Dict], severity: str) -> int:
    """Count findings by severity level."""
    return sum(1 for f in findings if f.get('severity', '').lower() == severity.lower())


def format_iocs_for_xdr(iocs_dict: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Format IOCs from Script Sentinel for XSIAM XDR correlation.
    
    Args:
        iocs_dict: Dictionary of IOC types to lists of IOC objects
                   Each IOC object has: type, value, confidence, line_number
        
    Returns:
        List of XDR-formatted IOC objects
    """
    xdr_iocs = []
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Map IOC types to XDR categories
    type_mapping = {
        'ip': ('IP', 'Network'),
        'domain': ('Domain', 'Network'),
        'url': ('URL', 'Network'),
        'file_path': ('FilePath', 'FileSystem')
    }
    
    # IP addresses
    for ioc in iocs_dict.get('ips', []):
        if isinstance(ioc, dict):
            confidence_pct = int(ioc.get('confidence', 0.8) * 100)
            xdr_iocs.append({
                'Type': 'IP',
                'Value': ioc.get('value', ''),
                'Source': 'Script Sentinel',
                'Confidence': f"{confidence_pct}%",
                'FirstSeen': timestamp,
                'Category': 'Network',
                'LineNumber': ioc.get('line_number')
            })
        else:
            # Fallback for string values
            xdr_iocs.append({
                'Type': 'IP',
                'Value': ioc,
                'Source': 'Script Sentinel',
                'Confidence': 'High',
                'FirstSeen': timestamp,
                'Category': 'Network'
            })
    
    # Domains
    for ioc in iocs_dict.get('domains', []):
        if isinstance(ioc, dict):
            confidence_pct = int(ioc.get('confidence', 0.8) * 100)
            xdr_iocs.append({
                'Type': 'Domain',
                'Value': ioc.get('value', ''),
                'Source': 'Script Sentinel',
                'Confidence': f"{confidence_pct}%",
                'FirstSeen': timestamp,
                'Category': 'Network',
                'LineNumber': ioc.get('line_number')
            })
        else:
            xdr_iocs.append({
                'Type': 'Domain',
                'Value': ioc,
                'Source': 'Script Sentinel',
                'Confidence': 'High',
                'FirstSeen': timestamp,
                'Category': 'Network'
            })
    
    # URLs
    for ioc in iocs_dict.get('urls', []):
        if isinstance(ioc, dict):
            confidence_pct = int(ioc.get('confidence', 0.8) * 100)
            xdr_iocs.append({
                'Type': 'URL',
                'Value': ioc.get('value', ''),
                'Source': 'Script Sentinel',
                'Confidence': f"{confidence_pct}%",
                'FirstSeen': timestamp,
                'Category': 'Network',
                'LineNumber': ioc.get('line_number')
            })
        else:
            xdr_iocs.append({
                'Type': 'URL',
                'Value': ioc,
                'Source': 'Script Sentinel',
                'Confidence': 'High',
                'FirstSeen': timestamp,
                'Category': 'Network'
            })
    
    # File paths
    for ioc in iocs_dict.get('file_paths', []):
        if isinstance(ioc, dict):
            confidence_pct = int(ioc.get('confidence', 0.6) * 100)
            xdr_iocs.append({
                'Type': 'FilePath',
                'Value': ioc.get('value', ''),
                'Source': 'Script Sentinel',
                'Confidence': f"{confidence_pct}%",
                'FirstSeen': timestamp,
                'Category': 'FileSystem',
                'LineNumber': ioc.get('line_number')
            })
        else:
            xdr_iocs.append({
                'Type': 'FilePath',
                'Value': ioc,
                'Source': 'Script Sentinel',
                'Confidence': 'Medium',
                'FirstSeen': timestamp,
                'Category': 'FileSystem'
            })
    
    return xdr_iocs


def run_sentinel_analysis(script_path: str, paranoia_level: int = 1, 
                         include_llm: bool = False) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Run Script Sentinel analysis using the existing CLI.
    
    Args:
        script_path: Path to script file to analyze
        paranoia_level: Analysis sensitivity (1-3)
        include_llm: Whether to use LLM analysis
        
    Returns:
        Tuple of (analysis_result_dict, error_message)
    """
    try:
        # Build command
        cmd = [
            'python3', '-m', 'sentinel.main',
            'analyze', script_path,
            '-f', 'json',  # Force JSON output
            '--paranoia-level', str(paranoia_level)
        ]
        
        if include_llm:
            cmd.append('--enable-llm')
        
        # Execute Script Sentinel CLI
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode != 0:
            return None, f"Script Sentinel failed: {result.stderr}"
        
        # Parse JSON output
        try:
            stdout = result.stdout.strip()
            
            # Find the start of JSON (first '{' character)
            json_start = stdout.find('{')
            if json_start == -1:
                return None, f"No JSON found in output: {stdout[:200]}"
            
            # Extract JSON portion
            json_str = stdout[json_start:]
            
            analysis_result = json.loads(json_str)
            return analysis_result, None
        except json.JSONDecodeError as e:
            return None, f"Failed to parse Script Sentinel output: {e}\nOutput: {result.stdout[:200]}"
            
    except subprocess.TimeoutExpired:
        return None, "Analysis timeout (5 minutes exceeded)"
    except Exception as e:
        return None, f"Execution error: {str(e)}"


def main():
    """Main entry point for XSIAM automation script."""
    try:
        # Get arguments from Demisto
        args = demisto.args()
        
        # Input methods (mutually exclusive)
        entry_id = args.get('entry_id')
        file_path = args.get('file_path')
        content_base64 = args.get('content_base64')
        content = args.get('content')
        
        # Analysis options
        paranoia_level = int(args.get('paranoia_level', 1))
        include_llm = args.get('include_llm', 'false').lower() == 'true'
        
        # Validate input
        if not any([entry_id, file_path, content_base64, content]):
            return_error('One of entry_id, file_path, content_base64, or content must be provided')
            return
        
        # Prepare script content and file
        script_content = None
        script_file = None
        temp_file = None
        original_filename = None
        
        if entry_id:
            # Retrieve file from War Room upload
            try:
                file_entry = demisto.getFilePath(entry_id)
                original_file = file_entry['path']
                original_filename = file_entry.get('name', 'unknown')
                
                # Read file content
                with open(original_file, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                # Preserve original file extension for Core Sentinel detection
                # Core Sentinel handles: .ps1, .sh, .js, .html, .xml, .sct, etc.
                file_suffix = Path(original_filename).suffix or '.txt'
                
                # Create temp file with ORIGINAL extension
                temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=file_suffix, delete=False)
                temp_file.write(script_content)
                temp_file.close()
                script_file = temp_file.name
                    
            except Exception as e:
                return_error(f'Failed to retrieve file from War Room (entry_id: {entry_id}): {e}')
                return
                
        elif file_path:
            # Use provided file path directly
            # Core Sentinel will detect language from extension
            script_file = file_path
            original_filename = Path(file_path).name
            with open(script_file, 'r', encoding='utf-8') as f:
                script_content = f.read()
                
        elif content_base64:
            # Decode base64 content
            try:
                script_content = base64.b64decode(content_base64).decode('utf-8')
            except Exception as e:
                return_error(f'Failed to decode base64 content: {e}')
                return
            
            # For base64 content, we need a filename hint
            # User should provide 'filename' argument for proper detection
            original_filename = args.get('filename', 'script.ps1')
            file_suffix = Path(original_filename).suffix or '.ps1'
            
            # Write to temp file with extension from filename hint
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=file_suffix, delete=False)
            temp_file.write(script_content)
            temp_file.close()
            script_file = temp_file.name
            
        elif content:
            # Use direct content
            script_content = content
            
            # For direct content, we need a filename hint
            # User should provide 'filename' argument for proper detection
            original_filename = args.get('filename', 'script.ps1')
            file_suffix = Path(original_filename).suffix or '.ps1'
            
            # Write to temp file with extension from filename hint
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=file_suffix, delete=False)
            temp_file.write(script_content)
            temp_file.close()
            script_file = temp_file.name
        
        # Run Script Sentinel analysis
        # Core Sentinel will:
        # 1. Detect language from file extension
        # 2. Handle embedded scripts (.html, .xml, .sct)
        # 3. Extract and analyze all embedded scripts
        # 4. Return comprehensive results
        analysis_result, error = run_sentinel_analysis(
            script_file,
            paranoia_level=paranoia_level,
            include_llm=include_llm
        )
        
        # Clean up temp file
        if temp_file:
            try:
                Path(temp_file.name).unlink()
            except:
                pass
        
        # Handle errors
        if error:
            return_error(f'Analysis failed: {error}')
            return
        
        # Calculate hashes
        script_hash_sha256 = calculate_hash(script_content, 'sha256')
        script_hash_md5 = calculate_hash(script_content, 'md5')
        
        # Extract key metrics
        verdict = analysis_result.get('verdict', 'unknown')
        confidence = analysis_result.get('confidence_score', 0.0)
        findings = analysis_result.get('findings', [])
        metadata = analysis_result.get('metadata', {})
        iocs_raw = analysis_result.get('iocs', [])
        mitre_techniques = analysis_result.get('mitre_techniques', {})
        
        # Parse IOCs from list format to grouped dictionary
        # Script Sentinel returns: [{'type': 'url', 'value': '...', 'confidence': 0.8, 'line_number': 5}, ...]
        # We need: {'urls': [{'value': '...', 'confidence': 0.8, 'line_number': 5}], ...}
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'file_paths': []
        }
        
        if isinstance(iocs_raw, list):
            for ioc_obj in iocs_raw:
                if isinstance(ioc_obj, dict):
                    ioc_type = ioc_obj.get('type', '').lower().replace(' ', '_')
                    
                    # Map various type formats to plural keys
                    type_map = {
                        'ip': 'ips',
                        'ipv4': 'ips',
                        'ipv6': 'ips',
                        'domain': 'domains',
                        'url': 'urls',
                        'file_path': 'file_paths',
                        'filepath': 'file_paths',
                        'path': 'file_paths'
                    }
                    
                    key = type_map.get(ioc_type)
                    if key:
                        iocs[key].append(ioc_obj)
        elif isinstance(iocs_raw, dict):
            # Already in dictionary format - normalize keys
            for key, value in iocs_raw.items():
                normalized_key = key.lower().replace(' ', '_')
                type_map = {
                    'ip': 'ips',
                    'ips': 'ips',
                    'ipv4': 'ips',
                    'ipv6': 'ips',
                    'domain': 'domains',
                    'domains': 'domains',
                    'url': 'urls',
                    'urls': 'urls',
                    'file_path': 'file_paths',
                    'file_paths': 'file_paths',
                    'filepath': 'file_paths',
                    'path': 'file_paths'
                }
                mapped_key = type_map.get(normalized_key, normalized_key)
                if mapped_key in iocs:
                    iocs[mapped_key] = value
        
        # Count findings by severity
        critical_count = count_by_severity(findings, 'Critical')
        high_count = count_by_severity(findings, 'High')
        medium_count = count_by_severity(findings, 'Medium')
        low_count = count_by_severity(findings, 'Low')
        
        # Calculate threat score
        threat_score = calculate_threat_score(
            verdict, 
            confidence, 
            len(findings),
            critical_count + high_count
        )
        
        # Map verdict to DBot score
        dbot_score_map = {
            'malicious': 3,
            'suspicious': 2,
            'benign': 1,
            'unknown': 0
        }
        dbot_score = dbot_score_map.get(verdict.lower(), 0)
        
        # Extract score breakdown for ML and scorer details
        score_breakdown = metadata.get('score_breakdown', {})
        scorer_scores = score_breakdown.get('scorer_scores', {})
        scorer_weights = score_breakdown.get('scorer_weights', {})
        explanations = score_breakdown.get('explanations', {})
        
        # Build XDR Context
        xdr_context = {
            'ScriptAnalysis': {
                'ScriptHash': script_hash_sha256,
                'ScriptHashMD5': script_hash_md5,
                'Verdict': verdict,
                'Confidence': confidence,
                'ThreatScore': threat_score,
                'Language': metadata.get('script_language', 'unknown'),
                'OriginalFilename': original_filename,
                'FileType': metadata.get('file_type'),  # 'html', 'xml', 'sct' for embedded
                'EmbeddedScripts': metadata.get('embedded_scripts_count', 0),
                'ScriptSize': metadata.get('script_bytes', 0),
                'ScriptLines': metadata.get('script_lines', 0),
                'MITRETechniques': list(mitre_techniques.keys()) if mitre_techniques else [],
                'MITRETactics': list(set(
                    tech.get('tactic', '') for tech in mitre_techniques.values()
                )) if mitre_techniques else [],
                'Findings': {
                    'Total': len(findings),
                    'Critical': critical_count,
                    'High': high_count,
                    'Medium': medium_count,
                    'Low': low_count
                },
                'IOCs': {
                    'Total': sum(len(ioc_list) for ioc_list in iocs.values()),
                    'IPs': len(iocs.get('ips', [])),
                    'Domains': len(iocs.get('domains', [])),
                    'URLs': len(iocs.get('urls', [])),
                    'FilePaths': len(iocs.get('file_paths', []))
                },
                'Timeline': {
                    'AnalysisTime': datetime.utcnow().isoformat() + 'Z',
                    'AnalysisDuration': metadata.get('analysis_time_seconds', 0)
                },
                'ScoringBreakdown': {
                    'Severity': {
                        'Score': scorer_scores.get('severity', 0),
                        'Weight': scorer_weights.get('severity', 0.30),
                        'Contribution': scorer_scores.get('severity', 0) * scorer_weights.get('severity', 0.30)
                    },
                    'Cooccurrence': {
                        'Score': scorer_scores.get('cooccurrence', 0),
                        'Weight': scorer_weights.get('cooccurrence', 0.20),
                        'Contribution': scorer_scores.get('cooccurrence', 0) * scorer_weights.get('cooccurrence', 0.20)
                    },
                    'KillChain': {
                        'Score': scorer_scores.get('killchain', 0),
                        'Weight': scorer_weights.get('killchain', 0.15),
                        'Contribution': scorer_scores.get('killchain', 0) * scorer_weights.get('killchain', 0.15)
                    },
                    'Content': {
                        'Score': scorer_scores.get('content', 0),
                        'Weight': scorer_weights.get('content', 0.10),
                        'Contribution': scorer_scores.get('content', 0) * scorer_weights.get('content', 0.10)
                    },
                    'YARA': {
                        'Score': scorer_scores.get('yara', 0),
                        'Weight': scorer_weights.get('yara', 0.15),
                        'Contribution': scorer_scores.get('yara', 0) * scorer_weights.get('yara', 0.15),
                        'Matches': analysis_result.get('yara_contribution', {}).get('matches', 0) if isinstance(analysis_result.get('yara_contribution'), dict) else 0
                    },
                    'ML': {
                        'Score': scorer_scores.get('ml', 0),
                        'Weight': scorer_weights.get('ml', 0.10),
                        'Contribution': scorer_scores.get('ml', 0) * scorer_weights.get('ml', 0.10),
                        'Enabled': scorer_scores.get('ml', 0) > 0
                    }
                }
            }
        }
        
        # Format IOCs for XDR
        xdr_iocs = format_iocs_for_xdr(iocs)
        
        # Build DBotScore
        dbot_score_entry = {
            'Indicator': script_hash_sha256,
            'Type': 'file',
            'Vendor': 'Script Sentinel',
            'Score': dbot_score,
            'Reliability': 'A - Completely reliable'
        }
        
        # Build File context
        file_context = {
            'SHA256': script_hash_sha256,
            'MD5': script_hash_md5,
            'Size': metadata.get('script_bytes', 0),
            'Type': metadata.get('script_language', 'unknown'),
            'Name': original_filename
        }
        
        if verdict in ['malicious', 'suspicious']:
            file_context['Malicious'] = {
                'Vendor': 'Script Sentinel',
                'Description': f"Verdict: {verdict} (Confidence: {confidence:.0%})",
                'Score': dbot_score
            }
        
        # Build human-readable output
        hr_output = f"""### Script Sentinel Analysis Results

**Verdict:** {verdict.upper()}
**Confidence:** {confidence:.0%}
**Threat Score:** {threat_score}/100

#### Script Information
- **Filename:** {original_filename}
- **Hash (SHA256):** {script_hash_sha256}
- **Hash (MD5):** {script_hash_md5}
- **Language:** {metadata.get('script_language', 'unknown')}
- **Size:** {metadata.get('script_bytes', 0)} bytes
- **Lines:** {metadata.get('script_lines', 0)}
"""
        
        # Add embedded script info if applicable
        if metadata.get('embedded_analysis'):
            embedded_count = metadata.get('embedded_scripts_count', 0)
            scripts_analyzed = metadata.get('scripts_analyzed', 0)
            hr_output += f"- **File Type:** {metadata.get('file_type', 'unknown').upper()} (container)\n"
            hr_output += f"- **Embedded Scripts:** {embedded_count} found, {scripts_analyzed} analyzed\n"
        
        hr_output += f"""
#### Findings Summary
- **Total Findings:** {len(findings)}
- **Critical:** {critical_count}
- **High:** {high_count}
- **Medium:** {medium_count}
- **Low:** {low_count}

#### Scoring Breakdown
"""
        
        # Add scorer breakdown if available
        if scorer_scores:
            hr_output += f"""- **Severity:** {scorer_scores.get('severity', 0):.1f} (weight: {scorer_weights.get('severity', 0.30):.0%})
- **Co-occurrence:** {scorer_scores.get('cooccurrence', 0):.1f} (weight: {scorer_weights.get('cooccurrence', 0.20):.0%})
- **Kill Chain:** {scorer_scores.get('killchain', 0):.1f} (weight: {scorer_weights.get('killchain', 0.15):.0%})
- **Content:** {scorer_scores.get('content', 0):.1f} (weight: {scorer_weights.get('content', 0.10):.0%})
- **YARA:** {scorer_scores.get('yara', 0):.1f} (weight: {scorer_weights.get('yara', 0.15):.0%})
- **ML:** {scorer_scores.get('ml', 0):.1f} (weight: {scorer_weights.get('ml', 0.10):.0%})
"""
        
        hr_output += f"""
#### IOCs Detected
- **Total IOCs:** {sum(len(ioc_list) for ioc_list in iocs.values())}
- **IP Addresses:** {len(iocs.get('ips', []))}
- **Domains:** {len(iocs.get('domains', []))}
- **URLs:** {len(iocs.get('urls', []))}
- **File Paths:** {len(iocs.get('file_paths', []))}
"""
        
        # Add extracted IOCs if any
        if iocs:
            has_iocs = False
            ioc_details = "\n#### Extracted IOCs\n"
            
            if iocs.get('ips'):
                has_iocs = True
                ioc_details += f"\n**IP Addresses ({len(iocs['ips'])}):**\n"
                for ioc in iocs['ips'][:10]:  # Limit to first 10
                    if isinstance(ioc, dict):
                        value = ioc.get('value', '')
                        confidence = int(ioc.get('confidence', 0.8) * 100)
                        line = ioc.get('line_number', '')
                        ioc_details += f"- `{value}` (Confidence: {confidence}%, Line: {line})\n"
                    else:
                        ioc_details += f"- `{ioc}`\n"
                if len(iocs['ips']) > 10:
                    ioc_details += f"- *... and {len(iocs['ips']) - 10} more*\n"
            
            if iocs.get('domains'):
                has_iocs = True
                ioc_details += f"\n**Domains ({len(iocs['domains'])}):**\n"
                for ioc in iocs['domains'][:10]:
                    if isinstance(ioc, dict):
                        value = ioc.get('value', '')
                        confidence = int(ioc.get('confidence', 0.8) * 100)
                        line = ioc.get('line_number', '')
                        ioc_details += f"- `{value}` (Confidence: {confidence}%, Line: {line})\n"
                    else:
                        ioc_details += f"- `{ioc}`\n"
                if len(iocs['domains']) > 10:
                    ioc_details += f"- *... and {len(iocs['domains']) - 10} more*\n"
            
            if iocs.get('urls'):
                has_iocs = True
                ioc_details += f"\n**URLs ({len(iocs['urls'])}):**\n"
                for ioc in iocs['urls'][:10]:
                    if isinstance(ioc, dict):
                        value = ioc.get('value', '')
                        confidence = int(ioc.get('confidence', 0.8) * 100)
                        line = ioc.get('line_number', '')
                        ioc_details += f"- `{value}` (Confidence: {confidence}%, Line: {line})\n"
                    else:
                        ioc_details += f"- `{ioc}`\n"
                if len(iocs['urls']) > 10:
                    ioc_details += f"- *... and {len(iocs['urls']) - 10} more*\n"
            
            if iocs.get('file_paths'):
                has_iocs = True
                ioc_details += f"\n**File Paths ({len(iocs['file_paths'])}):**\n"
                for ioc in iocs['file_paths'][:10]:
                    if isinstance(ioc, dict):
                        value = ioc.get('value', '')
                        confidence = int(ioc.get('confidence', 0.6) * 100)
                        line = ioc.get('line_number', '')
                        ioc_details += f"- `{value}` (Confidence: {confidence}%, Line: {line})\n"
                    else:
                        ioc_details += f"- `{ioc}`\n"
                if len(iocs['file_paths']) > 10:
                    ioc_details += f"- *... and {len(iocs['file_paths']) - 10} more*\n"
            
            # Check for other IOC types that might exist
            other_ioc_types = [k for k in iocs.keys() if k not in ['ips', 'domains', 'urls', 'file_paths']]
            if other_ioc_types:
                has_iocs = True
                for ioc_type in other_ioc_types:
                    ioc_list = iocs[ioc_type]
                    if ioc_list:
                        ioc_details += f"\n**{ioc_type.replace('_', ' ').title()} ({len(ioc_list)}):**\n"
                        for ioc in ioc_list[:10]:
                            if isinstance(ioc, dict):
                                value = ioc.get('value', '')
                                confidence = int(ioc.get('confidence', 0.7) * 100)
                                line = ioc.get('line_number', '')
                                ioc_details += f"- `{value}` (Confidence: {confidence}%, Line: {line})\n"
                            else:
                                ioc_details += f"- `{ioc}`\n"
                        if len(ioc_list) > 10:
                            ioc_details += f"- *... and {len(ioc_list) - 10} more*\n"
            
            if has_iocs:
                hr_output += ioc_details
        
        hr_output += f"""
        #### MITRE ATT&CK
        - **Techniques:** {len(mitre_techniques)}
        - **Tactics:** {len(set(tech.get('tactic', '') for tech in mitre_techniques.values()))}
        """
        
        # Add detailed findings if any
        if findings:
            hr_output += "\n#### Detailed Findings\n"
            for i, finding in enumerate(findings[:10], 1):  # Limit to first 10
                hr_output += f"\n{i}. **{finding.get('pattern_id', 'Unknown')}** ({finding.get('severity', 'Unknown')})\n"
                hr_output += f"   - {finding.get('description', 'No description')}\n"
                
                # Add line number if available
                line_number = finding.get('line_number')
                if line_number:
                    hr_output += f"   - **Line:** {line_number}\n"
                
                # Add code snippet if available (correct field name is 'code_snippet')
                code_snippet = finding.get('code_snippet', '').strip()
                if code_snippet:
                    # Truncate very long snippets
                    if len(code_snippet) > 200:
                        code_snippet = code_snippet[:200] + '...'
                    hr_output += f"   - **Code:** `{code_snippet}`\n"
            
            if len(findings) > 10:
                hr_output += f"\n*... and {len(findings) - 10} more findings*\n"
        
        # Return results to XSIAM
        results = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': analysis_result,
            'HumanReadable': hr_output,
            'EntryContext': {
                'ScriptSentinel': xdr_context,
                'DBotScore': dbot_score_entry,
                'File': file_context
            }
        }
        
        # Add IOCs to context if any
        if xdr_iocs:
            results['EntryContext']['ScriptSentinel.IOCs'] = xdr_iocs
        
        # Add MITRE techniques if any
        if mitre_techniques:
            results['EntryContext']['ScriptSentinel.MITRETechniques'] = [
                {
                    'ID': tech_id,
                    'Name': tech_data.get('name', ''),
                    'Tactic': tech_data.get('tactic', ''),
                    'Description': tech_data.get('description', '')
                }
                for tech_id, tech_data in mitre_techniques.items()
            ]
        
        # Add findings with code snippets to context
        if findings:
            results['EntryContext']['ScriptSentinel.Findings'] = [
                {
                    'PatternID': finding.get('pattern_id', ''),
                    'Severity': finding.get('severity', ''),
                    'Description': finding.get('description', ''),
                    'LineNumber': finding.get('line_number'),
                    'CodeSnippet': clean_code_snippet(finding.get('code_snippet', '')),
                    'MITRETechnique': finding.get('mitre_technique', ''),
                    'Confidence': finding.get('confidence', 0.0)
                }
                for finding in findings
            ]
        
        # Add scoring breakdown to context if available
        if scorer_scores:
            results['EntryContext']['ScriptSentinel.ScoringBreakdown'] = xdr_context['ScriptAnalysis']['ScoringBreakdown']
        
        return_results(results)
        
    except Exception as e:
        return_error(f'Script execution error: {str(e)}')


# Execute main function
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()