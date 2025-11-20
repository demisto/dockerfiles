#!/usr/bin/env python3
"""
XSIAM Wrapper for Script Sentinel

This wrapper bridges XSIAM's execution model with Script Sentinel's CLI,
providing XSIAM-specific output formatting including XDR context, IOC correlation,
and MITRE ATT&CK enrichment.

NO CHANGES to core Script Sentinel code - all integration logic is here.
"""

import sys
import json
import argparse
import hashlib
import base64
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple


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
    # Base score from verdict
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


def format_iocs_for_xdr(iocs_dict: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Format IOCs from Script Sentinel for XSIAM XDR correlation.
    
    Args:
        iocs_dict: Dictionary of IOC types to lists of IOC values
        
    Returns:
        List of XDR-formatted IOC objects
    """
    xdr_iocs = []
    timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # IP addresses
    for ip in iocs_dict.get('ips', []):
        xdr_iocs.append({
            'Type': 'IP',
            'Value': ip,
            'Source': 'Script Sentinel',
            'Confidence': 'High',
            'FirstSeen': timestamp,
            'Category': 'Network'
        })
    
    # Domains
    for domain in iocs_dict.get('domains', []):
        xdr_iocs.append({
            'Type': 'Domain',
            'Value': domain,
            'Source': 'Script Sentinel',
            'Confidence': 'High',
            'FirstSeen': timestamp,
            'Category': 'Network'
        })
    
    # URLs
    for url in iocs_dict.get('urls', []):
        xdr_iocs.append({
            'Type': 'URL',
            'Value': url,
            'Source': 'Script Sentinel',
            'Confidence': 'High',
            'FirstSeen': timestamp,
            'Category': 'Network'
        })
    
    # File paths
    for path in iocs_dict.get('file_paths', []):
        xdr_iocs.append({
            'Type': 'FilePath',
            'Value': path,
            'Source': 'Script Sentinel',
            'Confidence': 'Medium',
            'FirstSeen': timestamp,
            'Category': 'FileSystem'
        })
    
    return xdr_iocs


def format_xsiam_output(analysis_result: Dict[str, Any], script_content: str) -> Dict[str, Any]:
    """
    Format Script Sentinel output for XSIAM XDR platform.
    
    Args:
        analysis_result: Raw JSON output from Script Sentinel
        script_content: Original script content for hash calculation
        
    Returns:
        XSIAM-formatted output with XDR context
    """
    # Calculate hashes
    script_hash_sha256 = calculate_hash(script_content, 'sha256')
    script_hash_md5 = calculate_hash(script_content, 'md5')
    
    # Extract key metrics
    verdict = analysis_result.get('verdict', 'unknown')
    confidence = analysis_result.get('confidence_score', 0.0)
    findings = analysis_result.get('findings', [])
    metadata = analysis_result.get('metadata', {})
    iocs = analysis_result.get('iocs', {})
    mitre_techniques = analysis_result.get('mitre_techniques', {})
    
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
    
    # Build XSIAM output
    output = {
        'success': True,
        'verdict': verdict,
        'confidence': confidence,
        'threat_score': threat_score,
        
        # Raw findings for detailed analysis
        'findings': findings,
        'findings_summary': {
            'total': len(findings),
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'low': low_count
        },
        
        # XDR Context for XSIAM
        'xdr_context': {
            'ScriptAnalysis': {
                'ScriptHash': script_hash_sha256,
                'ScriptHashMD5': script_hash_md5,
                'Verdict': verdict,
                'Confidence': confidence,
                'ThreatScore': threat_score,
                'Language': metadata.get('script_language', 'unknown'),
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
                'AnalysisMetadata': {
                    'PatternsMatched': metadata.get('patterns_checked', 0),
                    'ObfuscationDetected': metadata.get('obfuscation_detected', False),
                    'LLMAnalysisUsed': metadata.get('llm_available', False),
                    'ParanoiaLevel': metadata.get('paranoia_level', 1)
                }
            }
        },
        
        # IOCs formatted for XDR correlation
        'xdr_iocs': format_iocs_for_xdr(iocs),
        
        # Standard DBotScore (compatible with XSOAR/XSIAM)
        'dbot_score': {
            'Indicator': script_hash_sha256,
            'Type': 'file',
            'Vendor': 'Script Sentinel',
            'Score': dbot_score,
            'Reliability': 'A - Completely reliable'
        },
        
        # File context
        'file_context': {
            'SHA256': script_hash_sha256,
            'MD5': script_hash_md5,
            'Size': metadata.get('script_bytes', 0),
            'Type': metadata.get('script_language', 'unknown'),
            'Malicious': {
                'Vendor': 'Script Sentinel',
                'Description': f"Verdict: {verdict} (Confidence: {confidence:.0%})",
                'Score': dbot_score
            } if verdict in ['malicious', 'suspicious'] else None
        },
        
        # MITRE ATT&CK details
        'mitre_attack': {
            'Techniques': [
                {
                    'ID': tech_id,
                    'Name': tech_data.get('name', ''),
                    'Tactic': tech_data.get('tactic', ''),
                    'Description': tech_data.get('description', '')
                }
                for tech_id, tech_data in mitre_techniques.items()
            ] if mitre_techniques else []
        },
        
        # Metadata
        'metadata': metadata
    }
    
    return output


def run_sentinel_analysis(script_path: str, language: Optional[str] = None,
                         paranoia_level: int = 1, include_llm: bool = False) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Run Script Sentinel analysis using the existing CLI.
    
    Args:
        script_path: Path to script file to analyze
        language: Script language (ignored - CLI auto-detects from extension)
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
        
        # Note: language parameter is not passed to CLI as it auto-detects from file extension
        # The wrapper accepts it for XSIAM compatibility but doesn't use it
        
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
        # Note: CLI may output informational messages before JSON, so we need to find the JSON part
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
    """Main entry point for XSIAM wrapper."""
    parser = argparse.ArgumentParser(
        description='XSIAM wrapper for Script Sentinel malware analysis'
    )
    
    # Input methods
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--file-path',
        help='Path to script file to analyze'
    )
    input_group.add_argument(
        '--content-base64',
        help='Base64-encoded script content'
    )
    input_group.add_argument(
        '--content',
        help='Direct script content'
    )
    
    # Analysis options
    parser.add_argument(
        '--language',
        choices=['powershell', 'bash', 'javascript'],
        help='Script language (auto-detect if not provided)'
    )
    parser.add_argument(
        '--paranoia-level',
        type=int,
        choices=[1, 2, 3],
        default=1,
        help='Analysis sensitivity: 1=Balanced, 2=Aggressive, 3=Maximum (default: 1)'
    )
    parser.add_argument(
        '--include-llm',
        action='store_true',
        help='Enable LLM-powered semantic analysis'
    )
    parser.add_argument(
        '--output',
        help='Output file path (default: stdout)'
    )
    
    args = parser.parse_args()
    
    try:
        # Prepare script content and file
        script_content = None
        script_file = None
        temp_file = None
        
        if args.file_path:
            # Use provided file path
            script_file = args.file_path
            with open(script_file, 'r', encoding='utf-8') as f:
                script_content = f.read()
                
        elif args.content_base64:
            # Decode base64 content
            try:
                script_content = base64.b64decode(args.content_base64).decode('utf-8')
            except Exception as e:
                print(json.dumps({
                    'success': False,
                    'error': f'Failed to decode base64 content: {e}'
                }), file=sys.stderr)
                sys.exit(1)
                
            # Determine file extension from language
            extension_map = {
                'powershell': '.ps1',
                'bash': '.sh',
                'javascript': '.js'
            }
            suffix = extension_map.get(args.language, '.script')
            
            # Write to temp file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False)
            temp_file.write(script_content)
            temp_file.close()
            script_file = temp_file.name
            
        elif args.content:
            # Use direct content
            script_content = args.content
            
            # Determine file extension from language
            extension_map = {
                'powershell': '.ps1',
                'bash': '.sh',
                'javascript': '.js'
            }
            suffix = extension_map.get(args.language, '.script')
            
            # Write to temp file
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False)
            temp_file.write(script_content)
            temp_file.close()
            script_file = temp_file.name
        
        # Run Script Sentinel analysis
        analysis_result, error = run_sentinel_analysis(
            script_file,
            language=args.language,
            paranoia_level=args.paranoia_level,
            include_llm=args.include_llm
        )
        
        # Clean up temp file
        if temp_file:
            try:
                Path(temp_file.name).unlink()
            except:
                pass
        
        # Handle errors
        if error:
            output = {
                'success': False,
                'error': error
            }
        else:
            # Format for XSIAM
            output = format_xsiam_output(analysis_result, script_content)
        
        # Output results
        output_json = json.dumps(output, indent=2)
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_json)
        else:
            print(output_json)
        
        # Exit with appropriate code
        sys.exit(0 if output.get('success', False) else 1)
        
    except Exception as e:
        error_output = {
            'success': False,
            'error': f'Wrapper error: {str(e)}'
        }
        print(json.dumps(error_output, indent=2), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()