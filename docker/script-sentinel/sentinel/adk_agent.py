# sentinel/adk_agent.py

"""
Google ADK integration for LLM-powered semantic analysis.

This module integrates Google's Agent Development Kit (ADK) with Gemini 2.5 Pro
to provide semantic analysis of scripts for security threat detection.
"""

import logging
import asyncio
from typing import Optional, Any
from dataclasses import dataclass

from google.adk import Agent, Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from .models import Finding
from .sanitizer import sanitize_script

logger = logging.getLogger(__name__)

# Timeout for LLM API calls (35 seconds per NFR-2)
LLM_TIMEOUT_SECONDS = 35

# Available Gemini models
GEMINI_MODELS = {
    'flash': 'gemini-2.0-flash-exp',      # Fast, cost-effective (recommended for production)
    'pro': 'gemini-2.5-pro',              # Deeper analysis, higher quality
    'flash-thinking': 'gemini-2.0-flash-thinking-exp'  # Experimental with reasoning
}

# Default model
DEFAULT_MODEL = 'flash'


@dataclass
class ADKAnalysisResult:
    """Result from ADK semantic analysis."""
    findings: list[Finding]
    metadata: dict[str, Any]


def _check_adk_available() -> tuple[bool, Optional[str]]:
    """
    Check if ADK and Gemini are available.
    
    Automatically attempts to configure authentication if not already set up.
    
    Returns:
        Tuple of (is_available, error_message).
    """
    try:
        # Try to import required modules
        import google.adk
        import google.genai
        import os
        
        # Auto-configure environment if not set
        if not os.getenv('GOOGLE_CLOUD_PROJECT'):
            # Try to get from gcloud config
            try:
                import subprocess
                result = subprocess.run(
                    ['gcloud', 'config', 'get-value', 'project'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    os.environ['GOOGLE_CLOUD_PROJECT'] = result.stdout.strip()
                    logger.info(f"Auto-configured GOOGLE_CLOUD_PROJECT from gcloud")
            except Exception:
                pass
        
        if not os.getenv('GOOGLE_CLOUD_LOCATION'):
            # Default to us-central1
            os.environ['GOOGLE_CLOUD_LOCATION'] = 'us-central1'
            logger.info("Auto-configured GOOGLE_CLOUD_LOCATION to us-central1")
        
        # Final check
        if not os.getenv('GOOGLE_CLOUD_PROJECT'):
            return False, "GOOGLE_CLOUD_PROJECT not configured. Set via: gcloud config set project YOUR_PROJECT_ID"
        
        # Check for authentication (multiple possible locations)
        credentials_paths = [
            os.path.expanduser('~/.config/gcloud/application_default_credentials.json'),
            os.getenv('GOOGLE_APPLICATION_CREDENTIALS', ''),
        ]
        
        has_credentials = any(os.path.exists(p) for p in credentials_paths if p)
        
        if not has_credentials:
            return False, "Google Cloud credentials not found. Run: gcloud auth application-default login"
        
        return True, None
        
    except ImportError as e:
        return False, f"Required module not available: {str(e)}. Install with: pip install google-adk google-genai"
    except Exception as e:
        return False, f"ADK availability check failed: {str(e)}"


def _create_analysis_prompt(
    language: str,
    script_content: str,
    heuristic_findings: list[Finding]
) -> str:
    """
    Create the analysis prompt for the LLM.
    
    Args:
        language: Script language (powershell, bash, javascript).
        script_content: The sanitized script content.
        heuristic_findings: Findings from heuristic analysis.
        
    Returns:
        Formatted prompt string.
    """
    # Build heuristic findings summary
    heuristic_summary = ""
    if heuristic_findings:
        heuristic_summary = "\n\n## Heuristic Findings\n\n"
        heuristic_summary += "The following patterns were detected by heuristic analysis:\n\n"
        for i, finding in enumerate(heuristic_findings, 1):
            heuristic_summary += f"{i}. **{finding.pattern_id}** (Severity: {finding.severity}, Confidence: {finding.confidence:.2f})\n"
            heuristic_summary += f"   - {finding.description}\n"
            if finding.mitre_technique:
                heuristic_summary += f"   - MITRE: {finding.mitre_technique}\n"
    
    prompt = f"""You are a cybersecurity expert analyzing a {language} script for potential security threats.

## Task

Perform semantic analysis to identify security threats, malicious patterns, or suspicious behaviors that may not be caught by simple pattern matching. Focus on:

1. **Intent Analysis**: What is the script trying to accomplish?
2. **Behavioral Patterns**: Does it exhibit malicious behaviors (data exfiltration, persistence, privilege escalation)?
3. **Context Understanding**: Are seemingly benign commands used in a malicious context?
4. **Obfuscation Detection**: Is the code intentionally obscured to hide malicious intent?
5. **MITRE ATT&CK Mapping**: Which tactics and techniques does it employ?

{heuristic_summary}

## Script Content

```{language}
{script_content}
```

## Output Format

Provide your analysis as a JSON array of findings. Each finding must include:

- `pattern_id`: A unique identifier (e.g., "semantic-data-exfil-001")
- `severity`: One of "High", "Medium", "Low"
- `confidence`: A float between 0.0 and 1.0
- `description`: Clear description of the threat
- `mitre_technique`: MITRE ATT&CK technique ID (e.g., "T1059.001") or null
- `category`: One of "execution", "persistence", "privilege_escalation", "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "exfiltration", "command_and_control", "impact"

Example:
```json
[
  {{
    "pattern_id": "semantic-credential-theft-001",
    "severity": "High",
    "confidence": 0.92,
    "description": "Script attempts to access browser credential stores and send data to external server",
    "mitre_technique": "T1555.003",
    "category": "credential_access"
  }}
]
```

**Important**: 
- Only report findings with confidence >= 0.6
- Be specific about WHY something is suspicious
- Consider the context - not all powerful commands are malicious
- If no threats are found, return an empty array: []
"""
    
    return prompt


def _parse_llm_response(response_text: str) -> tuple[list[Finding], Optional[str]]:
    """
    Parse LLM response into Finding objects.
    
    Args:
        response_text: Raw response from LLM.
        
    Returns:
        Tuple of (findings_list, error_message).
    """
    import json
    import re
    
    try:
        # Extract JSON from response (handle markdown code blocks)
        json_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            # Try to find JSON array directly
            json_match = re.search(r'\[.*?\]', response_text, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                return [], "No JSON array found in LLM response"
        
        # Parse JSON
        findings_data = json.loads(json_str)
        
        if not isinstance(findings_data, list):
            return [], "LLM response is not a JSON array"
        
        # Convert to Finding objects
        findings = []
        for item in findings_data:
            try:
                # Convert confidence string to float if needed
                confidence = item.get('confidence', 0.0)
                if isinstance(confidence, str):
                    confidence = float(confidence)
                
                finding = Finding(
                    pattern_id=item.get('pattern_id', 'semantic-unknown'),
                    severity=item.get('severity', 'Medium'),
                    confidence=confidence,
                    description=item.get('description', 'No description provided'),
                    mitre_technique=item.get('mitre_technique'),
                    category=item.get('category', 'unknown')
                )
                findings.append(finding)
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Failed to parse finding: {e}")
                continue
        
        return findings, None
        
    except json.JSONDecodeError as e:
        return [], f"Failed to parse JSON: {str(e)}"
    except Exception as e:
        return [], f"Failed to parse LLM response: {str(e)}"


async def _run_adk_analysis(
    language: str,
    sanitized_content: str,
    heuristic_findings: list[Finding],
    model: str = DEFAULT_MODEL
) -> tuple[Optional[ADKAnalysisResult], Optional[str]]:
    """
    Run ADK analysis with Gemini.
    
    Args:
        language: Script language.
        sanitized_content: Sanitized script content.
        heuristic_findings: Findings from heuristic analysis.
        model: Gemini model to use ('flash', 'pro', or 'flash-thinking').
        
    Returns:
        Tuple of (ADKAnalysisResult, error_message).
    """
    try:
        # Create the analysis prompt
        prompt = _create_analysis_prompt(language, sanitized_content, heuristic_findings)
        
        # Get project and location from environment
        import os
        
        project = os.getenv('GOOGLE_CLOUD_PROJECT')
        location = os.getenv('GOOGLE_CLOUD_LOCATION', 'us-central1')
        
        # Configure environment for Vertex AI (per official ADK docs)
        os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'true'
        os.environ['GOOGLE_CLOUD_PROJECT'] = project
        os.environ['GOOGLE_CLOUD_LOCATION'] = location
        
        # Get model name from configuration
        model_name = GEMINI_MODELS.get(model, GEMINI_MODELS[DEFAULT_MODEL])
        
        logger.info(f"Configured Vertex AI: project={project}, location={location}, model={model_name}")
        
        # Create ADK agent (ADK will auto-detect Vertex AI from env vars)
        agent = Agent(
            name="security_analyzer",
            model=model_name,
            instruction="""You are a cybersecurity expert specializing in script analysis.
            Analyze scripts for security threats and provide detailed findings in JSON format.
            Focus on semantic understanding and context, not just pattern matching.""",
            description="Security script analyzer using semantic analysis"
        )
        
        # Create runner with session service (no client parameter needed)
        session_service = InMemorySessionService()
        runner = Runner(
            app_name="script_sentinel",
            agent=agent,
            session_service=session_service
        )
        
        # Create session
        session = await session_service.create_session(
            app_name="script_sentinel",
            user_id="analyzer",
            state={"language": language}
        )
        
        # Create message content
        message = types.Content(
            role='user',
            parts=[types.Part(text=prompt)]
        )
        
        # Run analysis with timeout
        response_text = ""
        async for event in runner.run_async(
            user_id=session.user_id,
            session_id=session.id,
            new_message=message
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    if part.text:
                        response_text += part.text
        
        # Parse response
        findings, parse_error = _parse_llm_response(response_text)
        if parse_error:
            return None, f"Failed to parse LLM response: {parse_error}"
        
        # Create result
        result = ADKAnalysisResult(
            findings=findings,
            metadata={
                "model": model_name,
                "model_type": model,
                "findings_count": len(findings),
                "response_length": len(response_text)
            }
        )
        
        return result, None
        
    except Exception as e:
        # Check if this is a rate limit error (expected, don't log stack trace)
        error_str = str(e)
        if '429' in error_str or 'RESOURCE_EXHAUSTED' in error_str:
            logger.warning(f"ADK analysis rate limited: {error_str}")
        else:
            # Unexpected error, log with stack trace
            logger.error(f"ADK analysis failed: {e}", exc_info=True)
        return None, f"ADK analysis failed: {error_str}"


async def analyze_with_adk(
    script_content: str,
    language: str,
    ast: Any,
    heuristic_findings: list[Finding],
    model: str = DEFAULT_MODEL
) -> tuple[Optional[list[Finding]], Optional[str]]:
    """
    Analyze script using Google ADK with Gemini for semantic analysis.
    
    This is the main entry point for LLM-powered analysis. It:
    1. Checks ADK availability
    2. Sanitizes the script content
    3. Runs semantic analysis with Gemini
    4. Returns findings or error for graceful degradation
    
    Args:
        script_content: Original script content (unsanitized).
        language: Script language (powershell, bash, javascript).
        ast: Parsed AST (for future use).
        heuristic_findings: Findings from heuristic analysis.
        model: Gemini model to use ('flash', 'pro', or 'flash-thinking').
                Default is 'flash' for speed and cost-effectiveness.
        
    Returns:
        Tuple of (findings_list, error_message).
        On success: (findings, None)
        On failure: (None, error_message) - triggers fallback to heuristics-only
        
    Examples:
        >>> # Use default Flash model (fast, cost-effective)
        >>> findings, error = await analyze_with_adk(script, "powershell", ast, [])
        
        >>> # Use Pro model for deeper analysis
        >>> findings, error = await analyze_with_adk(script, "powershell", ast, [], model='pro')
        
        >>> if findings:
        ...     print(f"Found {len(findings)} semantic threats")
        >>> else:
        ...     print(f"ADK unavailable: {error}")
    """
    # Step 1: Check ADK availability
    is_available, availability_error = _check_adk_available()
    if not is_available:
        logger.warning(f"ADK not available: {availability_error}")
        return None, availability_error
    
    # Step 2: Sanitize script content
    logger.info("Sanitizing script content for LLM transmission")
    sanitized_content, stats = sanitize_script(script_content)
    logger.info(f"Sanitization complete: {stats.total_redactions} redactions")
    
    # Step 3: Run ADK analysis with timeout
    try:
        logger.info(f"Starting ADK analysis with {model} model (timeout: {LLM_TIMEOUT_SECONDS}s)")
        result, error = await asyncio.wait_for(
            _run_adk_analysis(language, sanitized_content, heuristic_findings, model),
            timeout=LLM_TIMEOUT_SECONDS
        )
        
        if error:
            logger.error(f"ADK analysis failed: {error}")
            return None, error
        
        if not result:
            return None, "ADK analysis returned no result"
        
        logger.info(f"ADK analysis complete: {len(result.findings)} findings")
        return result.findings, None
        
    except asyncio.TimeoutError:
        error_msg = f"ADK analysis timed out after {LLM_TIMEOUT_SECONDS} seconds"
        logger.error(error_msg)
        return None, error_msg
    except Exception as e:
        error_msg = f"ADK analysis failed: {str(e)}"
        # Check if this is a rate limit error (expected, don't log stack trace)
        if '429' in error_msg or 'RESOURCE_EXHAUSTED' in error_msg:
            logger.warning(error_msg)
        else:
            # Unexpected error, log with stack trace
            logger.error(error_msg, exc_info=True)
        return None, error_msg