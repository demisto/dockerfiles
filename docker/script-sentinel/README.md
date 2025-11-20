# Script Sentinel Docker Image

Malware analysis for PowerShell, Bash, and JavaScript scripts with MITRE ATT&CK mapping.

## Features

- Static pattern matching for malicious behaviors
- MITRE ATT&CK technique identification
- IOC extraction (IPs, domains, URLs, file paths)
- XDR-compatible output format for XSIAM integration
- Configurable sensitivity levels (3 paranoia levels)
- Optional LLM-powered semantic analysis

## Base Image

`demisto/python3:3.11.9.109876` (Alpine-based)

## Size

Approximately 450MB compressed

## Security

- Non-root user (UID 1000)
- No network access required for analysis
- Minimal dependencies
- Includes verification script

## Usage

```bash
docker run --rm demisto/script-sentinel:latest analyze --language javascript --content "your script here"
```

## Testing

- Tested with keylogger detection
- Tested with obfuscation detection  
- Tested with various malware samples
- Verification script included (`verify.py`)

## Related

This image is used in the Script Sentinel integration in the Cortex XSOAR/XSIAM content repository.
