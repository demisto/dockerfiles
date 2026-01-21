# Script Sentinel Pattern Style Guide

This guide defines best practices for creating Script Sentinel detection patterns.

## Pattern Naming Conventions

### ID Format
- **Hand-crafted patterns**: `{LANG}-{NUM}` (e.g., `PS-001`, `SH-001`, `JS-001`)
- **Generated patterns**: `{LANG}-GEN-{NUM}` (e.g., `PS-GEN-001`)

Language prefixes:
- `PS` - PowerShell
- `SH` - Bash/Shell
- `JS` - JavaScript

### Name Format
- Use descriptive, action-based names
- Avoid abbreviations unless well-known (e.g., IEX, AMSI)
- Examples: "Download Cradle Detection", "Credential Dumping via Mimikatz"

## Severity Assignment Guidelines

| Severity | Use When |
|----------|----------|
| Critical | Direct code execution, credential theft, system compromise |
| High | Download/execute, persistence mechanisms, defense evasion |
| Medium | Suspicious but potentially legitimate, reconnaissance |
| Low | Informational, weak indicators |
| Info | Metadata collection only |

## Confidence Assignment Guidelines

| Confidence | Meaning |
|------------|---------|
| 0.90-1.00 | Very high precision, rarely false positive |
| 0.75-0.89 | High precision, occasional false positives |
| 0.60-0.74 | Moderate precision, some false positives expected |
| 0.40-0.59 | Lower precision, requires context validation |
| < 0.40 | Not recommended for production |

## Detection Logic Best Practices

### Regex Patterns
- Always use case-insensitive flag: `(?i)`
- Anchor patterns when possible: `\b` for word boundaries
- Avoid overly broad patterns that match legitimate code
- Test against benign samples to validate precision

### AST Patterns
- Use AST detection for structural patterns that regex can't capture
- Prefer AST for function call sequences and control flow

## Common Pitfalls to Avoid

1. **Too Broad**: Pattern matches common legitimate code
   - Bad: `(?i)invoke-expression` (matches any IEX usage)
   - Good: `(?i)invoke-expression\s*\(\s*(new-object|iwr)` (specific to download cradles)

2. **Too Specific**: Pattern only matches exact malware sample
   - Bad: `powershell -enc SW52b2tl...` (exact Base64 string)
   - Good: `(?i)-enc(odedcommand)?\s+[A-Za-z0-9+/=]{50,}` (general pattern)

3. **Missing Context**: Pattern doesn't consider execution context
   - Include indicators like file paths, network activity when relevant

4. **Ignoring Obfuscation**: Malware often obfuscates to evade detection
   - Consider tick marks, string concatenation, variable substitution

## Category Values

Use these category values:
- `execution` - Code execution techniques
- `persistence` - Maintaining access
- `credential_access` - Stealing credentials
- `defense_evasion` - Avoiding detection
- `exfiltration` - Data theft
- `command_and_control` - C2 communication
- `obfuscation` - Code obfuscation techniques
- `reconnaissance` - Information gathering
