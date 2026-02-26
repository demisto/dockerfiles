# Script Sentinel Yara Rule Style Guide

## Rule Naming
- Use PascalCase with underscores: `Malicious_PowerShell_Mimikatz`
- Prefix with behavior category: `Malicious_`, `Suspicious_`, `Obfuscated_`
- Be descriptive but concise

## Required Metadata
Every rule MUST include:
- `description`: One-line explanation of what the rule detects
- `severity`: One of "Critical", "High", "Medium", "Low", "Info"
- `confidence`: Float 0.0-1.0 indicating rule precision
- `mitre_technique`: MITRE ATT&CK technique ID (e.g., "T1059.001")
- `author`: "Script Sentinel" for generated rules

## String Patterns
- Use `nocase` for case-insensitive matching
- Prefer specific strings over broad patterns
- Comment each string group explaining what it matches
- Use regex sparingly (performance impact)

## Condition Best Practices
- Require multiple indicators (reduce false positives)
- Use `any of ($category*)` for grouped alternatives
- Keep conditions readable - avoid complex boolean logic
- Consider script size constraints when relevant

## Performance Considerations
- Avoid expensive regex patterns (`.+`, `.*`)
- Prefer exact strings over wildcards when possible
- Test rules against large benign dataset for FP rate
