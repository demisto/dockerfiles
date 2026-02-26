# Public YARA Rules Attribution

This directory contains YARA rules from public repositories, imported for
script-based malware detection. All rules retain their original licensing.

## Sources

### Neo23x0/signature-base
- **URL**: https://github.com/Neo23x0/signature-base
- **License**: Detection Rule License (DRL) 1.1
- **Author**: Florian Roth (Neo23x0)
- **Directories**: powershell/, python/, javascript/, bash/, webshells/ (partial)

The DRL 1.1 license requires:
1. Retain author identification in rules
2. Provide URI to original rule set
3. Indicate rules are licensed under DRL 1.1

### Yara-Rules/rules
- **URL**: https://github.com/Yara-Rules/rules
- **License**: GNU General Public License v2.0
- **Directories**: webshells/ (partial)

The GPL v2.0 license requires:
1. Include license text with distribution
2. Provide source code for any modifications
3. Retain copyright notices

## Rule Categories

| Directory   | Count | Primary Source       | Description                    |
|-------------|-------|---------------------|--------------------------------|
| powershell/ | 9     | signature-base      | PowerShell attack detection    |
| python/     | 5     | signature-base      | Python malware/shells          |
| javascript/ | 1     | signature-base      | JS-to-PowerShell attacks       |
| bash/       | 4     | signature-base      | Linux/bash malware indicators  |
| webshells/  | 15    | Both                | PHP/ASP/JSP webshell detection |

## Imported On
Date: 2025-12-28

## Notes
- Rules are used as-is without modification
- Original metadata (author, description, references) preserved in each rule
- MITRE ATT&CK mappings not present in original rules
