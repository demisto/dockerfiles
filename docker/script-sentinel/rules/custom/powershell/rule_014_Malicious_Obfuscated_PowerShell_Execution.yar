rule rule_014_Malicious_Obfuscated_PowerShell_Execution {
    meta:
        description = "Heavily obfuscated PowerShell execution patterns"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1027"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2559a6428664b666,32bcff55ccf0d8c3,767bf51b6b1e7982"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $obf1 = /\$[a-zA-Z]+\[[\d,\s]+\]\s*\|\s*ForEach[^{]+\{[^}]*\[char\]/i
        $obf2 = /\$[a-zA-Z]+\[[^\]]+\]\+\$[a-zA-Z]+\[[^\]]+\]\+/i
        $obf3 = /-split\s*'[^']*'\s*-split/i
        $obf4 = /\[Convert\]::ToInt16.*-As\s*\[Char\]/i
        $obf5 = /\$VErBOsEPREFerenCe\.tOstRiNG/i
    
    condition:
        any of them
}