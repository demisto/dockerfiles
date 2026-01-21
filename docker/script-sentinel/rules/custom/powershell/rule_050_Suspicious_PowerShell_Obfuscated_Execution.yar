rule rule_050_Suspicious_PowerShell_Obfuscated_Execution {
    meta:
        description = "Heavily obfuscated PowerShell with character conversion and random casing"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "5e34a4598db08d11"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Obfuscation patterns
        $obfus1 = "CoNverT]::toinT16" nocase
        $obfus2 = "[ChAR]" nocase
        $obfus3 = "-JOiN" nocase
        $obfus4 = "StrIng]" nocase
        
        // Variable obfuscation
        $var1 = "GV '*" nocase
        $var2 = "').NaMe[" nocase
        
        // Execution patterns
        $exec1 = "|.(" nocase
        $exec2 = "-JOIn'')" nocase

    condition:
        3 of ($obfus*) and any of ($var*) and any of ($exec*)
}