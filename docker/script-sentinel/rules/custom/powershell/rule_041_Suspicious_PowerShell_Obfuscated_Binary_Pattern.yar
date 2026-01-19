rule rule_041_Suspicious_PowerShell_Obfuscated_Binary_Pattern {
    meta:
        description = "PowerShell script with obfuscated binary-like patterns"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "4f65ee518d55a640"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Obfuscated binary patterns with character substitution
        $pattern1 = /[01K]{6,}/ nocase
        $pattern2 = /('[01K,]{100,}')/ nocase
        
        // Common obfuscation indicators
        $replace1 = ".Replace(" nocase
        $split1 = ".Split(" nocase
        
        // Variable assignment with suspicious patterns
        $var_assign = /\$\w+\s*=\s*\('[01K,]{50,}'\)/ nocase

    condition:
        (any of ($pattern*) and filesize > 10KB) or 
        ($var_assign and any of ($replace*, $split*))
}