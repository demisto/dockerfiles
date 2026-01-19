rule rule_024_Obfuscated_PowerShell_Command_Execution {
    meta:
        description = "Heavily obfuscated PowerShell with character substitution and encoding"
        severity = "High"
        confidence = "0.87"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2559a6428664b666"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Shell variable manipulation
        $shell1 = "$sHeLliD[" nocase
        $shell2 = "$SHElLID[" nocase
        
        // Character replacement patterns
        $replace1 = ".Replace(" nocase
        $char_sep1 = /[0-9]+[hdluz!;~,]/
        $char_sep2 = /[hdluz!;~,][0-9]+/
        
        // Obfuscated execution
        $iex = /['"]\s*\+\s*['"]\s*x\s*['"]/
        $invoke = "Invoke-Expression" nocase
        
        // Long encoded strings (>500 chars with separators)
        $long_encoded = /[0-9hdluz!;~,]{500,}/

    condition:
        (any of ($shell*) and 3 of ($char_sep*)) or
        ($replace1 and $long_encoded and ($iex or $invoke))
}