rule rule_037_Obfuscated_PowerShell_Excessive_Whitespace {
    meta:
        description = "PowerShell script with excessive leading whitespace obfuscation"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "04d376baafdcc08f"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // PowerShell indicators
        $ps1 = "function " nocase
        $ps2 = "param(" nocase
        $ps3 = "New-Object" nocase
        
        // Excessive whitespace pattern (looking for many consecutive newlines/spaces at start)
        $whitespace = /^\s{50,}/

    condition:
        $whitespace and any of ($ps*)
}