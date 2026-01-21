rule rule_038_Suspicious_PowerShell_Single_Character_Script {
    meta:
        description = "PowerShell script containing only single character or minimal suspicious content"
        severity = "High"
        confidence = "0.92"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "3f79bb7b435b0532"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $single_char = /^[a-zA-Z0-9]$/
        $minimal_suspicious = /^[a-zA-Z0-9\s]{1,5}$/

    condition:
        filesize < 10 and ($single_char or $minimal_suspicious)
}