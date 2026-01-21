rule rule_004_Suspicious_PowerShell_History_Disable {
    meta:
        description = "PowerShell command to disable history logging"
        severity = "Medium"
        confidence = "0.90"
        mitre_technique = "T1070.003"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "022b197d52a6eb62,22eb58011b00c3ef"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $history1 = "Set-PSReadlineOption -HistorySaveStyle SaveNothing" nocase
        $history2 = "Set-PSReadLineOption -HistorySaveStyle SaveNothing" nocase
    
    condition:
        any of them
}