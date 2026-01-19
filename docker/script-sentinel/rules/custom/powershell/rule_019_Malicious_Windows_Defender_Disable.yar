rule rule_019_Malicious_Windows_Defender_Disable {
    meta:
        description = "Attempts to disable Windows Defender protection"
        severity = "High"
        confidence = "0.95"
        mitre_technique = "T1562.001"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "ff8f855722b47602,ea3e2f17b0bf2081"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $disable1 = "Set-MpPreference -DisableRealtimeMonitoring $true" nocase
        $disable2 = "Set-MpPreference -DisableBehaviorMonitoring $true" nocase
        $disable3 = "Set-MpPreference -DisableBlockAtFirstSeen $true" nocase
        $disable4 = "Set-MpPreference -ExclusionExtension" nocase
        $disable5 = "Set-MpPreference -ExclusionPath" nocase
        $disable6 = "sc stop WinDefend" nocase
    
    condition:
        2 of them
}