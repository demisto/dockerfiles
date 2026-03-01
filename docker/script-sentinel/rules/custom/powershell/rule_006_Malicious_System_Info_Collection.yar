rule rule_006_Malicious_System_Info_Collection {
    meta:
        description = "Comprehensive system information collection script"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1082"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "022b197d52a6eb62,22eb58011b00c3ef,166d81d21bddcd9c"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $wmi1 = "Get-WmiObject -class Win32_Product" nocase
        $wmi2 = "Get-WmiObject Win32_OperatingSystem" nocase
        $wmi3 = "Get-WmiObject -Class Win32_ComputerSystem" nocase
        $info1 = "ConvertTo-Html" nocase
        $info2 = "$env:USERNAME" nocase
        $info3 = "$env:COMPUTERNAME" nocase
    
    condition:
        2 of ($wmi*) and any of ($info*)
}