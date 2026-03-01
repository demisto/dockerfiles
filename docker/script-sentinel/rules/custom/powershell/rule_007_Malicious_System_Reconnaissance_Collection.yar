rule rule_007_Malicious_System_Reconnaissance_Collection {
    meta:
        description = "Extensive system reconnaissance and data collection typical of malware"
        severity = "Medium"
        confidence = "0.82"
        mitre_technique = "T1082"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "022b197d52a6eb62,166d81d21bddcd9c"
    approved_by = "wsladmin"
    approved_at = "2025-12-27"
    strings:
        $wmi1 = "Get-WmiObject -Class Win32_Product" nocase
        $wmi2 = "Get-WmiObject -Class Win32_ComputerSystem" nocase
        $wmi3 = "Get-WmiObject -Class Win32_OperatingSystem" nocase
        $hash1 = "Get-FileHash" nocase
        $hash2 = "SHA256" nocase
        $export1 = "Export-Csv" nocase
        $export2 = "ConvertTo-Html" nocase
        $sys1 = "TotalPhysicalMemory" nocase
        $sys2 = "SerialNumber" nocase

    condition:
        3 of ($wmi*) and any of ($hash*) and any of ($export*) and any of ($sys*)
}