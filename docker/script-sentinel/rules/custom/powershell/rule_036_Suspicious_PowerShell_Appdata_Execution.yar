rule rule_036_Suspicious_PowerShell_Appdata_Execution {
    meta:
        description = "PowerShell downloading and executing files from APPDATA directory"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "410c9ca2e0655ca9,411f8097493fd62d,44e5f8d113bfa907"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // APPDATA environment variable usage
        $appdata1 = "$env:APPDATA" nocase
        $appdata2 = "%APPDATA%" nocase
        
        // Download methods
        $download = "DownloadFile(" nocase
        
        // Execution from APPDATA
        $exec_appdata = "Start-Process (\"$env:APPDATA\\" nocase
        
        // File extensions commonly used by malware
        $exe = ".exe" nocase

    condition:
        any of ($appdata*) and $download and $exec_appdata and $exe
}