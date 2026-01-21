rule rule_015_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "PowerShell WebClient download and immediate execution pattern"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "1c54a98bcf8317a9,22aec71e38abedda,232149943e9a53aa,256f1d658cbdeb70,25b815735c2e901c,27fcb736915bb8d0"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download methods
        $download1 = "System.Net.WebClient).DownloadFile(" nocase
        $download2 = "WebClient).DownloadFile(" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "& " nocase
        
        // Temp directory patterns
        $temp1 = "$env:TEMP\\" nocase
        $temp2 = "$env:APPDATA\\" nocase
        
        // Executable extensions
        $exe = ".exe" nocase

    condition:
        any of ($download*) and any of ($exec*) and any of ($temp*) and $exe
}