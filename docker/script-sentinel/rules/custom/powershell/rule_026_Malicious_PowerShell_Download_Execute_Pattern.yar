rule rule_026_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "PowerShell script downloading and executing files from remote URLs"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "280ee1b2504ca5ed,2a7deabaa14a1e76,2adbfaa748da59df,2b2fb42280e596ce,2bbd2d435c9526aa,2cda5450c5beef6f,2cdadbae7bd3be05"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download methods
        $download1 = "System.Net.WebClient).DownloadFile" nocase
        $download2 = "New-Object System.Net.WebClient" nocase
        $download3 = "New-Object net.webclient" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Start-Process (" nocase
        
        // Suspicious file extensions in environment paths
        $path1 = "$env:APPDATA\\" nocase
        $path2 = "$env:LOCALAPPDATA\\" nocase
        
        // Executable extensions
        $ext1 = ".exe" nocase

    condition:
        any of ($download*) and any of ($exec*) and any of ($path*) and $ext1
}