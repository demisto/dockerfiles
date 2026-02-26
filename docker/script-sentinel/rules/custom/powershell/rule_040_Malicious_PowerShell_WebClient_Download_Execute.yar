rule rule_040_Malicious_PowerShell_WebClient_Download_Execute {
    meta:
        description = "PowerShell WebClient download and execute pattern"
        severity = "Critical"
        confidence = "0.95"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "49e134e5a05a6449,4c84983be37209b0,4d4c3e1b44e7ea3d,4de59496812770d5,4fa63163f3008d7f"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // WebClient download methods
        $download1 = "WebClient).DownloadFile(" nocase
        $download2 = "WebClient).DownloadString(" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "IEX" nocase
        
        // Suspicious file paths
        $path1 = "$env:APPDATA\\" nocase
        $path2 = "$env:TEMP\\" nocase
        
        // HTTP URLs
        $url = /https?:\/\/[^\s'"]+\.exe/ nocase

    condition:
        any of ($download*) and any of ($exec*) and (any of ($path*) or $url)
}