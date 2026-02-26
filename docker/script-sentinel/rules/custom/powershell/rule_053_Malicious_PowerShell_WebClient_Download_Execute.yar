rule rule_053_Malicious_PowerShell_WebClient_Download_Execute {
    meta:
        description = "PowerShell WebClient download and execute pattern commonly used by malware"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "5fa7406d91af6fce,5fbd0fdbf7b81c67,617f3615630e7d29,63c4243c82e75c8a,661546dce888039b,68568e2ddd9ef940,68bcd3bf50e222ec"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // WebClient download methods
        $download1 = "System.Net.WebClient).DownloadFile(" nocase
        $download2 = "New-Object System.Net.WebClient" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "IEX" nocase
        
        // Suspicious file locations
        $path1 = "$env:APPDATA\\" nocase
        $path2 = "$env:TEMP\\" nocase
        
        // Executable extensions
        $ext1 = ".exe" nocase
        $ext2 = ".bat" nocase
        $ext3 = ".cmd" nocase

    condition:
        any of ($download*) and any of ($exec*) and (any of ($path*) or any of ($ext*))
}