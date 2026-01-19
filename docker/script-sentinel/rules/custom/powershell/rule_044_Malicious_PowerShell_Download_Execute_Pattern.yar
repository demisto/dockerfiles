rule rule_044_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "PowerShell WebClient download and execute pattern commonly used by malware"
        severity = "Critical"
        confidence = "0.95"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "4fe631e52b550479,50a883cbae41ede3,515de267690176c5,5183a63ff7ee81f3,526007963ef9c193"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // WebClient download methods
        $download1 = "New-Object System.Net.WebClient).DownloadFile(" nocase
        $download2 = "(New-Object System.Net.WebClient).DownloadFile(" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "IEX" nocase
        
        // Suspicious file extensions in URLs
        $exe_url = /https?:\/\/[^\s'"]+\.exe/ nocase
        
        // Environment variable paths commonly used for temp execution
        $env_temp = "$env:TEMP" nocase
        $env_appdata = "$env:APPDATA" nocase

    condition:
        any of ($download*) and any of ($exec*) and ($exe_url or any of ($env_*))
}