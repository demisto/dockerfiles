rule rule_048_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "PowerShell download and execute pattern using WebClient and Start-Process"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "54b22e2f108eab32,5643903ed38f9cfd,58d0751a84580540,5a0bd424fc660698,5c7605af93fc509e,5c7adcb3176c3557"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download methods
        $download1 = "System.Net.WebClient).DownloadFile" nocase
        $download2 = "WebClient).DownloadFile" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "IEX" nocase
        
        // Executable extensions in quotes
        $exe1 = ".exe'" nocase
        $exe2 = ".exe\"" nocase
        $exe3 = ".exe')" nocase
        $exe4 = ".exe\")" nocase
        
        // HTTP URLs
        $url = /https?:\/\/[^\s'"]+/ nocase

    condition:
        any of ($download*) and any of ($exec*) and any of ($exe*) and $url
}