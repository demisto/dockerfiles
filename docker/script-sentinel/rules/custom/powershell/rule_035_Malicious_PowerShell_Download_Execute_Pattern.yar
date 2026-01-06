rule rule_035_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "PowerShell download and execute malicious payload pattern"
        severity = "Critical"
        confidence = "0.95"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "410c9ca2e0655ca9,411f8097493fd62d,44e5f8d113bfa907,48e1663d94a7fccb"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download methods
        $download1 = "System.Net.WebClient).DownloadFile(" nocase
        $download2 = "New-Object System.Net.WebClient" nocase
        
        // Suspicious file extensions in download
        $exe_ext = ".exe" nocase
        
        // Immediate execution patterns
        $exec1 = "Start-Process" nocase
        $exec2 = ";Start-Process" nocase
        
        // Suspicious domains/IPs (from the samples)
        $suspicious_url1 = "94.102.53.238" nocase
        $suspicious_url2 = "89.248.170.218" nocase
        $suspicious_url3 = "worldnit.com" nocase

    condition:
        any of ($download*) and $exe_ext and any of ($exec*) and 
        (any of ($suspicious_url*) or 
         (any of ($download*) and $exe_ext and any of ($exec*)))
}