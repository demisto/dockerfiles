rule rule_039_Malicious_PowerShell_Chained_Download_Execute {
    meta:
        description = "PowerShell chained download and execute commands in single line"
        severity = "Critical"
        confidence = "0.90"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "410c9ca2e0655ca9,411f8097493fd62d,44e5f8d113bfa907,48e1663d94a7fccb"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Chained download and execute pattern
        $chain1 = /DownloadFile\([^)]+\);Start-Process/ nocase
        $chain2 = /\.DownloadFile\([^)]+\);\s*Start-Process/ nocase
        
        // Alternative chaining patterns
        $chain3 = /WebClient\(\)\.DownloadFile[^;]+;[^;]*Start-Process/ nocase

    condition:
        any of ($chain*)
}