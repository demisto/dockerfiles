rule rule_002_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "PowerShell WebClient download and execute pattern commonly used by malware"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "0208df2aeb9fbe40,05c3b0bd11b9b772,069971512a08a2f1,070f216652aff14d,0abb120eb649b989,0f02c8cdcda561d3,12da540ae989a109,140dd855c9676a48,141adc1b31ddf4d3,14d10862cf30a45d,17986c869474fb98,17dcaeeb7d93c8bc,1a65bab12f379c7b,1ab0b3818dbee36d"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        // Download methods
        $download1 = "New-Object System.Net.WebClient).DownloadFile" nocase
        $download2 = "WebClient).DownloadFile" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "IEX" nocase
        
        // Common temp/appdata paths
        $path1 = "$env:TEMP\\" nocase
        $path2 = "$env:APPDATA\\" nocase

    condition:
        any of ($download*) and any of ($exec*) and any of ($path*)
}