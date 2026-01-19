rule rule_031_Malicious_PowerShell_Download_Execute_Pattern {
    meta:
        description = "Detects PowerShell download-and-execute pattern with suspicious domain"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2efbe1225eded4f0,2fae96c729b53b9b,30eb0a5c55f9aae7,31b7b83012a6c9e2,31ce17f3fbe8760b,326e3f7fe35312dc,33580e141db1d52c"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download methods
        $download1 = "New-Object System.Net.WebClient" nocase
        $download2 = ".DownloadFile(" nocase
        
        // Execution methods
        $exec1 = "Start-Process" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "IEX" nocase
        
        // Suspicious patterns
        $suspicious_domain = /http:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase
        $appdata_path = "$env:APPDATA" nocase
        $exe_extension = ".exe" nocase

    condition:
        $download1 and $download2 and any of ($exec*) and 
        ($suspicious_domain or $appdata_path) and $exe_extension
}