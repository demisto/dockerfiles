rule rule_009_Malicious_PowerShell_Appdata_Execution_Chain {
    meta:
        description = "PowerShell downloading executables to APPDATA and executing them"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "1bdd80db57afdb7c,1c0ce5528c2f701f,1c2b295ce766b881,1d61951c4221c8bc,1eb7de2ccc21ca93,1fd19d19db32f79e"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // APPDATA references
        $appdata1 = "$env:APPDATA" nocase
        $appdata2 = "\\AppData\\" nocase
        
        // Download and execute pattern
        $download = "DownloadFile(" nocase
        $webclient = "System.Net.WebClient" nocase
        $execute = "Start-Process" nocase
        
        // Executable extension
        $exe = ".exe" nocase
        
        // Suspicious executable names (common malware names)
        $malname1 = "csrsv.exe" nocase
        $malname2 = "msvmonr.exe" nocase

    condition:
        any of ($appdata*) and $download and $webclient and $execute and $exe and (any of ($malname*) or 4 of them)
}