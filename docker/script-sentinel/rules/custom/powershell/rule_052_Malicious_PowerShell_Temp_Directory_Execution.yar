rule rule_052_Malicious_PowerShell_Temp_Directory_Execution {
    meta:
        description = "PowerShell downloading executables to temp directories for execution"
        severity = "High"
        confidence = "0.87"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "58d0751a84580540,5a0bd424fc660698,5c7adcb3176c3557"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Temp directory references
        $temp1 = "$env:TEMP\\" nocase
        $temp2 = "$env:APPDATA\\" nocase
        $temp3 = "\\temp\\" nocase
        
        // Download methods
        $download1 = "DownloadFile" nocase
        $download2 = "WebClient" nocase
        
        // Execution with temp path
        $exec1 = "Start-Process (\"$env:TEMP\\" nocase
        $exec2 = "Start-Process (\"$env:APPDATA\\" nocase
        $exec3 = "Start-Process \"$env:TEMP\\" nocase
        $exec4 = "Start-Process \"$env:APPDATA\\" nocase
        
        // Executable extensions
        $exe1 = ".exe" nocase

    condition:
        any of ($temp*) and any of ($download*) and any of ($exec*) and $exe1
}