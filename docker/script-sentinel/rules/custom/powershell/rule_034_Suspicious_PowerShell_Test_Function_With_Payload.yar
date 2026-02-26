rule rule_034_Suspicious_PowerShell_Test_Function_With_Payload {
    meta:
        description = "Detects malicious payload hidden in PowerShell test functions"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2efbe1225eded4f0,326e3f7fe35312dc"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Test function patterns
        $test_func1 = /function\s+Test-[a-zA-Z]+/ nocase
        $test_func2 = /Describe\s+"[^"]*"/ nocase
        $test_func3 = "It \"" nocase
        
        // Malicious download patterns
        $download = "New-Object System.Net.WebClient" nocase
        $download_file = "DownloadFile" nocase
        
        // Execution patterns
        $start_process = "Start-Process" nocase
        
        // Suspicious file paths
        $appdata = "$env:APPDATA" nocase
        $temp_path = "$env:TEMP" nocase

    condition:
        any of ($test_func*) and $download and $download_file and 
        $start_process and (filesize < 50KB) and ($appdata or $temp_path)
}