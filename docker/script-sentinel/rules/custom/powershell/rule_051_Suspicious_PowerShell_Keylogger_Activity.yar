rule rule_051_Suspicious_PowerShell_Keylogger_Activity {
    meta:
        description = "PowerShell keylogger activity with window manipulation"
        severity = "High"
        confidence = "0.90"
        mitre_technique = "T1056.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "534f8db246578387"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Keylogger indicators
        $keylog1 = "keylogger.txt" nocase
        $keylog2 = "keylogger.log" nocase
        
        // Window manipulation
        $window1 = "Get-ForegroundWindow" nocase
        $window2 = "MainWindowHandle" nocase
        $window3 = "MainWindowTitle" nocase
        
        // File operations
        $file1 = "New-Item" nocase
        $file2 = "Start-Process notepad" nocase
        
        // Sleep/timing
        $timing1 = "Start-Sleep" nocase

    condition:
        any of ($keylog*) and 2 of ($window*) and any of ($file*) and $timing1
}