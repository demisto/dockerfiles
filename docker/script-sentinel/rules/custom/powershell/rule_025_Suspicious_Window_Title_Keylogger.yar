rule rule_025_Suspicious_Window_Title_Keylogger {
    meta:
        description = "Window title capture and logging indicating keylogger behavior"
        severity = "High"
        confidence = "0.86"
        mitre_technique = "T1056.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "15895910edc39bf8,1bb59a98d3c1764a"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        $window1 = "Get-WindowStation" nocase
        $window2 = "MainWindowHandle" nocase
        $window3 = "MainWindowTitle" nocase
        $window4 = "Get-ForegroundWindow" nocase
        $log1 = "keylogger.log" nocase
        $log2 = "test.log" nocase
        $output1 = "echo $echo >" nocase
        $desktop1 = "Desktop" nocase

    condition:
        2 of ($window*) and any of ($log*) and ($output1 or $desktop1)
}