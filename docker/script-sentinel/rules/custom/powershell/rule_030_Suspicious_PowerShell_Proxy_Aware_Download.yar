rule rule_030_Suspicious_PowerShell_Proxy_Aware_Download {
    meta:
        description = "PowerShell with proxy configuration and suspicious download behavior"
        severity = "Medium"
        confidence = "0.83"
        mitre_technique = "T1090.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2e1b008e1b149ade"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Proxy configuration
        $proxy1 = "GetSystemWebProxy" nocase
        $proxy2 = "DefaultCredentials" nocase
        $proxy3 = "UseDefaultCredentials" nocase
        
        // Custom headers
        $header1 = "Headers.add" nocase
        $header2 = "user-agent" nocase
        $header3 = "Mozilla/" nocase
        
        // Web client configuration
        $web1 = "New-Object net.webclient" nocase
        $web2 = ".proxy=" nocase
        
        // Execution bypass
        $bypass1 = "-exec bypass" nocase

    condition:
        (any of ($proxy*) and any of ($header*) and $web1) or
        ($bypass1 and any of ($proxy*) and $header1) or
        (2 of ($proxy*) and $web2 and any of ($header*))
}