rule rule_055_Suspicious_PowerShell_Network_Reconnaissance {
    meta:
        description = "PowerShell network reconnaissance and IP scanning functions"
        severity = "Medium"
        confidence = "0.78"
        mitre_technique = "T1018"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "46fe0196299a6a37"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Network reconnaissance functions
        $recon1 = "Invoke-ReverseDnsLookup" nocase
        $recon2 = "Parse-IPList" nocase
        $recon3 = "IPtoInt" nocase
        $recon4 = "InttoIP" nocase
        
        // IP range parsing
        $ip1 = "cidrRange" nocase
        $ip2 = "/\\d{1,2}$" nocase
        $ip3 = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" nocase
        
        // Network operations
        $net1 = "System.Net.IPAddress" nocase
        $net2 = "TryParse" nocase
        $net3 = "SubString" nocase
        
        // Binary operations on IPs
        $bin1 = "ToString(\"X8\")" nocase
        $bin2 = "ToInt64" nocase

    condition:
        (2 of ($recon*) and any of ($ip*)) or 
        (any of ($recon*) and 2 of ($net*) and any of ($bin*))
}