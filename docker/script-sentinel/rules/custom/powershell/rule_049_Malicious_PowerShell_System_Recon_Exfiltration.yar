rule rule_049_Malicious_PowerShell_System_Recon_Exfiltration {
    meta:
        description = "PowerShell system reconnaissance with HTTP POST exfiltration"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1082"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "5c5649ac19b99acf"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // System reconnaissance commands
        $recon1 = "systeminfo" nocase
        $recon2 = "whoami /all" nocase
        $recon3 = "nltest /domain_trusts" nocase
        $recon4 = "tasklist" nocase
        $recon5 = "Win32_Product" nocase
        
        // Data exfiltration
        $exfil1 = "Invoke-RestMethod" nocase
        $exfil2 = "-Method Post" nocase
        $exfil3 = "-Body" nocase
        
        // HTTP URL pattern
        $url = /https?:\/\/[^\s'"]+/ nocase

    condition:
        3 of ($recon*) and all of ($exfil*) and $url
}