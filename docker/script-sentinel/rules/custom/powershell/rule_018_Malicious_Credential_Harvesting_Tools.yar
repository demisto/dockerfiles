rule rule_018_Malicious_Credential_Harvesting_Tools {
    meta:
        description = "Credential harvesting and extraction tools"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1555"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "27ef493c6b671f1e,5a76e642357792bb,a996a86c04bb42dd"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $cred1 = "CredEnumerate" nocase
        $cred2 = "CredRead" nocase
        $cred3 = "System.Security.Cryptography.ProtectedData" nocase
        $cred4 = "KeePass.config.xml" nocase
        $cred5 = "rdcman.settings" nocase
        $cred6 = "Decrypt-RDCMan" nocase
        $cred7 = "Find-KeePassconfig" nocase
        $cred8 = "Invoke-WCMDump" nocase
    
    condition:
        2 of ($cred1, $cred2, $cred3) or any of ($cred4, $cred5, $cred6, $cred7, $cred8)
}