rule rule_021_Malicious_Credential_Harvesting_Tools {
    meta:
        description = "Credential harvesting using Windows APIs or application decryption"
        severity = "High"
        confidence = "0.90"
        mitre_technique = "T1555"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "27172ea4394fc12f,27ef493c6b671f1e"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // VSS-based credential access
        $vss1 = "Get-Service -name VSS" nocase
        $vss2 = "win32_shadowcopy" nocase
        $sam = "system32\\config\\SAM" nocase
        $ntds = "ntds.dit" nocase
        
        // RDCMan credential decryption
        $rdcman1 = "remote desktop connection manager" nocase
        $rdcman2 = "rdcman.settings" nocase
        $dpapi1 = "System.Security.Cryptography.ProtectedData" nocase
        $dpapi2 = "DataProtectionScope" nocase
        
        // Credential extraction patterns
        $decrypt = "Decrypt-" nocase
        $creds = "logonCredentials" nocase

    condition:
        (($vss1 or $vss2) and ($sam or $ntds)) or 
        (($rdcman1 or $rdcman2) and ($dpapi1 or $dpapi2)) or
        ($decrypt and $creds)
}