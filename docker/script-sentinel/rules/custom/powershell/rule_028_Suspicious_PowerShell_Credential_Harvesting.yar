rule rule_028_Suspicious_PowerShell_Credential_Harvesting {
    meta:
        description = "PowerShell script accessing credential storage and Group Policy Preferences"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1552.006"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2ab7a1d43c42564d"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // GPP specific patterns
        $gpp1 = "Get-GPPAutologon" nocase
        $gpp2 = "DefaultPassword" nocase
        $gpp3 = "DefaultUserName" nocase
        $gpp4 = "Registry.xml" nocase
        
        // Credential manager patterns
        $cred1 = "CredDeleteW" nocase
        $cred2 = "CredEnumerateW" nocase
        $cred3 = "CredReadW" nocase
        $cred4 = "Advapi32.dll" nocase
        
        // SYSVOL access
        $sysvol1 = "\\\\$Env:USERDNSDOMAIN\\SYSVOL" nocase
        
        // Password extraction
        $pass1 = "Passwords" nocase
        $pass2 = "[BLANK]" nocase

    condition:
        (any of ($gpp*) and ($sysvol1 or any of ($pass*))) or
        (2 of ($cred*)) or
        ($gpp2 and $gpp3 and $gpp4)
}