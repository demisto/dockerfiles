rule rule_054_Malicious_PowerShell_KeePass_Credential_Harvesting {
    meta:
        description = "PowerShell script targeting KeePass credential databases"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1555.005"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "5a76e642357792bb"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // KeePass specific files and paths
        $keepass1 = "KeePass.config.xml" nocase
        $keepass2 = "KeePass.ini" nocase
        $keepass3 = "Find-KeePassconfig" nocase
        
        // Database file extensions
        $db1 = ".kdb" nocase
        $db2 = ".kdbx" nocase
        
        // Credential harvesting indicators
        $cred1 = "DefaultDatabasePath" nocase
        $cred2 = "DefaultKeyFilePath" nocase
        $cred3 = "UserMasterKey" nocase
        $cred4 = "ProtectedUserKey" nocase
        
        // Parsing functions
        $parse1 = "Get-IniContent" nocase
        $parse2 = "RecentlyUsed" nocase

    condition:
        (any of ($keepass*) and any of ($db*)) or 
        (2 of ($cred*) and any of ($parse*))
}