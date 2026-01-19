rule rule_033_Malicious_PowerShell_Credential_Manager_Access {
    meta:
        description = "Detects PowerShell accessing Windows Credential Manager APIs"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1555.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "08d2665ab7ffcebc"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Credential Manager API functions
        $cred_api1 = "CredDeleteW" nocase
        $cred_api2 = "CredEnumerateW" nocase
        $cred_api3 = "CredReadW" nocase
        $cred_api4 = "CredWriteW" nocase
        $cred_api5 = "CredFree" nocase
        
        // DLL and namespace indicators
        $advapi32 = "Advapi32.dll" nocase
        $dllimport = "DllImport" nocase
        $credman_class = "class CredMan" nocase
        
        // Credential-related enums/structs
        $cred_type = "CRED_TYPE" nocase
        $cred_flags = "CRED_FLAGS" nocase

    condition:
        3 of ($cred_api*) and $advapi32 and $dllimport and 
        ($credman_class or any of ($cred_type, $cred_flags))
}