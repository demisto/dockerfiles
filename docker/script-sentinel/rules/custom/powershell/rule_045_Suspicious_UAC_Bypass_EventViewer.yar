rule rule_045_Suspicious_UAC_Bypass_EventViewer {
    meta:
        description = "UAC bypass using Event Viewer registry hijacking technique"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1548.002"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "528d92427e762e44"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Registry paths used in UAC bypass
        $reg1 = "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" nocase
        $reg2 = "mscfile\\shell\\open\\command" nocase
        
        // Event Viewer executable
        $eventvwr = "eventvwr.exe" nocase
        
        // Registry manipulation functions
        $newitem = "New-Item" nocase
        $newprop = "New-ItemProperty" nocase
        
        // UAC-related checks
        $uac1 = "ConsentPromptBehaviorAdmin" nocase
        $uac2 = "PromptOnSecureDesktop" nocase
        
        // Function name
        $func = "Invoke-EventVwrBypass" nocase

    condition:
        ($func or (any of ($reg*) and $eventvwr)) and 
        (any of ($newitem, $newprop) or any of ($uac*))
}