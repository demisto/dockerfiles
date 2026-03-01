rule rule_013_Malicious_UAC_Bypass_Techniques {
    meta:
        description = "UAC bypass using registry hijacking techniques"
        severity = "High"
        confidence = "0.92"
        mitre_technique = "T1548.002"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "528d92427e762e44,6d2f6b1761827bb5"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $reg1 = "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command" nocase
        $reg2 = "HKCU:\\Software\\Classes\\exefile\\shell\\runas\\command" nocase
        $bypass1 = "eventvwr.exe" nocase
        $bypass2 = "sdclt.exe" nocase
        $bypass3 = "/kickoffelev" nocase
        $function1 = "Invoke-EventVwrBypass" nocase
        $function2 = "Invoke-SDCLTBypass" nocase
    
    condition:
        (any of ($reg*) and any of ($bypass*)) or any of ($function*)
}