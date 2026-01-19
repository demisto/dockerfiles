rule rule_013_Malicious_XMRig_Cryptominer_Deployment_Script {
    meta:
        description = "Detects XMRig cryptocurrency miner deployment with systemd persistence"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1496"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "c7a0d6ccf56b187e"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // XMRig specific indicators
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "donate-level" nocase
        
        // Mining parameters
        $mining1 = "--url" nocase
        $mining2 = "--user" nocase
        $mining3 = "--pass" nocase
        
        // Persistence mechanisms
        $persist1 = "systemctl enable" nocase
        $persist2 = "systemctl start" nocase
        $persist3 = "/etc/systemd/system/" nocase
        
        // Stealth execution
        $stealth1 = "nohup" nocase
        $stealth2 = ">/dev/null 2>&1" nocase
        
        // Service masquerading
        $masq1 = "system-update" nocase
        $masq2 = "System Update Service" nocase

    condition:
        any of ($xmrig*) and 
        2 of ($mining*) and 
        2 of ($persist*) and 
        any of ($stealth*) and
        any of ($masq*)
}