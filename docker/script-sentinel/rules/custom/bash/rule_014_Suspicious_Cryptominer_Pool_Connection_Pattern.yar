rule rule_014_Suspicious_Cryptominer_Pool_Connection_Pattern {
    meta:
        description = "Detects cryptocurrency mining pool connections with wallet addresses"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1496"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "c7a0d6ccf56b187e"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Mining pool connection patterns
        $pool1 = /--url\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/ nocase
        $pool2 = /--server\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}/ nocase
        
        // Wallet address patterns (Monero-like)
        $wallet1 = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ 
        $wallet2 = /--user\s+[48][0-9AB][1-9A-HJ-NP-Za-km-z]{90,95}/ nocase
        
        // Mining software flags
        $flags1 = "--donate-level" nocase
        $flags2 = "--tls" nocase
        $flags3 = "--pass" nocase
        $flags4 = "--algo" nocase
        
        // Common mining software names
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "minerd" nocase

    condition:
        (any of ($pool*) and any of ($wallet*) and 2 of ($flags*)) or
        (any of ($miner*) and any of ($wallet*) and any of ($pool*))
}