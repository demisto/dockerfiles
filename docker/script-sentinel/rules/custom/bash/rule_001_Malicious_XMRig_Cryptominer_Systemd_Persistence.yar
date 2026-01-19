rule rule_001_Malicious_XMRig_Cryptominer_Systemd_Persistence {
    /*
     * Detects XMRig cryptocurrency mining malware that establishes
     * persistence via systemd services with deceptive names.
     *
     * Example match:
     *   BINARY_PATH="$(pwd)/$EXTRACT_DIR/xmrig"
     *   ARGS="--url pool.hashvault.pro:443 --user 88tGYBwh..."
     *   SERVICE_NAME="system-update-service"
     */
    meta:
        description = "XMRig cryptominer with systemd persistence and deceptive service naming"
        severity = "High"
        confidence = "0.92"
        mitre_technique = "T1053.006"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "13675cca4674a8f9,5bae25736a09de5f"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // XMRig specific indicators
        $xmrig1 = "xmrig" nocase
        $xmrig2 = "/xmrig" nocase
        
        // Mining pool connection patterns
        $pool1 = "--url" nocase
        $pool2 = "--user" nocase
        $pool3 = "--pass" nocase
        $pool4 = "--donate-level" nocase
        $pool5 = "--tls" nocase
        
        // Systemd persistence
        $systemd1 = "systemctl daemon-reload" nocase
        $systemd2 = "systemctl enable" nocase
        $systemd3 = "systemctl start" nocase
        $systemd4 = "/etc/systemd/system/" nocase
        
        // Deceptive service names
        $deceptive1 = "system-update-service" nocase
        $deceptive2 = "system-maintenance" nocase
        $deceptive3 = "kernel-update" nocase
        
        // Wallet address patterns (long alphanumeric strings typical of crypto wallets)
        $wallet = /[A-Za-z0-9]{80,100}/ nocase

    condition:
        any of ($xmrig*) and 
        3 of ($pool*) and 
        2 of ($systemd*) and 
        (any of ($deceptive*) or $wallet)
}