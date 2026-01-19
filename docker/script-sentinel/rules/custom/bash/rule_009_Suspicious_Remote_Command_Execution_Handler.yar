rule rule_009_Suspicious_Remote_Command_Execution_Handler {
    meta:
        description = "Detects remote command execution handlers with encryption/encoding"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "5ea426c285a14b5b"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Configuration loading (common in backdoors)
        $config_load1 = ". ./config.sh" nocase
        $config_load2 = ". ./lib.sh" nocase
        
        // Request handling patterns
        $read_request = "read -r" nocase
        $request_var = "request" nocase
        $crypted_suffix = "Crypted" nocase
        $uncrypted_suffix = "Uncrypted" nocase
        
        // Decoding/decryption functions
        $decode_func = "decode" nocase
        
        // Command execution
        $run_cmd = "run $" nocase
        
        // Logging patterns (operational security)
        $log_receive = "Receive request" nocase
        $log_end = "End request" nocase
        
        // Variable patterns suggesting crypto operations
        $crypto_pattern = /\$[a-zA-Z]*[Cc]rypted/ nocase

    condition:
        ($config_load1 or $config_load2) and
        $read_request and $request_var and
        ($crypted_suffix or $uncrypted_suffix or $crypto_pattern) and
        $decode_func and $run_cmd and
        ($log_receive or $log_end)
}