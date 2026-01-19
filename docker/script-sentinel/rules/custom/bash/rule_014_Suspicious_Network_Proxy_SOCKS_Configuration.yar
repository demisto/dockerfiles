rule rule_014_Suspicious_Network_Proxy_SOCKS_Configuration {
    meta:
        description = "Detects SOCKS proxy configuration through Tor for potential C2 communication"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1090.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "217e20f7b584726a"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // SOCKS proxy configuration
        $socks = "SOCKS4A:" nocase
        $socat = "socat" nocase
        $tcp_listen = "TCP4-LISTEN:" nocase
        
        // Tor-related indicators
        $tor_port = "socksport=" nocase
        $onion_addr = "onion addr" nocase
        $orlisadr = "orlisadr=127.0.0.1" nocase
        $orport = "orport=9050" nocase
        
        // Process management for persistence
        $pidof = "pidof" nocase
        $kill_restart = "kill $(pidof" nocase

    condition:
        $socks and $socat and $tcp_listen and
        ($tor_port or $onion_addr or ($orlisadr and $orport)) and
        ($pidof or $kill_restart)
}