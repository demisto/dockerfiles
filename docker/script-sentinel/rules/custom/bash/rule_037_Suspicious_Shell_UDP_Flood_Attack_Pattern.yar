rule rule_037_Suspicious_Shell_UDP_Flood_Attack_Pattern {
    meta:
        description = "Detects shell scripts implementing UDP flood DoS attacks"
        severity = "High"
        confidence = "0.82"
        mitre_technique = "T1498.001"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "f55ee64f06a7b111"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // UDP flood indicators
        $udp1 = "udpdata" nocase
        $udp2 = "datagram packets" nocase
        
        // DoS terminology
        $dos1 = "dos" nocase
        $dos2 = "flood" nocase
        $dos3 = "hitting" nocase
        
        // Random IP generation pattern
        $rand1 = "randIp" nocase
        $rand2 = "/dev/urandom" nocase
        $rand3 = "randPort" nocase
        
        // Loop patterns for packet sending
        $loop1 = "seq 1" nocase
        $loop2 = "for i in" nocase
        
        // Network targeting
        $target1 = "target ip" nocase
        $target2 = "port" nocase
        
    condition:
        any of ($udp*) and any of ($dos*) and any of ($rand*) and any of ($loop*) and any of ($target*)
}