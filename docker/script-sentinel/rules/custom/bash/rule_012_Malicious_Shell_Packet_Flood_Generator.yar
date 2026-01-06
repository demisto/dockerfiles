rule rule_012_Malicious_Shell_Packet_Flood_Generator {
    meta:
        description = "Detects shell scripts that generate TCP/UDP packet floods using flood utilities"
        severity = "Critical"
        confidence = "0.85"
        mitre_technique = "T1498.002"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "6b3170a83fb7a8a8"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Flood utilities
        $flood1 = "ssyn2" nocase
        $flood2 = "sudp" nocase
        $flood3 = "syn flood" nocase
        $flood4 = "udp flood" nocase

        // Flood attack parameters
        $param1 = "$ip $port $threads" nocase
        $param2 = "for $secs secs with $threads threads" nocase
        $param3 = "mode tcp" nocase
        $param4 = "mode udp" nocase

        // Attack control structure
        $control1 = "tcp(){" nocase
        $control2 = "udp(){" nocase
        $control3 = "case $mode in" nocase
        $control4 = "trap finish" nocase

        // Attack validation
        $valid1 = "Max: 20 threads" nocase
        $valid2 = "threads -gt" nocase
        $valid3 = "secs -gt" nocase

    condition:
        (any of ($flood*) and any of ($param*)) or
        (any of ($control*) and any of ($param*) and any of ($valid*))
}