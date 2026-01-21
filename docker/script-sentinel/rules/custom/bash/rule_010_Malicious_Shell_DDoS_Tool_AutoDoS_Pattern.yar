rule rule_010_Malicious_Shell_DDoS_Tool_AutoDoS_Pattern {
    meta:
        description = "Detects shell-based DDoS attack tools with TCP/UDP flood capabilities"
        severity = "Critical"
        confidence = "0.88"
        mitre_technique = "T1498.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "6b3170a83fb7a8a8"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Attack mode indicators
        $mode1 = "--tcp" nocase
        $mode2 = "--udp" nocase
        $mode3 = "-t|--tcp" nocase
        $mode4 = "-u|--udp" nocase

        // DDoS-specific parameters
        $param1 = "threads" nocase
        $param2 = "secs" nocase
        $param3 = "target" nocase

        // Attack execution patterns
        $attack1 = "Hitting" nocase
        $attack2 = "flood" nocase
        $attack3 = "dos" nocase
        $attack4 = "attack" nocase

        // Thread/process management for attacks
        $thread1 = "Max:" nocase
        $thread2 = "threads/" nocase
        $thread3 = "$threads" nocase

        // Suspicious comments/headers
        $comment1 = "AutoDoS" nocase
        $comment2 = "DDoS" nocase
        $comment3 = "Spoofed Packets" nocase

    condition:
        (any of ($mode*) and any of ($param*) and any of ($attack*)) or
        (any of ($comment*) and any of ($param*) and any of ($thread*))
}