rule rule_017_Suspicious_Shell_Network_Stress_Test_Pattern {
    /*
     * Detects shell scripts that perform network stress testing
     * or flooding operations with packet generation loops.
     */
    meta:
        description = "Shell script performing network stress testing with packet generation"
        severity = "High"
        confidence = "0.78"
        mitre_technique = "T1498"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "78621342c91d1fd6"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Network targeting patterns
        $target1 = /ip=.*1/ nocase
        $target2 = /port=.*2/ nocase
        $hitting = /hitting.*:.*with/i

        // Packet/data generation loops
        $urandom1 = "/dev/urandom" nocase
        $loop_pattern1 = /while.*\[\[.*-lt/ nocase
        $loop_pattern2 = /for.*seq.*hits/ nocase

        // Random data generation for packets
        $random_gen1 = /head.*urandom.*cksum/ nocase
        $random_gen2 = /dd.*urandom.*count/ nocase

        // Network operation indicators
        $verbose_net = /verbose.*Source.*Dest/ nocase
        $net_operation = /Source:.*Dest:/ nocase

    condition:
        (($target1 and $target2) or $hitting) and
        $urandom1 and
        any of ($loop_pattern*) and
        any of ($random_gen*) and
        any of ($verbose_net, $net_operation)
}