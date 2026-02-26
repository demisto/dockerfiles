rule rule_039_Suspicious_Shell_Infinite_Resource_Consumption_Loop {
    meta:
        description = "Detects shell scripts with infinite loops consuming system resources"
        severity = "Medium"
        confidence = "0.71"
        mitre_technique = "T1499.004"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "f27eb7cd279e8388"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Infinite loop patterns
        $loop1 = "while true" nocase
        $loop2 = "| while" nocase
        
        // Random data generation
        $rand1 = "/dev/urandom" nocase
        $rand2 = "$RANDOM" nocase
        
        // Resource intensive operations
        $compress1 = "gzip" nocase
        $compress2 = "gunzip" nocase
        
        // Continuous processing
        $pipe1 = "| ../busybox" nocase
        $pipe2 = ">/dev/null" nocase
        
        // Leak test terminology (could indicate malicious testing)
        $test1 = "leak test" nocase
        $test2 = "growing process" nocase
        
    condition:
        any of ($loop*) and $rand1 and any of ($compress*) and any of ($pipe*) and (any of ($test*) or (#rand2 > 0))
}