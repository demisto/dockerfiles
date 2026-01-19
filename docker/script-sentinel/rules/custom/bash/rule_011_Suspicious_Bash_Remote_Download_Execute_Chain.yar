rule rule_011_Suspicious_Bash_Remote_Download_Execute_Chain {
    meta:
        description = "Detects remote download and execute patterns using various tools"
        severity = "High"
        confidence = "0.78"
        mitre_technique = "T1105"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "b85b59cba5749b4d"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Download tools
        $download1 = "wget" nocase
        $download2 = "curl" nocase
        
        // Remote URLs
        $url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\/[^\s'"]*\.(sh|bash|py|pl)/ nocase
        
        // Execution indicators
        $exec1 = "| bash" nocase
        $exec2 = "| sh" nocase
        $exec3 = "&& bash" nocase
        $exec4 = "&& sh" nocase
        $exec5 = "; bash" nocase
        $exec6 = "; sh" nocase
        
        // Suspicious flags
        $quiet_flag = /-(q|s|silent)/ nocase
        $output_flag = /-O-/ nocase
        
    condition:
        any of ($download*) and $url and any of ($exec*) and ($quiet_flag or $output_flag)
}