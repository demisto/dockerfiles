rule rule_010_Malicious_Bash_Wget_Pipe_Execute_LOLBin {
    meta:
        description = "Detects wget download and pipe to bash execution pattern"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1105"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "b85b59cba5749b4d"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // wget with quiet output to stdout
        $wget_quiet = /wget\s+[^|]*-[a-zA-Z]*q[a-zA-Z]*O-/ nocase
        
        // HTTP/HTTPS URLs
        $http_url = /https?:\/\/[^\s'"]+/ nocase
        
        // Pipe to bash execution
        $pipe_bash1 = "| bash" nocase
        $pipe_bash2 = "|bash" nocase
        $pipe_bash3 = "| sh" nocase
        $pipe_bash4 = "|sh" nocase
        
        // Alternative execution patterns
        $exec_pattern = /\|\s*(bash|sh)\s*$/ nocase
        
    condition:
        $wget_quiet and $http_url and (any of ($pipe_bash*) or $exec_pattern)
}