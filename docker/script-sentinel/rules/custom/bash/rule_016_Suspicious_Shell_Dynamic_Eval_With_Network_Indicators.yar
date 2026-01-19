rule rule_016_Suspicious_Shell_Dynamic_Eval_With_Network_Indicators {
    meta:
        description = "Shell script with dynamic evaluation and network operation patterns"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1059.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "7aed6f79239d5839,be3c1ffb2f36ee64"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Dynamic evaluation patterns
        $eval1 = "eval " nocase
        $eval2 = "`eval " nocase
        $eval3 = "$(eval " nocase
        
        // Network/download related operations
        $net1 = "wget" nocase
        $net2 = "curl" nocase
        $net3 = "nc " nocase
        $net4 = "netcat" nocase
        $net5 = "/dev/tcp/" nocase
        $net6 = "http://" nocase
        $net7 = "https://" nocase
        $net8 = "ftp://" nocase
        
        // Suspicious variable manipulation
        $var1 = "${" 
        $var2 = "export " nocase
        $var3 = "unset " nocase
        
        // Command substitution with variables
        $cmd1 = "`$" 
        $cmd2 = "$(" 

    condition:
        any of ($eval*) and any of ($net*) and any of ($var*) and any of ($cmd*)
}