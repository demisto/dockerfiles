rule rule_012_Malicious_Script_LOLBin_Comment_Indicator {
    meta:
        description = "Detects scripts with explicit LOLBin technique references"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "b85b59cba5749b4d"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // LOLBin references in comments
        $lolbin1 = "# LOLBin:" nocase
        $lolbin2 = "# LOLBIN:" nocase
        $lolbin3 = "# Living off the land" nocase
        $lolbin4 = "# lolbin" nocase
        
        // Download and execute tools
        $tool1 = "wget" nocase
        $tool2 = "curl" nocase
        $tool3 = "powershell" nocase
        $tool4 = "certutil" nocase
        
        // Execution patterns
        $exec1 = "download and execute" nocase
        $exec2 = "| bash" nocase
        $exec3 = "| sh" nocase
        $exec4 = "invoke-expression" nocase
        $exec5 = "iex" nocase
        
    condition:
        any of ($lolbin*) and any of ($tool*) and any of ($exec*)
}