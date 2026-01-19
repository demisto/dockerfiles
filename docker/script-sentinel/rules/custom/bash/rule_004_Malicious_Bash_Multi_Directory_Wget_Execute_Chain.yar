rule rule_004_Malicious_Bash_Multi_Directory_Wget_Execute_Chain {
    meta:
        description = "Bash script with chained directory changes, wget download, execute and cleanup pattern"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1105"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "72f07e0609282c65"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Multiple directory fallback pattern
        $dir_chain = /cd\s+\/[a-zA-Z\/]+\s*\|\|\s*cd\s+\/[a-zA-Z\/]+\s*\|\|\s*cd\s+\/[a-zA-Z\/]+/ nocase
        
        // Download methods
        $download = "wget http" nocase
        
        // Execute and cleanup pattern
        $exec_cleanup1 = /chmod\s+\+x\s+[^;]+;\s*\.\/[^;]+;\s*rm\s+-rf/ nocase
        $exec_cleanup2 = /chmod\s+\+x\s+[^&]+&&\s*\.\/[^&]+&&\s*rm\s+-rf/ nocase
        
        // Suspicious file extensions or patterns
        $suspicious_ext1 = ".Sakura" nocase
        $suspicious_ext2 = /\.[a-zA-Z0-9\-]{8,}$/ nocase

    condition:
        $dir_chain and $download and any of ($exec_cleanup*) and any of ($suspicious_ext*)
}