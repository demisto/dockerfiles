rule rule_030_Suspicious_Shell_Binary_Download_Execute_Chain {
    /*
     * Detects shell scripts that download files via wget and immediately
     * make them executable and run them, often to temporary directories.
     * Common pattern in malware droppers and automated infection scripts.
     */
    meta:
        description = "Shell script downloading and executing binaries in sequence"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1105" 
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "c7b6b69f679aab08,3f1119b0a6e0d822"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Download methods
        $download1 = /wget.*-[cP]/ nocase
        $download2 = /curl.*-o/ nocase
        
        // Make executable
        $chmod = /chmod\s+\+x/ nocase
        
        // Execute downloaded file
        $execute1 = /&&\s+\.?\// nocase
        $execute2 = /;\s*\.?\// nocase
        
        // Suspicious locations
        $temp_dir1 = "/var/run" nocase
        $temp_dir2 = "/tmp" nocase
        $temp_dir3 = "/dev/shm" nocase
        
        // Cleanup evidence  
        $remove = /rm.*-f/ nocase

    condition:
        any of ($download*) and 
        $chmod and 
        any of ($execute*) and
        any of ($temp_dir*) and
        $remove
}