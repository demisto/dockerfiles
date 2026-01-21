rule rule_005_Malicious_Bash_Persistent_C2_Shell_Loop {
    /*
     * Detects persistent C2 shell scripts that use infinite loops
     * to maintain connection and execute remote commands with
     * subclient/pubclient communication tools.
     */
    meta:
        description = "Persistent C2 shell with subclient/pubclient infinite loop communication"
        severity = "Critical"
        confidence = "0.88"
        mitre_technique = "T1059.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "51fb3ed22caa40f5"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Infinite loop patterns
        $loop1 = "while true;do" nocase
        $loop2 = "while true; do" nocase
        
        // C2 communication tools
        $c2_1 = "subclient -h" nocase
        $c2_2 = "pubclient -h" nocase
        
        // Command execution and output handling
        $exec1 = "sh cmds > output" nocase
        $exec2 = "> cmds" nocase
        $exec3 = "-t shell" nocase
        
        // Background process indicators
        $bg = "done &" nocase

    condition:
        any of ($loop*) and any of ($c2_*) and any of ($exec*) and $bg
}