rule rule_032_Suspicious_Compiler_Execution_Chain_With_Immediate_Run {
    /*
     * Detects compilation followed by immediate execution, or compilation
     * with suspicious flags that may indicate malware development.
     */
    meta:
        description = "Compiler execution chain with immediate run or debug flags"
        severity = "Medium"
        confidence = "0.78"
        mitre_technique = "T1027.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "892f1a1cc6411d9c,e074259dc6113c68"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Compilation patterns
        $compile1 = /g\+\+\s+[^&]+&&\s*\.\/[^\s]+/ nocase
        $compile2 = /gcc\s+[^&]+&&\s*\.\/[^\s]+/ nocase
        
        // Suspicious compilation flags
        $debug_flag = "-DDEBUG" nocase
        $static_flag = "-static" nocase
        $lefence = "-lefence" nocase
        
        // Immediate execution patterns
        $exec_chain = /&&\s*\.\/[a-zA-Z0-9_.-]+/
        $output_exec = /-o\s+[a-zA-Z0-9_.-]+.*&&.*\.\/[a-zA-Z0-9_.-]+/

    condition:
        // Compile and execute chain OR suspicious debug compilation
        ($compile1 or $compile2 or $exec_chain or $output_exec) or
        ($debug_flag and $static_flag and any of them)
}