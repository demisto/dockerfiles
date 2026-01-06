rule rule_005_Suspicious_Bash_Static_Compilation_With_Threading {
    meta:
        description = "Bash script performing static compilation with threading libraries"
        severity = "Medium"
        confidence = "0.78"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "5bb15012ee9420e3,6bf11c58ffbeb16c"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // GCC compilation
        $gcc = "gcc" nocase
        
        // Static compilation flag
        $static = "-static" nocase
        
        // Threading libraries
        $pthread1 = "-lpthread" nocase
        $pthread2 = "-pthread" nocase
        
        // Wildcard source compilation or minimal paths
        $wildcard_src = /src\/\*\.c/ nocase
        $minimal_src = /[a-zA-Z_]+\.c/ nocase
        
        // Output to simple executable names
        $simple_output = /-o\s+[a-zA-Z_]{4,12}(\s|$)/ nocase

    condition:
        $gcc and $static and any of ($pthread*) and (
            $wildcard_src or ($minimal_src and $simple_output)
        )
}