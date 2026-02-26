rule rule_026_Suspicious_Shell_Dynamic_Code_Generation {
    meta:
        description = "Shell script with dynamic code generation patterns"
        severity = "Medium" 
        confidence = "0.82"
        mitre_technique = "T1059.004"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "2e4f1748382f0c30,a219f4921a022093"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Complex sed operations for code generation
        $sed_complex1 = /sed.*-e.*-e.*-e/ nocase
        $sed_complex2 = "sed -n" nocase
        
        // Dynamic variable construction
        $dynamic1 = /\$'[^']*'/ nocase
        $dynamic2 = "${" nocase
        
        // Code generation indicators
        $generate1 = "generate" nocase
        $generate2 = "> \"${" nocase
        $generate3 = "printf" nocase
        
        // File modification patterns
        $modify1 = "mv \"${" nocase
        $modify2 = "cat \"$" nocase
        
        // Shell indicators
        $shell1 = "#!/bin/sh" nocase
        $shell2 = "#!/bin/bash" nocase
    
    condition:
        any of ($shell*) and
        any of ($sed_complex*) and
        any of ($dynamic*) and
        any of ($generate*) and
        any of ($modify*)
}